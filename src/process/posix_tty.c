#include "posix_tty.h"
#include "posix_io.h"
#include "posix_poll.h"
#include "posix_pgroup.h"
#include "posix_signal.h"
#include "runtime64.h"
#include "scheduler.h"
#include "task.h"
#include "klock.h"
#include "vm64.h"

// A whole line fits in the accumulator; the queue behind it holds what a
// program has not read yet. Both are static and bounded like every other
// buffer in the profile, and a full one drops the byte rather than growing,
// which is what the UART overrun path does anyway.
#define POSIX_TTY_LINE_MAX 256u
#define POSIX_TTY_QUEUE_MAX 1024u

struct posix_tty_state {
    u32 active;
    struct posix_termios termios;
    struct posix_winsize winsize;
    posix_tty_output_fn output;
    void *output_context;
    u8 line[POSIX_TTY_LINE_MAX];
    u32 line_length;
    u8 queue[POSIX_TTY_QUEUE_MAX];
    u32 queue_head;
    u32 queue_count;
    u32 eof_pending;
    u32 foreground;
};

static struct posix_tty_state ttys[POSIX_TTY_MAX];

// One parked reader per task slot, the way the pipe path keeps its wait
// table: the profile has a single console, so a list per tty would be
// state without users, and the slot is where the request to answer into
// is remembered while the caller's frame is abandoned.
struct tty_wait {
    u32 index;
    uptr_t request;
    u32 length;
};

static struct tty_wait tty_waits[MAX_TASKS];
// Parks and the wake that answers them have to be ordered against each other:
// input landing between a reader's readiness test and its state change wakes
// nobody, and the read then never returns.
static struct klock posix_tty_wait_klock = KLOCK_INIT(KLOCK_LEVEL_WAIT);

static void tty_wake_readers(u32 index);

static struct posix_tty_state *tty_for(u32 index) {
    if (index >= POSIX_TTY_MAX) return 0;
    return ttys[index].active ? &ttys[index] : 0;
}

void posix_tty_init(void) {
    for (u32 index = 0; index < POSIX_TTY_MAX; index++) {
        for (u32 byte = 0; byte < sizeof(ttys[index]); byte++)
            ((u8 *)&ttys[index])[byte] = 0;
    }
    for (u32 slot = 0; slot < MAX_TASKS; slot++) {
        tty_waits[slot].index = 0;
        tty_waits[slot].request = 0;
        tty_waits[slot].length = 0;
    }
}

int posix_tty_create(void) {
    for (u32 index = 0; index < POSIX_TTY_MAX; index++) {
        if (ttys[index].active) continue;
        struct posix_tty_state *tty = &ttys[index];
        for (u32 byte = 0; byte < sizeof(*tty); byte++)
            ((u8 *)tty)[byte] = 0;
        // The defaults an interactive program expects: CR maps to NL, NL
        // maps back to CR-NL on the way out, lines are assembled, echoed
        // and interruptible.
        tty->termios.iflag = POSIX_ICRNL;
        tty->termios.oflag = POSIX_OPOST | POSIX_ONLCR;
        tty->termios.lflag = POSIX_ISIG | POSIX_ICANON | POSIX_ECHO;
        tty->termios.cc[POSIX_VINTR] = 0x03;
        tty->termios.cc[POSIX_VQUIT] = 0x1C;
        tty->termios.cc[POSIX_VERASE] = 0x7F;
        tty->termios.cc[POSIX_VKILL] = 0x15;
        tty->termios.cc[POSIX_VEOF] = 0x04;
        tty->termios.cc[POSIX_VSUSP] = 0x1A;
        // The serial port reports no geometry, so the console carries the
        // classic 80x25 until TIOCSWINSZ says otherwise.
        tty->winsize.rows = 25;
        tty->winsize.cols = 80;
        tty->active = 1;
        return (int)index;
    }
    return POSIX_TTY_ENFILE;
}

void posix_tty_destroy(u32 index) {
    if (index >= POSIX_TTY_MAX) return;
    for (u32 byte = 0; byte < sizeof(ttys[index]); byte++)
        ((u8 *)&ttys[index])[byte] = 0;
}

void posix_tty_set_output(u32 index, posix_tty_output_fn output,
                          void *context) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return;
    tty->output = output;
    tty->output_context = context;
}

posix_tty_output_fn posix_tty_output_get(u32 index, void **context) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return 0;
    if (context) *context = tty->output_context;
    return tty->output;
}

static void tty_put(struct posix_tty_state *tty, u8 byte) {
    if (tty->output) tty->output(tty->output_context, byte);
}

// Output mapping: with ONLCR a newline leaves as CR-NL, and the echo of
// what was typed takes the same path a write does. The echo of an erase is
// the backspace-space-backspace trio, because the terminal does the
// erasing, not the tty.
static void tty_emit(struct posix_tty_state *tty, u8 byte) {
    if (byte == '\n' && (tty->termios.oflag & POSIX_OPOST) &&
        (tty->termios.oflag & POSIX_ONLCR)) {
        tty_put(tty, '\r');
    }
    tty_put(tty, byte);
}

static void tty_echo(struct posix_tty_state *tty, u8 byte) {
    if (tty->termios.lflag & POSIX_ECHO) tty_emit(tty, byte);
}

static u32 queue_push(struct posix_tty_state *tty, const u8 *data, u32 count) {
    u32 accepted = 0;
    for (; accepted < count && tty->queue_count < POSIX_TTY_QUEUE_MAX;
         accepted++) {
        u32 slot = (tty->queue_head + tty->queue_count) % POSIX_TTY_QUEUE_MAX;
        tty->queue[slot] = data[accepted];
        tty->queue_count++;
    }
    return accepted;
}

u32 posix_tty_input_byte(u32 index, u8 byte) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_EVENT_NONE;
    struct posix_termios *termios = &tty->termios;
    if (termios->lflag & POSIX_ISIG) {
        // A zero control character is the "disabled" spelling, so it never
        // matches the byte being tested.
        if (termios->cc[POSIX_VINTR] && byte == termios->cc[POSIX_VINTR])
            return POSIX_TTY_EVENT_INTR;
        if (termios->cc[POSIX_VQUIT] && byte == termios->cc[POSIX_VQUIT])
            return POSIX_TTY_EVENT_QUIT;
        if (termios->cc[POSIX_VSUSP] && byte == termios->cc[POSIX_VSUSP])
            return POSIX_TTY_EVENT_SUSP;
    }
    if ((termios->iflag & POSIX_ICRNL) && byte == '\r') byte = '\n';
    if (!(termios->lflag & POSIX_ICANON)) {
        queue_push(tty, &byte, 1);
        tty_echo(tty, byte);
        tty_wake_readers(index);
        posix_poll_notify();
        return POSIX_TTY_EVENT_NONE;
    }
    if (byte == '\n') {
        queue_push(tty, tty->line, tty->line_length);
        tty->line_length = 0;
        queue_push(tty, &byte, 1);
        tty_echo(tty, byte);
        tty_wake_readers(index);
        posix_poll_notify();
        return POSIX_TTY_EVENT_NONE;
    }
    if (termios->cc[POSIX_VERASE] && byte == termios->cc[POSIX_VERASE]) {
        if (tty->line_length) {
            tty->line_length--;
            if (termios->lflag & POSIX_ECHO) {
                tty_emit(tty, '\b');
                tty_emit(tty, ' ');
                tty_emit(tty, '\b');
            }
        }
        return POSIX_TTY_EVENT_NONE;
    }
    if (termios->cc[POSIX_VKILL] && byte == termios->cc[POSIX_VKILL]) {
        tty->line_length = 0;
        return POSIX_TTY_EVENT_NONE;
    }
    if (termios->cc[POSIX_VEOF] && byte == termios->cc[POSIX_VEOF]) {
        // EOF on a partial line hands that line over; on an empty one it
        // marks the end the next read reports as zero bytes.
        if (tty->line_length) {
            queue_push(tty, tty->line, tty->line_length);
            tty->line_length = 0;
        } else {
            tty->eof_pending = 1;
        }
        tty_wake_readers(index);
        posix_poll_notify();
        return POSIX_TTY_EVENT_NONE;
    }
    if (tty->line_length < POSIX_TTY_LINE_MAX) {
        tty->line[tty->line_length++] = byte;
        tty_echo(tty, byte);
    }
    return POSIX_TTY_EVENT_NONE;
}

// The event byte names a signal and the line's owner is the group it goes
// to. The disposition rules are the ones every other sender uses, so an
// ignored SIGINT stays ignored, a blocked one stays pending, and a stopped
// member reports to its parent exactly as a kill from a process would. A
// default-terminate action is taken here through the runtime hook, because
// the wire has no syscall frame to return through.
void posix_tty_deliver(u32 index, u32 event) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty || !tty->foreground) return;
    if (!(tty->termios.lflag & POSIX_ISIG)) return;
    u32 signo = 0;
    if (event & POSIX_TTY_EVENT_INTR) signo = POSIX_SIG_INT;
    else if (event & POSIX_TTY_EVENT_QUIT) signo = POSIX_SIG_QUIT;
    else if (event & POSIX_TTY_EVENT_SUSP) signo = POSIX_SIG_TSTP;
    if (!signo) return;
    struct task *batch[POSIX_PGROUP_BATCH];
    u32 from = 0;
    u32 count;
    while ((count = posix_pgroup_members_from(tty->foreground, from, batch,
                                              POSIX_PGROUP_BATCH, &from))) {
        for (u32 member = 0; member < count; member++) {
            struct task *target = batch[member];
            if (posix_signal_one(target, target, signo) == 1)
                task64_terminate((u32)(target - task_pool), signo);
        }
    }
}

// A zero foreground group means nobody claimed the line, which reads as
// everyone being foreground: the rules only exist once a group owns it.
static int tty_background(struct task *task,
                            const struct posix_tty_state *tty) {
    if (!tty->foreground) return 0;
    return posix_pgroup_get(task) != tty->foreground;
}

// The two SIGTTOU gates. A background write asks only when TOSTOP is set,
// while the handover always asks, because taking the line from the group
// that owns it is the one move a background group may never make quietly.
static int tty_tou_gate(struct task *task, u32 index, int always) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty || !task) return POSIX_TTY_ENOTTY;
    if (!always && !(tty->termios.lflag & POSIX_TOSTOP)) return 0;
    if (!tty_background(task, tty)) return 0;
    int posted = posix_signal_one(task, task, POSIX_SIG_TTOU);
    // An ignored, caught or blocked SIGTTOU lets the call through, which
    // is the escape a background logger and a shell's handover use.
    return posted == 2 ? 1 : posted;
}

int posix_tty_check_write(struct task *task, u32 index) {
    return tty_tou_gate(task, index, 0);
}

int posix_tty_check_foreground(struct task *task, u32 index) {
    return tty_tou_gate(task, index, 1);
}

// The background read rule, which is the one place the disposition has to
// be known: a stopped caller resumes with EINTR once it is continued, and
// a caller that keeps running did not take the stop, so the read fails.
int posix_tty_check_read(struct task *task, u32 index) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty || !task) return POSIX_TTY_ENOTTY;
    if (!tty_background(task, tty)) return 0;
    // The read owes EINTR to the resume; the continue hands it over.
    task->stop_answer = POSIX_SIGNAL_EINTR;
    task->stop_answer_set = 1;
    int posted = posix_signal_one(task, task, POSIX_SIG_TTIN);
    if (posted == 2) return 1;
    task->stop_answer = 0;
    task->stop_answer_set = 0;
    if (posted < 0) return posted;
    return POSIX_TTY_EIO;
}

static int tty_ready(const struct posix_tty_state *tty) {
    return tty->queue_count || tty->eof_pending;
}

static void tty_clear_wait(u32 slot) {
    tty_waits[slot].index = 0;
    tty_waits[slot].request = 0;
    tty_waits[slot].length = 0;
}

int posix_tty_read(u32 index, u8 *buffer, u32 length, u32 *transferred) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_ENOTTY;
    if (!buffer || !transferred) return POSIX_TTY_EINVAL;
    if (!tty->queue_count) {
        if (tty->eof_pending) {
            tty->eof_pending = 0;
            *transferred = 0;
            return 0;
        }
        *transferred = 0;
        return POSIX_TTY_EAGAIN;
    }
    u32 count = length < tty->queue_count ? length : tty->queue_count;
    for (u32 offset = 0; offset < count; offset++) {
        buffer[offset] = tty->queue[tty->queue_head];
        tty->queue_head = (tty->queue_head + 1u) % POSIX_TTY_QUEUE_MAX;
        tty->queue_count--;
    }
    *transferred = count;
    return 0;
}

int posix_tty_write(u32 index, const u8 *data, u32 length, u32 *transferred) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_ENOTTY;
    if (!data || !transferred) return POSIX_TTY_EINVAL;
    for (u32 offset = 0; offset < length; offset++)
        tty_emit(tty, data[offset]);
    *transferred = length;
    return 0;
}

// Hand the waiting line to every reader parked on this tty. Each takes
// what is there up to what it asked for, and a reader still without a line
// stays parked; the loop stops as soon as the queue drains.
static void tty_wake_readers(u32 index) {
    struct posix_tty_state *tty = &ttys[index];
    u8 staging[POSIX_IO_MAX];
    klock_acquire(&posix_tty_wait_klock);
    for (u32 slot = 0; slot < (u32)task_pool_count; slot++) {
        struct task *reader = &task_pool[slot];
        if (reader->state != TASK_BLOCKED_TTY ||
            tty_waits[slot].index != index + 1u)
            continue;
        if (!tty_ready(tty)) {
            klock_release(&posix_tty_wait_klock);
            return;
        }
        u32 transferred = 0;
        i64 answer = 0;
        if (posix_tty_read(index, staging, tty_waits[slot].length,
                           &transferred) ||
            vm64_copy_to(reader->page_dir, tty_waits[slot].request +
                         POSIX_IO_DATA_OFFSET, staging, transferred) ||
            posix_io_patch_result(reader, tty_waits[slot].request,
                                  transferred))
            answer = POSIX_TTY_EIO;
        else
            answer = (i64)transferred;
        tty_clear_wait(slot);
        task_state_set(reader, TASK_RUNNING);
        task64_set_result(slot, answer);
    }
    klock_release(&posix_tty_wait_klock);
}

// Returns 1 when a line arrived while the park was being set up, and the
// caller reads it instead of blocking.
int posix_tty_park(struct task *task, u32 index, uptr_t request, u32 length) {
    u32 slot = (u32)(task - task_pool);
    struct posix_tty_state *tty = tty_for(index);
    if (slot >= (u32)MAX_TASKS || !tty || !request || !length) return -1;
    klock_acquire(&posix_tty_wait_klock);
    if (tty_ready(tty)) {
        klock_release(&posix_tty_wait_klock);
        return 1;
    }
    tty_waits[slot].index = index + 1u;
    tty_waits[slot].request = request;
    tty_waits[slot].length = length;
    task_state_set(task, TASK_BLOCKED_TTY);
    klock_release(&posix_tty_wait_klock);
    return 0;
}

static i64 tty_read_ready(struct task *task, u32 index, uptr_t request,
                          u32 length) {
    u8 staging[POSIX_IO_MAX];
    u32 transferred = 0;
    int result = posix_tty_read(index, staging, length, &transferred);
    if (result) return result;
    if (vm64_copy_to(task->page_dir, request + POSIX_IO_DATA_OFFSET,
                     staging, transferred) ||
        posix_io_patch_result(task, request, transferred))
        return POSIX_TTY_EIO;
    return (i64)transferred;
}

i64 posix_tty_io_read(struct task *task, u32 index, uptr_t request,
                      u32 length) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_ENOTTY;
    if (!request || !length) return POSIX_TTY_EINVAL;
    int slot = scheduler_current();
    if (slot < 0 || &task_pool[slot] != task) return POSIX_TTY_EIO;
    // The foreground check comes before the data check: a line waiting in
    // the queue is still not the background's to take.
    int gate = posix_tty_check_read(task, index);
    if (gate == 1) return task64_self_stop((u32)slot);
    if (gate < 0) return gate;
    if (tty_ready(tty))
        return tty_read_ready(task, index, request, length);
    // Nothing typed yet, so the read parks and the input path completes it
    // in the caller's own request, because this frame is abandoned on the
    // switch the way a pipe read's is.
    int parked = posix_tty_park(task, index, request, length);
    if (parked < 0) return POSIX_TTY_EIO;
    if (parked) return tty_read_ready(task, index, request, length);
    if (scheduler_pick_next(slot) < 0) {
        tty_clear_wait((u32)slot);
        task_state_set(task, TASK_RUNNING);
        return POSIX_TTY_EDEADLK;
    }
    return (i64)task64_block_switch();
}

u32 posix_tty_blocked_count(u32 index) {
    u32 count = 0;
    if (index >= POSIX_TTY_MAX) return 0;
    for (u32 slot = 0; slot < (u32)task_pool_count; slot++) {
        if (task_pool[slot].state != TASK_BLOCKED_TTY) continue;
        if (tty_waits[slot].index == index + 1u) count++;
    }
    return count;
}

u16 posix_tty_poll(u32 index) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return 0;
    u16 ready = POSIX_POLLOUT;
    if (tty_ready(tty)) ready |= POSIX_POLLIN;
    return ready;
}

i64 posix_tty_signal(struct task *target) {
    u32 slot = (u32)(target - task_pool);
    if (slot >= (u32)MAX_TASKS || target->state != TASK_BLOCKED_TTY) return 0;
    tty_clear_wait(slot);
    return POSIX_SIGNAL_EINTR;
}

u32 posix_tty_foreground_get(u32 index) {
    struct posix_tty_state *tty = tty_for(index);
    return tty ? tty->foreground : 0;
}

int posix_tty_foreground_set(u32 index, u32 pgid) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_ENOTTY;
    // Zero is the "nobody owns the line" spelling the getter reports, so
    // it is what a caller restores; the syscall path refuses it before it
    // reaches here, since a caller cannot hand the terminal to no group.
    tty->foreground = pgid;
    return 0;
}

int posix_tty_termios_get(u32 index, struct posix_termios *out) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_ENOTTY;
    if (!out) return POSIX_TTY_EINVAL;
    *out = tty->termios;
    return 0;
}

int posix_tty_termios_set(u32 index, const struct posix_termios *in) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_ENOTTY;
    if (!in) return POSIX_TTY_EINVAL;
    // N_TTY is the only line discipline here, so a selector naming another
    // one is refused rather than quietly running the same code.
    if (in->line != POSIX_N_TTY || (in->iflag & ~(u32)POSIX_TTY_IFLAG_KNOWN) ||
        (in->oflag & ~(u32)POSIX_TTY_OFLAG_KNOWN) ||
        (in->lflag & ~(u32)POSIX_TTY_LFLAG_KNOWN))
        return POSIX_TTY_EINVAL;
    tty->termios = *in;
    return 0;
}

int posix_tty_winsize_get(u32 index, struct posix_winsize *out) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_ENOTTY;
    if (!out) return POSIX_TTY_EINVAL;
    *out = tty->winsize;
    return 0;
}

int posix_tty_winsize_set(u32 index, const struct posix_winsize *in) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty) return POSIX_TTY_ENOTTY;
    if (!in) return POSIX_TTY_EINVAL;
    tty->winsize = *in;
    return 0;
}

i64 posix_tty_ioctl(struct task *task, u32 index, u64 request,
                    uptr_t argument) {
    struct posix_tty_state *tty = tty_for(index);
    if (!tty || !task) return POSIX_TTY_ENOTTY;
    switch (request) {
    case POSIX_TCGETS: {
        struct posix_termios copy;
        if (posix_tty_termios_get(index, &copy)) return POSIX_TTY_ENOTTY;
        if (vm64_copy_to(task->page_dir, argument, &copy, sizeof(copy)))
            return POSIX_TTY_EIO;
        return 0;
    }
    case POSIX_TCSETS: {
        struct posix_termios copy;
        if (vm64_copy_from(task->page_dir, &copy, argument, sizeof(copy)))
            return POSIX_TTY_EIO;
        return posix_tty_termios_set(index, &copy);
    }
    case POSIX_TIOCGWINSZ: {
        struct posix_winsize copy;
        if (posix_tty_winsize_get(index, &copy)) return POSIX_TTY_ENOTTY;
        if (vm64_copy_to(task->page_dir, argument, &copy, sizeof(copy)))
            return POSIX_TTY_EIO;
        return 0;
    }
    case POSIX_TIOCSWINSZ: {
        struct posix_winsize copy;
        if (vm64_copy_from(task->page_dir, &copy, argument, sizeof(copy)))
            return POSIX_TTY_EIO;
        return posix_tty_winsize_set(index, &copy);
    }
    case POSIX_TIOCGPGRP: {
        u32 pgid = posix_tty_foreground_get(index);
        if (vm64_copy_to(task->page_dir, argument, &pgid, sizeof(pgid)))
            return POSIX_TTY_EIO;
        return 0;
    }
    case POSIX_TIOCSPGRP: {
        u32 pgid = 0;
        if (vm64_copy_from(task->page_dir, &pgid, argument, sizeof(pgid)))
            return POSIX_TTY_EIO;
        int gate = posix_tty_check_foreground(task, index);
        if (gate == 1) return task64_self_stop((u32)(task - task_pool));
        if (gate < 0) return gate;
        if (!posix_pgroup_live(pgid)) return POSIX_TTY_ESRCH;
        return posix_tty_foreground_set(index, pgid);
    }
    default:
        return POSIX_TTY_ENOTTY;
    }
}

u32 posix_tty_active_count(void) {
    u32 count = 0;
    for (u32 index = 0; index < POSIX_TTY_MAX; index++)
        if (ttys[index].active) count++;
    return count;
}
