#include "types.h"
#include "posix_abi.h"
#include "posix_pgroup.h"
#include "posix_process.h"
#include "posix_signal.h"
#include "posix_tty.h"
#include "task.h"
#include "tests64.h"

// Process groups, the stopped state and the waitpid vocabulary. The test
// drives the signal layer directly on probe tasks: a stop is a state
// transition the scheduler already understands, and the reports the parent
// collects are read back as status words, not inferred from a console log.

int test_posix_job64(struct task *owner) {
    struct task *probe = task_alloc_slot();
    struct task *peer = task_alloc_slot();
    int valid = probe && peer && probe != peer;
    if (!valid) {
        if (probe) task_free_slot(probe);
        if (peer) task_free_slot(peer);
        return -1;
    }

    probe->parent_id = -1;
    peer->parent_id = -1;
    probe->uid = 0;
    peer->uid = 0;
    posix_signal_reset(probe);
    posix_signal_reset(peer);

    // A task that never named a group leads its own; setpgid(0, 0) keeps
    // that, and a group id nobody is in is refused rather than invented.
    u32 own = (u32)probe->id;
    valid = valid && posix_pgroup_get(probe) == own &&
        posix_pgroup_set(probe, own) == 0 &&
        posix_pgroup_get(probe) == own &&
        posix_pgroup_set(probe, own + 1000u) == -1;
    // The peer joins the probe's group, and the fork inheritance keeps a
    // child in its parent's group.
    valid = valid && posix_pgroup_set(peer, own) == 0 &&
        posix_pgroup_get(peer) == own &&
        posix_pgroup_live(own) == 1;
    struct task *batch[POSIX_PGROUP_BATCH];
    u32 from = 0;
    u32 count = 0;
    u32 found;
    int saw_probe = 0;
    int saw_peer = 0;
    while ((found = posix_pgroup_members_from(own, from, batch,
                                              POSIX_PGROUP_BATCH, &from))) {
        count += found;
        for (u32 index = 0; index < found; index++) {
            if (batch[index] == probe) saw_probe = 1;
            if (batch[index] == peer) saw_peer = 1;
        }
    }
    valid = valid && count >= 2;
    valid = valid && saw_probe && saw_peer;

    // A default SIGTSTP stops the target: the state leaves the runnable
    // set and the report names the signal that did it.
    peer->state = TASK_RUNNING;
    peer->stop_report = 0;
    peer->continued_report = 0;
    int posted = posix_signal_one(owner, peer, POSIX_SIG_TSTP);
    valid = valid && posted == 0 && peer->state == TASK_STOPPED &&
        peer->stop_report == POSIX_SIG_TSTP;
    // SIGCONT runs it again and turns the stop report into a continue.
    posted = posix_signal_one(owner, peer, POSIX_SIG_CONT);
    valid = valid && posted == 0 && peer->state == TASK_RUNNING &&
        peer->stop_report == 0 && peer->continued_report == 1;
    // A stop does not restart a task that is already stopped, and a
    // continue of a running task reports nothing.
    posted = posix_signal_one(owner, peer, POSIX_SIG_STOP);
    valid = valid && posted == 0 && peer->state == TASK_STOPPED;
    posted = posix_signal_one(owner, peer, POSIX_SIG_STOP);
    valid = valid && peer->state == TASK_STOPPED;
    valid = valid && posix_signal_one(owner, peer, POSIX_SIG_CONT) == 0 &&
        peer->state == TASK_RUNNING;
    peer->continued_report = 0;

    // A caught stop signal runs the handler instead of stopping: the
    // disposition decides, not the number.
    struct posix_sigaction_request action;
    u8 *bytes = (u8 *)&action;
    for (u32 index = 0; index < sizeof(action); index++) bytes[index] = 0;
    action.signo = (u32)POSIX_SIG_TTIN;
    action.handler = 0x400000u;
    action.restorer = 0x401000u;
    action.flags = POSIX_SA_APPLY | POSIX_SA_RESTORER;
    valid = valid && posix_signal_action(peer, POSIX_SIG_TTIN, &action) == 0;
    posted = posix_signal_one(owner, peer, POSIX_SIG_TTIN);
    valid = valid && posted == 0 && peer->state == TASK_RUNNING &&
        peer->stop_report == 0;
    // And SIGSTOP cannot be caught: a handler for it is refused.
    action.signo = (u32)POSIX_SIG_STOP;
    valid = valid && posix_signal_action(peer, POSIX_SIG_STOP, &action) ==
        POSIX_SIGNAL_EINVAL && peer->state == TASK_RUNNING;

    // The status words: an exit is a zero low byte with the code above it,
    // a death carries the signal in the low byte, and the two job-control
    // reports take the low byte whole so no code can read as one. Exit 1
    // is the case that a flag-in-the-middle layout got wrong, so it is the
    // one the test pins.
    u32 exit_status = posix_wait_status(7, 0, 0, 0);
    u32 one_status = posix_wait_status(1, 0, 0, 0);
    u32 signal_status = posix_wait_status(0, (u32)POSIX_SIG_KILL, 0, 0);
    u32 stop_status = posix_wait_status(0, 0, (u32)POSIX_SIG_TSTP, 0);
    u32 cont_status = posix_wait_status(0, 0, 0, 1);
    valid = valid && exit_status == (7u << 8) && (exit_status & 0xFF) == 0 &&
        (exit_status >> 8) == 7u && (exit_status & 0xFF) != 0x7Fu &&
        one_status == (1u << 8) && (one_status & 0xFF) == 0 &&
        signal_status == (u32)POSIX_SIG_KILL &&
        (signal_status & 0xFF) != 0 && (signal_status & 0xFF) != 0x7Fu &&
        stop_status == (0x7Fu | ((u32)POSIX_SIG_TSTP << 8)) &&
        (stop_status & 0xFF) == 0x7Fu && (stop_status >> 8) == 20u &&
        cont_status == 0xFFFFu && (cont_status & 0xFF) == 0xFFu &&
        (cont_status & 0xFF) != 0x7Fu;

    // The terminal's foreground group: a line nobody owns reads as zero,
    // the set refuses a dead group, and a live one sticks.
    valid = valid && posix_tty_foreground_set(POSIX_TTY_MAX, own) ==
        POSIX_TTY_ENOTTY;
    u32 previous = posix_tty_foreground_get(0);
    valid = valid && posix_tty_foreground_set(0, own) == 0 &&
        posix_tty_foreground_get(0) == own &&
        posix_tty_foreground_set(0, previous) == 0 &&
        posix_tty_foreground_get(0) == previous;

    // A tty of the test's own: nothing typed means a read parks rather
    // than answering zero bytes, the ready row follows the line the
    // discipline assembles, and a signal breaks the park with EINTR.
    int spare = posix_tty_create();
    valid = valid && spare >= 1 &&
        posix_tty_poll((u32)spare) == POSIX_POLLOUT &&
        posix_tty_park(probe, (u32)spare, 0, 8) == -1 &&
        posix_tty_blocked_count((u32)spare) == 0;
    valid = valid && posix_tty_park(probe, (u32)spare, 0x400000u, 8) == 0 &&
        probe->state == TASK_BLOCKED_TTY &&
        posix_tty_blocked_count((u32)spare) == 1 &&
        posix_tty_poll((u32)spare) == POSIX_POLLOUT;
    valid = valid && posix_tty_signal(probe) == POSIX_SIGNAL_EINTR &&
        posix_tty_blocked_count((u32)spare) == 0;
    probe->state = TASK_RUNNING;
    valid = valid && posix_tty_input_byte((u32)spare, 'h') ==
        POSIX_TTY_EVENT_NONE &&
        posix_tty_input_byte((u32)spare, '\n') == POSIX_TTY_EVENT_NONE &&
        posix_tty_poll((u32)spare) == (POSIX_POLLOUT | POSIX_POLLIN);
    u8 line[8];
    u32 got = 0;
    valid = valid && posix_tty_read((u32)spare, line, sizeof(line), &got) == 0 &&
        got == 2 && line[0] == 'h' && line[1] == '\n' &&
        posix_tty_poll((u32)spare) == POSIX_POLLOUT;
    posix_tty_destroy((u32)spare);

    // The background rules. The peer leads the group that owns the line,
    // so the probe is background on it: a read stops the probe with
    // SIGTTIN, an ignored SIGTTIN turns the read into EIO instead of a
    // wait that may never end, and the gates leave the owner alone.
    int spare_second = posix_tty_create();
    valid = valid && spare_second >= 1 &&
        posix_pgroup_set(peer, (u32)peer->id) == 0 &&
        posix_tty_foreground_set((u32)spare_second, (u32)peer->id) == 0;
    posix_signal_reset(probe);
    probe->state = TASK_RUNNING;
    probe->stop_report = 0;
    valid = valid && posix_tty_check_read(probe, (u32)spare_second) == 1 &&
        probe->state == TASK_STOPPED &&
        probe->stop_report == POSIX_SIG_TTIN;
    valid = valid && posix_signal_one(probe, probe, POSIX_SIG_CONT) == 0 &&
        probe->state == TASK_RUNNING;
    probe->continued_report = 0;
    struct posix_sigaction_request ignore;
    for (u32 index = 0; index < sizeof(ignore); index++)
        ((u8 *)&ignore)[index] = 0;
    ignore.signo = (i32)POSIX_SIG_TTIN;
    ignore.flags = POSIX_SA_APPLY;
    ignore.handler = POSIX_SIG_IGN;
    valid = valid && posix_signal_action(probe, POSIX_SIG_TTIN, &ignore) == 0 &&
        posix_tty_check_read(probe, (u32)spare_second) == POSIX_TTY_EIO &&
        probe->state == TASK_RUNNING;
    // The owner reads, writes and hands over without a signal, which is
    // what makes the foreground group the foreground group.
    valid = valid && posix_tty_check_read(peer, (u32)spare_second) == 0 &&
        posix_tty_check_write(peer, (u32)spare_second) == 0 &&
        posix_tty_check_foreground(peer, (u32)spare_second) == 0;

    // A background write asks only under TOSTOP, and then stops the
    // writer with SIGTTOU; the handover asks even without TOSTOP.
    posix_signal_reset(probe);
    probe->state = TASK_RUNNING;
    probe->stop_report = 0;
    valid = valid && posix_tty_check_write(probe, (u32)spare_second) == 0;
    struct posix_termios termios;
    valid = valid && posix_tty_termios_get((u32)spare_second, &termios) == 0;
    termios.lflag |= POSIX_TOSTOP;
    valid = valid && posix_tty_termios_set((u32)spare_second, &termios) == 0 &&
        posix_tty_check_write(probe, (u32)spare_second) == 1 &&
        probe->state == TASK_STOPPED &&
        probe->stop_report == POSIX_SIG_TTOU;
    valid = valid && posix_signal_one(probe, probe, POSIX_SIG_CONT) == 0 &&
        probe->state == TASK_RUNNING;
    probe->continued_report = 0;
    valid = valid &&
        posix_tty_check_foreground(probe, (u32)spare_second) == 1 &&
        probe->state == TASK_STOPPED &&
        probe->stop_report == POSIX_SIG_TTOU;
    valid = valid && posix_signal_one(probe, probe, POSIX_SIG_CONT) == 0 &&
        probe->state == TASK_RUNNING;
    probe->continued_report = 0;
    // An ignored SIGTTOU lets both through, which is the escape a
    // background logger and a shell's own handover use.
    ignore.signo = (i32)POSIX_SIG_TTOU;
    ignore.handler = POSIX_SIG_IGN;
    valid = valid && posix_signal_action(probe, POSIX_SIG_TTOU, &ignore) == 0 &&
        posix_tty_check_write(probe, (u32)spare_second) == 0 &&
        posix_tty_check_foreground(probe, (u32)spare_second) == 0 &&
        probe->state == TASK_RUNNING;
    posix_tty_destroy((u32)spare_second);

    posix_signal_reset(probe);
    posix_signal_reset(peer);
    posix_pgroup_reset(probe);
    posix_pgroup_reset(peer);
    task_free_slot(probe);
    task_free_slot(peer);
    return valid ? 0 : -1;
}
