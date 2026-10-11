#include "task.h"
#include "arch_task.h"
#include "klock.h"
#include "posix_fd.h"
#include "posix_profile.h"
#include "posix_signal.h"
#include "posix_pgroup.h"
#include "posix_pledge.h"

struct task task_pool[MAX_TASKS];
int task_pool_count = 0;

// The pool is the one table every CPU walks: every tick picks from it, the
// BSP spawns into it, and a task exits on whichever CPU ran it. Level 1 of
// the order in the notes means everything below may be taken while it is
// held, and nothing below may take it again, so the transitions here are
// the only writers of the fields the pick reads.
static struct klock task_pool_klock = KLOCK_INIT(KLOCK_LEVEL_POOL);

void task_pool_lock(void) {
    klock_acquire(&task_pool_klock);
}

void task_pool_unlock(void) {
    klock_release(&task_pool_klock);
}

static void task_clear_dynamic(struct task *t) {
    t->page_dir = 0;
    t->recv_buf = 0;
    t->pending_msg = 0;
    t->iomap = 0;
    t->next = 0;
    t->wq_head = 0;
    t->wq_tail = 0;
    t->parent_id = -1;
    t->exit_code = 0;
    t->exit_signal = 0;
    t->wait_pid = -1;
    t->wait_posix = 0;
    t->wait_status_address = 0;
    t->kstack_phys = 0;
    t->exec_gate = 0;
    t->recv_expect = 0;
    t->send_result = 0;
    t->send_to = 0;
    t->send_deadline = 0;
    t->sleep_deadline = 0;
    t->sleep_request = 0;
    t->capabilities = 0;
    t->irq_rights = 0;
    for (int i = 0; i < MAX_MMIO_GRANTS; i++) {
        t->mmio[i].phys = 0;
        t->mmio[i].length = 0;
        t->mmio[i].mapped_va = 0;
    }
    t->dma_page_limit = 0;
    t->dma_pages_used = 0;
    t->dma_max_addr = 0;
    t->on_cpu = TASK_CPU_NONE;
    t->is_idle = 0;
    t->name[0] = 0;
}

// The check and the write sit in one critical section: two CPUs waking the
// same waiter would otherwise both see it parked and both publish a result.
int task_state_wake_locked(struct task *t, int from_state) {
    if (t->state != from_state) return 0;
    t->state = TASK_RUNNING;
    return 1;
}

int task_state_wake(struct task *t, int from_state) {
    int woke;
    if (!t) return 0;
    task_pool_lock();
    woke = task_state_wake_locked(t, from_state);
    task_pool_unlock();
    return woke;
}

void task_state_set_locked(struct task *t, int state) {
    t->state = state;
}

void task_state_set(struct task *t, int state) {
    if (!t) return;
    task_pool_lock();
    task_state_set_locked(t, state);
    task_pool_unlock();
}

void task_sleep_block_locked(struct task *t, u32 deadline) {
    t->sleep_deadline = deadline;
    t->state = TASK_BLOCKED_SLEEP;
}

void task_sleep_block(struct task *t, u32 deadline) {
    if (!t) return;
    task_pool_lock();
    task_sleep_block_locked(t, deadline);
    task_pool_unlock();
}

void task_sleep_expire_locked(struct task *t) {
    t->sleep_deadline = 0;
    t->state = TASK_RUNNING;
}

// The tick and a signal can reach the same sleeper, and only one of them
// may publish the result the abandoned frame will return. The claim hands
// back what the interrupted sleep still owed and flips the state in one
// step, so the loser sees a task that is no longer parked.
int task_sleep_wake_claim(struct task *t, u32 *deadline, uptr_t *request) {
    int parked;
    task_pool_lock();
    parked = t->state == TASK_BLOCKED_SLEEP;
    if (parked) {
        *deadline = t->sleep_deadline;
        *request = t->sleep_request;
        t->sleep_deadline = 0;
        t->sleep_request = 0;
        t->state = TASK_RUNNING;
    }
    task_pool_unlock();
    return parked;
}

void task_exit_signal_set(struct task *t, u32 signo) {
    if (!t) return;
    task_pool_lock();
    t->exit_signal = signo;
    task_pool_unlock();
}

// The wait fields and the state are one record: a CPU that finds the state
// parked has to find the fields that go with it, and the park and the wake
// each have to move both in one critical section. A wake that landed
// between the two would see a task that is not parked yet and skip it,
// which leaves it parked with nothing left to wake it.
void task_wait_park(struct task *t, int pid, int posix, u32 options,
                    uptr_t status_address) {
    if (!t) return;
    task_pool_lock();
    t->wait_pid = pid;
    t->wait_posix = posix;
    t->wait_options = options;
    t->wait_status_address = status_address;
    t->state = TASK_BLOCKED_WAIT;
    task_pool_unlock();
}

// The match and the flip in one critical section: the child's exit and a
// signal can reach the same waiting parent, and the CPU that claims the
// record is the only one that publishes the report its frame returns.
int task_wait_wake(struct task *t, int child_id) {
    int claimed;
    if (!t) return 0;
    task_pool_lock();
    claimed = t->state == TASK_BLOCKED_WAIT &&
        (t->wait_pid == -1 || t->wait_pid == child_id);
    if (claimed) {
        t->wait_pid = -1;
        t->state = TASK_RUNNING;
    }
    task_pool_unlock();
    return claimed;
}

// The signal wake abandons the wait without a report, so it clears the
// whole record: the woken parent must not read a promise of a status word
// nobody is going to write.
int task_wait_cancel(struct task *t, int child_id) {
    int claimed;
    if (!t) return 0;
    task_pool_lock();
    claimed = t->state == TASK_BLOCKED_WAIT &&
        (t->wait_pid == -1 || t->wait_pid == child_id);
    if (claimed) {
        t->wait_pid = -1;
        t->wait_posix = 0;
        t->wait_options = 0;
        t->wait_status_address = 0;
        t->state = TASK_RUNNING;
    }
    task_pool_unlock();
    return claimed;
}

// The rollback a park takes back when nothing else can run: no other CPU
// saw the record, so it is the park's to clear.
void task_wait_clear(struct task *t) {
    if (!t) return;
    task_pool_lock();
    t->wait_pid = -1;
    t->wait_posix = 0;
    t->wait_options = 0;
    t->wait_status_address = 0;
    t->state = TASK_RUNNING;
    task_pool_unlock();
}

void task_cpu_claim(struct task *t, int cpu) {
    if (!t) return;
    task_pool_lock();
    t->on_cpu = cpu;
    task_pool_unlock();
}

void task_cpu_release(struct task *t) {
    task_cpu_claim(t, TASK_CPU_NONE);
}

// Slots that are not free, which is what a spawn and reap section can assert
// on: unlike the free page count it does not move when another task allocates,
// so a capsule that stays alive shifts it once instead of every packet.
u32 task_active_count(void) {
    u32 live = 0;
    task_pool_lock();
    for (int i = 1; i < task_pool_count; i++)
        if (task_pool[i].state != TASK_FREE) live++;
    task_pool_unlock();
    return live;
}

struct task *task_alloc_slot(void) {
    struct task *t = 0;
    task_pool_lock();
    for (int i = 1; i < MAX_TASKS; i++) {
        if (task_pool[i].state == TASK_FREE) {
            t = &task_pool[i];
            break;
        }
    }
    if (!t && task_pool_count < MAX_TASKS) t = &task_pool[task_pool_count++];
    if (t) {
        t->state = TASK_RUNNING;
        t->on_cpu = TASK_CPU_NONE;
        t->id = t->gen ? (int)PID_MAKE(t->gen, (unsigned int)(t - task_pool))
                       : (int)(t - task_pool);
    }
    task_pool_unlock();
    return t;
}

// The teardown below reaches the object table and the allocator, so the lock
// is not held across it: only the writes that make the slot allocatable
// again are, which is what keeps a fresh spawn off a slot still being torn
// down.
void task_free_slot(struct task *t) {
    unsigned int g = t->gen;
    t->exit_signal = 0;
    posix_fd_close_all(t);
    posix_profile_release(t);
    posix_signal_reset(t);
    posix_pgroup_reset(t);
    posix_pledge_reset(t);
    arch_task_release(t);
    g = (g + 1) & 0x7FFFu;
    if (!g) g = 1;
    task_pool_lock();
    task_clear_dynamic(t);
    t->esp = 0;
    t->eip = 0;
    t->stack = 0;
    t->kernel_stack = 0;
    t->gen = g;
    t->state = TASK_FREE;
    task_pool_unlock();
}

void task_mark_zombie(struct task *t, int code) {
    posix_fd_close_all(t);
    posix_profile_release(t);
    posix_signal_reset(t);
    posix_pgroup_reset(t);
    posix_pledge_reset(t);
    task_pool_lock();
    t->exit_code = code;
    t->on_cpu = TASK_CPU_NONE;
    t->state = TASK_ZOMBIE;
    t->recv_buf = 0;
    t->recv_expect = 0;
    t->pending_msg = 0;
    t->send_to = 0;
    t->send_deadline = 0;
    t->sleep_deadline = 0;
    t->sleep_request = 0;
    t->next = 0;
    t->wait_pid = -1;
    t->wait_posix = 0;
    t->wait_status_address = 0;
    t->capabilities = 0;
    t->irq_rights = 0;
    task_pool_unlock();
}

// The check runs under the lock and the teardown outside it: freeing the
// slot takes the lock of its own, and a slot that looked like a zombie
// cannot be reaped twice once the claim is read and released as one step.
int task_reap_zombie(struct task *parent, int pid, int *code) {
    unsigned int slot = PID_SLOT((unsigned int)pid);
    struct task *child;
    int ok;
    if (!parent || !code || slot == 0 || slot >= (unsigned int)task_pool_count)
        return -1;
    child = &task_pool[slot];
    task_pool_lock();
    ok = child->state == TASK_ZOMBIE && child->id == pid &&
         child->parent_id == parent->id;
    if (ok) *code = child->exit_code;
    task_pool_unlock();
    if (!ok) return -1;
    task_free_slot(child);
    return 0;
}

// The pick and the claim in one critical section: a task chosen in one
// section and claimed in the next is a task a second CPU can choose in
// between, and the shared run queue makes that the normal case, not a
// corner. The read-only form serves the callers that only ask whether
// anything is runnable at all.
static int task_pick_locked(int current, int cpu, int claim) {
    int idle = -1;
    int pick = -1;
    if (task_pool_count <= 0) return -1;
    for (int offset = 1; offset <= task_pool_count; offset++) {
        int candidate = (current + offset) % task_pool_count;
        if (task_pool[candidate].state != TASK_RUNNING) continue;
        int owner = task_pool[candidate].on_cpu;
        if (owner != TASK_CPU_NONE && owner != cpu) continue;
        // The idle task is always runnable and does no useful work: remember
        // it and keep scanning, so a freshly woken task is not passed over.
        if (task_pool[candidate].is_idle) {
            if (idle < 0) idle = candidate;
            continue;
        }
        pick = candidate;
        break;
    }
    if (pick < 0) pick = idle;
    if (claim && pick >= 0) task_pool[pick].on_cpu = cpu;
    return pick;
}

int task_pick_next(int current, int cpu) {
    int next;
    task_pool_lock();
    next = task_pick_locked(current, cpu, 0);
    task_pool_unlock();
    return next;
}

int task_pick_and_claim(int current, int cpu) {
    int next;
    task_pool_lock();
    next = task_pick_locked(current, cpu, 1);
    task_pool_unlock();
    return next;
}

// A task pinned to one CPU, seen only by that CPU, so no claim is needed.
int task_pick_pinned(int cpu, int current) {
    int idle = -1;
    int pick = -1;
    task_pool_lock();
    for (int offset = 1; offset <= task_pool_count; offset++) {
        int candidate = (current + offset) % task_pool_count;
        if (task_pool[candidate].state != TASK_RUNNING) continue;
        if (task_pool[candidate].on_cpu != cpu) continue;
        if (task_pool[candidate].is_idle) {
            if (idle < 0) idle = candidate;
            continue;
        }
        pick = candidate;
        break;
    }
    task_pool_unlock();
    return pick >= 0 ? pick : idle;
}

void task_set_name(struct task *t, const char *path) {
    const char *base = path;
    if (!base || !base[0]) base = "elf";
    for (const char *p = base; *p; p++)
        if (*p == '/') base = p + 1;
    int j = 0;
    while (j < 15 && base[j] && base[j] != '.') { t->name[j] = base[j]; j++; }
    t->name[j] = 0;
}

struct task *create_task(void (*entry)(void), reg_t *stack_top, reg_t *kernel_stack_top, int ring) {
    struct task *t = task_alloc_slot();
    if (!t) return 0;

    t->stack = stack_top;
    t->kernel_stack = (ring == 3) ? kernel_stack_top : stack_top;
    t->eip = (reg_t)(uptr_t)entry;
    t->ring = ring;
    task_clear_dynamic(t);

    reg_t *sp = t->kernel_stack;

    *--sp = USER_SS;
    *--sp = (reg_t)(uptr_t)stack_top;
    *--sp = USER_EFLAGS;
    *--sp = USER_CS;
    *--sp = t->eip;

    *--sp = 0;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;
    *--sp = 0;

    t->esp = (reg_t)(uptr_t)sp;
    return t;
}
