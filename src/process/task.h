#ifndef TASK_H
#define TASK_H

#include "types.h"

// Sixteen CPUs whose APs each host a capsule and an idle task, next to the
// BSP chain, do not fit in sixteen slots. The PID slot field is 16 bits, so
// the pool can grow without changing the encoded ids.
#define MAX_TASKS 32
#define MAX_MMIO_GRANTS 4

struct mmio_grant {
    paddr_t phys;
    usize_t length;
    vaddr_t mapped_va;
};

// Neutral share for a task whose creator asked for none. Scaling against a
// fixed reference keeps vruntime comparable across weights without any of
// them having to know the others.
#define TASK_WEIGHT_DEFAULT 1024u

#define TASK_RUNNING 0
#define TASK_BLOCKED_SEND 1
#define TASK_BLOCKED_RECV 2
#define TASK_ZOMBIE 3
#define TASK_FREE 4
#define TASK_BLOCKED_WAIT 5
#define TASK_BLOCKED_EVENT 6
#define TASK_SUSPENDED 7
#define TASK_BLOCKED_SLEEP 8
#define TASK_BLOCKED_PIPE 9
#define TASK_BLOCKED_SOCKET 10
#define TASK_BLOCKED_POLL 11
#define TASK_STOPPED 12
#define TASK_BLOCKED_TTY 13

// Spawn flag (syscall arg1): the child is created but held off the scheduler
// until its parent resumes it, so the parent can delegate capabilities before
// the child is ever runnable. Mirrored user-side as MICH_SPAWN_SUSPENDED.
#define SPAWN_FLAG_SUSPENDED 1u

#define USER_CS 0x1B
#define USER_SS 0x23
#define USER_EFLAGS 0x202

#define KFRAME_BYTES 52
#define KFR_EDI 0
#define KFR_ESI 1
#define KFR_EBP 2
#define KFR_ESP 3
#define KFR_EBX 4
#define KFR_EDX 5
#define KFR_ECX 6
#define KFR_EAX 7
#define KFR_EIP 8
#define KFR_CS 9
#define KFR_EFLAGS 10
#define KFR_UESP 11
#define KFR_USS 12

#define PID_SLOT(pid) ((unsigned int)(pid) & 0xFFFF)
#define PID_GEN(pid)  ((unsigned int)(pid) >> 16)
#define PID_MAKE(gen, slot) ((((unsigned int)(gen)) << 16) | ((unsigned int)(slot) & 0xFFFF))

#define KSTACK_CANARY 0x4D494348U
#define TASK_CPU_NONE (-1)

struct message;

struct task {
    reg_t esp;
    reg_t eip;
    paddr_t page_dir;
    reg_t *stack;
    reg_t *kernel_stack;
    int id;
    int ring;
    int state;
    struct message *recv_buf;
    const struct message *pending_msg;
    const unsigned char *iomap;
    char name[16];
    struct task *next;
    struct task *wq_head;
    struct task *wq_tail;
    int parent_id;
    int exit_code;
    // Set when the death came from a signal rather than a plain exit, so
    // waitpid can answer WIFSIGNALED with the real termsig instead of
    // folding it into the exit code byte.
    u32 exit_signal;
    int wait_pid;
    // POSIX waitpid waiter state: the blocking dispatch frame is abandoned
    // on switch, so the wake path itself must deliver the reaped pid and
    // publish the encoded status word into the waiter's memory.
    int wait_posix;
    uptr_t wait_status_address;
    // The options the waiter parked with: a stop or a continue is only
    // published to a parent that asked for one.
    u32 wait_options;
    // Stop reporting: the signal that stopped this task stays here until
    // the parent collects the report, the way a zombie keeps its exit
    // code. A continue sets the flag below instead.
    u32 stop_report;
    u32 continued_report;
    // The answer a self-stopped syscall owes its resume. Staged at stop
    // time because the context save inside the very switch that follows
    // overwrites anything published before it; whoever continues the task
    // publishes this instead.
    i64 stop_answer;
    u32 stop_answer_set;
    // Scheduler accounting. runtime_ns is wall time spent on a CPU and
    // vruntime_ns is the same time scaled by weight, which is what a
    // proportional-share policy compares. cpu_started_ns is nonzero only
    // while the task is on a CPU, so a double charge is impossible.
    u64 runtime_ns;
    u64 vruntime_ns;
    u64 cpu_started_ns;
    u32 weight;
    paddr_t kstack_phys;
    u32 exec_gate;
    u32 recv_expect;
    u32 gen;
    int send_result;
    u32 send_to;
    u32 send_deadline;
    // Absolute tick the nanosleep dispatch parks the task until. The timer
    // tick owns the wake, so a sleep can never outlive its deadline.
    u32 sleep_deadline;
    // User address of the nanosleep request the task parked on, so a
    // signal that breaks the sleep can answer the remainder pointer.
    uptr_t sleep_request;
    // Absolute tick a timed poll parks until; zero is the endless wait.
    u32 poll_deadline;
    u32 capabilities;
    u32 irq_rights;
    // POSIX credentials: a single uid and gid, no supplementary groups, and
    // the umask the posix create paths apply. Profile admit seeds them and
    // fork carries them; exec keeps them, as POSIX requires.
    u32 uid;
    u32 gid;
    u32 umask;
    struct mmio_grant mmio[MAX_MMIO_GRANTS];
    u32 dma_page_limit;
    u32 dma_pages_used;
    paddr_t dma_max_addr;
    // CPU currently executing this task, or TASK_CPU_NONE. pick_next
    // skips a task owned by another CPU so two cores cannot run it.
    int on_cpu;
    // The idle task never blocks, so once the scheduler lands on it the CPU
    // busy-loops in ring 3 until the next timer tick preempts it. pick_next
    // treats an idle task as lowest priority and hands the CPU to any other
    // runnable task first, so a syscall-context wake (the virtio capsule
    // delivering a received segment to a blocked socket owner) runs the woken
    // task at once instead of stalling a full ~10ms tick behind the busy-loop.
    int is_idle;
};

extern struct task task_pool[MAX_TASKS];
extern int task_pool_count;
u32 task_active_count(void);

static inline unsigned int task_full_pid(const struct task *t) {
    return PID_MAKE(t->gen, (unsigned int)(t - task_pool));
}

// The pool lock, level 1 of the order in the notes. A single transition
// takes the wrapper; a walk across the pool takes the lock for the loop and
// uses the _locked forms inside, so no slot is freed under the walk.
void task_pool_lock(void);
void task_pool_unlock(void);
void task_state_set(struct task *t, int state);
void task_state_set_locked(struct task *t, int state);
int task_state_wake(struct task *t, int from_state);
int task_sleep_wake_claim(struct task *t, u32 *deadline, uptr_t *request);
// Bookkeeping only: the caller supplies the timestamp, because the clock is
// arch specific and this file is portable.
void task_runtime_arm(struct task *t, u64 now_ns);
void task_runtime_charge(struct task *t, u64 now_ns);

int task_state_wake_locked(struct task *t, int from_state);
void task_sleep_block(struct task *t, u32 deadline);
void task_sleep_block_locked(struct task *t, u32 deadline);
void task_sleep_expire_locked(struct task *t);
void task_exit_signal_set(struct task *t, u32 signo);
void task_wait_park(struct task *t, int pid, int posix, u32 options,
                    uptr_t status_address);
int task_wait_wake(struct task *t, int child_id);
int task_wait_cancel(struct task *t, int child_id);
void task_wait_clear(struct task *t);
void task_cpu_claim(struct task *t, int cpu);
void task_cpu_release(struct task *t);
int task_pick_next(int current, int cpu);
int task_pick_and_claim(int current, int cpu);
int task_pick_pinned(int cpu, int current);

struct task *create_task(void (*entry)(void), reg_t *stack_top, reg_t *kernel_stack_top, int ring);
struct task *task_alloc_slot(void);
void task_free_slot(struct task *t);
void task_mark_zombie(struct task *t, int code);
int task_reap_zombie(struct task *parent, int pid, int *code);
void task_set_name(struct task *t, const char *path);

#endif
