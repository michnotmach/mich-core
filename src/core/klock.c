#include "klock.h"
#include "irq.h"
#include "protos.h"
#include "scheduler.h"
#include "serial.h"

#define KLOCK_DEPTH_MAX 15

// One record per CPU, because the only CPU that can take a lock it already
// holds is the one running the code. The boot CPU answers before the arch
// tables exist: the scheduler id falls back to its own zero record.
static struct {
    u32 depth;
    u32 levels[KLOCK_DEPTH_MAX];
    irq_state_t flags[KLOCK_DEPTH_MAX];
} klock_records[KLOCK_MAX_CPUS];

// Indexed by level minus one. A ticket ahead of the served count means
// this acquire is going to wait, which is the only kind worth counting.
static struct {
    u64 acquires;
    u64 contended;
} klock_stats[KLOCK_LEVEL_PMM];

void klock_stats_read(u32 level, u64 *acquires, u64 *contended) {
    u64 taken = 0;
    u64 waited = 0;
    if (level && level <= KLOCK_LEVEL_PMM) {
        taken = __atomic_load_n(&klock_stats[level - 1].acquires,
                                __ATOMIC_RELAXED);
        waited = __atomic_load_n(&klock_stats[level - 1].contended,
                                 __ATOMIC_RELAXED);
    }
    if (acquires) *acquires = taken;
    if (contended) *contended = waited;
}

int klock_order_ok(u32 held, u32 wanted) {
    return wanted > held;
}

// The abort prints the pair it refused: a bare reason leaves the next red
// run to guess which nesting it tripped on.
static void klock_violation(u32 held, u32 wanted) {
    char digit[2] = {'0', 0};
    serial_write("KLOCK order violation held=");
    digit[0] = (char)('0' + held % 10);
    serial_write(digit);
    serial_write(" wanted=");
    digit[0] = (char)('0' + wanted % 10);
    serial_write(digit);
    serial_write("\n");
    panic_str("KLOCK order violation");
}

static u32 klock_cpu(void) {
    int cpu = scheduler_cpu_id();
    return cpu > 0 && (u32)cpu < KLOCK_MAX_CPUS ? (u32)cpu : 0;
}

u32 klock_held_level(void) {
    u32 cpu = klock_cpu();
    u32 depth = klock_records[cpu].depth;
    return depth ? klock_records[cpu].levels[depth - 1] : 0;
}

// Interrupts go off before the level is read and stay off while the lock is
// held: a tick landing inside the critical section would walk the pool this
// CPU has locked, and the unlock would never come.
void klock_acquire(struct klock *klock) {
    u32 cpu = klock_cpu();
    irq_state_t flags = irq_save();
    u32 depth = klock_records[cpu].depth;
    u32 held = depth ? klock_records[cpu].levels[depth - 1] : 0;
    if (depth >= KLOCK_DEPTH_MAX || !klock_order_ok(held, klock->level))
        klock_violation(held, klock->level);
    __atomic_fetch_add(&klock_stats[klock->level - 1].acquires, 1,
                       __ATOMIC_RELAXED);
    if (__atomic_load_n(&klock->lock.ticket, __ATOMIC_RELAXED) !=
        __atomic_load_n(&klock->lock.served, __ATOMIC_RELAXED))
        __atomic_fetch_add(&klock_stats[klock->level - 1].contended, 1,
                           __ATOMIC_RELAXED);
    spin_lock(&klock->lock);
    klock_records[cpu].levels[depth] = klock->level;
    klock_records[cpu].flags[depth] = flags;
    klock_records[cpu].depth = depth + 1;
}

void klock_release(struct klock *klock) {
    u32 cpu = klock_cpu();
    u32 depth = klock_records[cpu].depth;
    if (!depth || klock_records[cpu].levels[depth - 1] != klock->level)
        panic_str("KLOCK release out of order");
    spin_unlock(&klock->lock);
    klock_records[cpu].depth = depth - 1;
    irq_restore(klock_records[cpu].flags[depth - 1]);
}
