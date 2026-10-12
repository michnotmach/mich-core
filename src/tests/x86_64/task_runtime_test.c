#include "tests64.h"
#include "test_report.h"
#include "types.h"
#include "task.h"

// Runtime and vruntime are pure arithmetic over a caller-supplied timestamp,
// so they are asserted exactly rather than observed through a real schedule.
// The clock itself is covered by the time base test; what is at stake here is
// the scaling and the guard against charging one interval twice.

int test_task_runtime(void) {
    struct task *t = task_alloc_slot();
    if (!t) return -1;
    if (t->weight != TASK_WEIGHT_DEFAULT || t->runtime_ns || t->vruntime_ns)
        return -2;

    // The default weight scales by one, so both counters move together.
    task_runtime_arm(t, 1000u);
    task_runtime_charge(t, 6000u);
    if (t->runtime_ns != 5000u || t->vruntime_ns != 5000u) return -3;

    // Charging again without arming is a no-op: the arm flag is what stops a
    // second switch path from billing the same interval twice.
    task_runtime_charge(t, 9000u);
    if (t->runtime_ns != 5000u || t->vruntime_ns != 5000u) return -4;

    // Double the weight halves vruntime and leaves wall time alone.
    t->weight = TASK_WEIGHT_DEFAULT * 2u;
    task_runtime_arm(t, 10000u);
    task_runtime_charge(t, 14000u);
    if (t->runtime_ns != 9000u || t->vruntime_ns != 7000u) return -5;

    // A timestamp behind the arm point is dropped rather than subtracted,
    // which would otherwise wrap and bill a huge interval.
    task_runtime_arm(t, 20000u);
    task_runtime_charge(t, 15000u);
    if (t->runtime_ns != 9000u || t->cpu_started_ns != 20000u) return -6;

    task_free_slot(t);
    return 0;
}

// The policy is asserted through the pure scaling rather than by watching a
// schedule, because the clock advance depends on every runnable task in the
// system and a test running inside the kernel cannot fix that. What is
// checked here is the arithmetic and the eligibility relation it implies.
int test_eevdf(void) {
    u64 slice = TASK_SLICE_NS;

    if (task_vruntime_delta(4000u, TASK_WEIGHT_DEFAULT) != 4000u) return -1;
    if (task_vruntime_delta(4000u, TASK_WEIGHT_DEFAULT * 2u) != 2000u)
        return -2;
    // A zero share is the default rather than a division by zero.
    if (task_vruntime_delta(4000u, 0) != 4000u) return -3;

    if (task_deadline_from(0, TASK_WEIGHT_DEFAULT) != slice) return -4;
    if (task_deadline_from(0, TASK_WEIGHT_DEFAULT * 2u) != slice / 2u)
        return -5;
    // A larger share has to buy an earlier deadline at equal vruntime, or
    // weight would mean nothing to the pick.
    if (task_deadline_from(1000u, TASK_WEIGHT_DEFAULT) <=
        task_deadline_from(1000u, TASK_WEIGHT_DEFAULT * 4u))
        return -6;

    // Two equal tasks, one of which ran for 2s. The clock advances by the
    // service divided by the total share, so it lands on s: the runner is
    // now ahead of the clock and ineligible, the waiter is behind it and
    // eligible. That inversion is the whole point of the policy.
    u64 step = 3000u;
    u64 vtime = task_vruntime_delta(step * 2u, TASK_WEIGHT_DEFAULT * 2u);
    u64 runner = task_vruntime_delta(step * 2u, TASK_WEIGHT_DEFAULT);
    u64 waiter = 0;
    if (vtime != step) return -7;
    if (runner <= vtime) return -8;
    if (waiter > vtime) return -9;
    return 0;
}
