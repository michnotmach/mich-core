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
