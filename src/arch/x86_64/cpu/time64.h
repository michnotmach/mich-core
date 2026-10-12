#ifndef TIME64_H
#define TIME64_H

#include "types.h"

// A monotonic nanosecond clock for the scheduler. The scheduler cannot use
// raw TSC ticks because the tick rate differs between machines and differs
// again between TCG and KVM, so every consumer would have to know the
// frequency. ARM64 implements the same three entry points over the
// architected generic timer.

// Establish the time base. Must run before anything delays by wall time,
// which includes APIC timer calibration and AP bring-up.
int time64_init(void);

// Nanoseconds since time64_init(). Monotonic on the calling CPU.
u64 time64_ns(void);

// Calibrated TSC rate in kHz, or 0 before time64_init() succeeds.
u32 time64_tsc_khz(void);

// Raw TSC ticks spanning ns, for callers that build a deadline by hand and
// cannot afford a division on a hot path.
u64 time64_ticks_from_ns(u64 ns);

#endif
