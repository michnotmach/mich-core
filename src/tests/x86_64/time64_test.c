#include "tests64.h"
#include "test_report.h"
#include "types.h"
#include "time64.h"
#include "apic64.h"
#include "serial64.h"

// The time base drives the 100 Hz tick and the AP bring-up delays, and it
// used to be a bare assumption that the TSC runs at exactly 1 GHz. What is
// asserted here is the calibration and the conversion arithmetic. The
// frequency itself is published rather than asserted against a number,
// because the interesting comparison is between environments: under TCG the
// reading is the one the old hardcode happened to match, and under KVM on
// real silicon it will not be.

int test_time64(void) {
    u32 khz = time64_tsc_khz();
    serial64_write("Mich x86_64: time64 tsc_khz=0x");
    serial64_hex(khz);
    serial64_write("\n");
    // time64_init already refused to boot outside this range, so a failure
    // here means the value moved after init rather than that calibration
    // was merely unlucky.
    if (khz < 50000u || khz > 10000000u) return -1;

    u64 first = time64_ns();
    u64 second = time64_ns();
    if (second < first) return -2;

    // One second has to invert to exactly the calibrated rate, and one
    // millisecond to the rate in kHz. These are the two boundaries where a
    // wrong split in the multiply would show up as an order of magnitude.
    u64 one_second = time64_ticks_from_ns(1000000000ULL);
    u64 want_hz = (u64)khz * 1000u;
    if (one_second != want_hz) return -3;
    u64 one_ms = time64_ticks_from_ns(1000000u);
    if (one_ms != (u64)khz) return -4;

    // The delay path shares this clock, so this checks that the plumbing
    // agrees with itself rather than proving the frequency. It still
    // catches a zero rate, which would make every deadline fire instantly.
    u64 start = time64_ns();
    if (apic64_delay_ms(10)) return -5;
    u64 elapsed = time64_ns() - start;
    if (elapsed < 5000000u || elapsed > 40000000u) return -6;
    return 0;
}
