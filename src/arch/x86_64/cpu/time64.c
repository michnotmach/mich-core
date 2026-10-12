#include "time64.h"

// PIT channel 2 is the calibration reference. Channel 0 is unusable here
// because programming it raises IRQ 0, which is why the APIC timer code
// rules the PIT out. Channel 2 drives the speaker gate and raises nothing,
// so it is readable at any point in boot, and its input is the fixed
// 1.193182 MHz oscillator every PC has.
#define TIME64_PIT_HZ 1193182u
#define PIT64_CHANNEL2_DATA 0x42u
#define PIT64_MODE 0x43u
#define PIT64_GATE 0x61u

// Roughly 20 ms of counting: long enough that port polling jitter is a
// small fraction of the window, short enough to stay invisible in boot.
#define TIME64_PIT_COUNT 23864u

// Outside this range the calibration read garbage. A wrong time base is
// worse than refusing to boot, because every deadline in the kernel would
// silently scale by the same factor.
#define TIME64_TSC_KHZ_MIN 50000u
#define TIME64_TSC_KHZ_MAX 10000000u

static u32 tsc_khz;
static u64 tsc_origin;

static u64 time64_rdtsc(void) {
    u32 low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return ((u64)high << 32) | (u64)low;
}

static u8 time64_inb(u16 port) {
    u8 value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void time64_outb(u16 port, u8 value) {
    __asm__ volatile("outb %0, %1" :: "a"(value), "Nd"(port));
}

static void time64_cpuid(u32 leaf, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx) {
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf));
}

// Run PIT channel 2 down once and time it with the TSC. The ratio is the
// TSC rate, because the PIT rate is fixed.
static int time64_calibrate_pit(u32 *khz_out) {
    // Channel 2, lobyte/hibyte, mode 0 (one-shot), binary counting.
    time64_outb(PIT64_MODE, 0xB0u);
    time64_outb(PIT64_CHANNEL2_DATA, (u8)(TIME64_PIT_COUNT & 0xFFu));
    time64_outb(PIT64_CHANNEL2_DATA, (u8)(TIME64_PIT_COUNT >> 8));
    // Gate the counter on, speaker off: bit 0 is the gate, bit 1 the
    // speaker enable.
    time64_outb(PIT64_GATE, (u8)((time64_inb(PIT64_GATE) & 0xFCu) | 0x01u));
    u64 start = time64_rdtsc();
    // OUT2 lands in bit 5 when the count expires.
    for (u32 spin = 0; spin < 400000000u; spin++) {
        if (!(time64_inb(PIT64_GATE) & 0x20u)) continue;
        u64 ticks = time64_rdtsc() - start;
        // Anything shorter means the gate read stale and the ratio would
        // be nonsense, so reject it rather than publish it.
        if (ticks < 1000u) return -1;
        *khz_out = (u32)((ticks * TIME64_PIT_HZ) /
                         (TIME64_PIT_COUNT * 1000u));
        return 0;
    }
    return -1;
}

// Fallback for machines where the PIT is absent or not wired up. Leaf 0x15
// reports the crystal ratio directly; leaf 0x16 reports the base frequency
// in MHz, which on every part that has it is also the invariant TSC rate.
static int time64_calibrate_cpuid(u32 *khz_out) {
    u32 eax, ebx, ecx, edx;
    time64_cpuid(0x15u, &eax, &ebx, &ecx, &edx);
    if (eax && ebx && ecx) {
        *khz_out = (u32)((((u64)ecx * ebx) / eax) / 1000u);
        return 0;
    }
    time64_cpuid(0x16u, &eax, &ebx, &ecx, &edx);
    if (eax) {
        *khz_out = eax * 1000u;
        return 0;
    }
    return -1;
}

int time64_init(void) {
    u32 khz = 0;
    if (time64_calibrate_pit(&khz) && time64_calibrate_cpuid(&khz))
        return -1;
    if (khz < TIME64_TSC_KHZ_MIN || khz > TIME64_TSC_KHZ_MAX) return -1;
    tsc_khz = khz;
    tsc_origin = time64_rdtsc();
    return 0;
}

u64 time64_ns(void) {
    u64 hz = (u64)tsc_khz * 1000u;
    if (!hz) return 0;
    u64 ticks = time64_rdtsc() - tsc_origin;
    // Split the product so no intermediate exceeds 64 bits: the whole
    // seconds part cannot overflow for centuries of uptime, and the
    // remainder is smaller than hz by definition.
    return (ticks / hz) * 1000000000u +
           ((ticks % hz) * 1000000000u) / hz;
}

u32 time64_tsc_khz(void) {
    return tsc_khz;
}

u64 time64_ticks_from_ns(u64 ns) {
    u64 hz = (u64)tsc_khz * 1000u;
    if (!hz) return 0;
    // Same split, inverted, so a caller that needs a raw TSC deadline can
    // have one without paying a division per call.
    return ((ns / 1000000000u) * hz) +
           (((ns % 1000000000u) * hz) / 1000000000u);
}
