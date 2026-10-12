#include "apic64.h"
#include "time64.h"
#include "vm64.h"

#define MSR_APIC_BASE 0x1B
#define APIC_BASE_ENABLE (1ULL << 11)
#define APIC_BASE_X2 (1ULL << 10)
#define APIC_ID 0x020
#define APIC_EOI 0x0B0
#define APIC_SVR 0x0F0
#define APIC_LVT_TIMER 0x320
#define APIC_LVT_THERMAL 0x330
#define APIC_LVT_PERF 0x340
#define APIC_LVT_LINT0 0x350
#define APIC_LVT_LINT1 0x360
#define APIC_LVT_ERROR 0x370
#define APIC_ICR1 0x300
#define APIC_ICR2 0x310
#define APIC_ICR_INIT (5u << 8)
#define APIC_ICR_SIPI (6u << 8)
#define APIC_ICR_ASSERT (1u << 14)
#define APIC_ICR_LEVEL (1u << 15)
#define APIC_TIMER_INITIAL 0x380
#define APIC_TIMER_CURRENT 0x390
#define APIC_TIMER_DIVIDE 0x3E0
#define APIC_LVT_MASKED (1u << 16)
#define APIC_TIMER_PERIODIC (1u << 17)

static volatile u32 *apic;
static u32 timer_initial;

static inline void outb(u16 port, u8 value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline u8 inb(u16 port) {
    u8 value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static u64 rdmsr(u32 msr) {
    u32 low;
    u32 high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((u64)high << 32) | low;
}

static void wrmsr(u32 msr, u64 value) {
    __asm__ volatile("wrmsr" : : "c"(msr), "a"((u32)value),
                     "d"((u32)(value >> 32)) : "memory");
}

static u32 read_register(u32 offset) {
    return apic[offset / 4];
}

static void write_register(u32 offset, u32 value) {
    apic[offset / 4] = value;
    (void)apic[APIC_ID / 4];
}

int apic64_init(paddr_t physical) {
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1), "c"(0));
    (void)eax;
    (void)ebx;
    (void)ecx;
    if (!(edx & (1u << 9)) || !physical || (physical & 0xFFF) ||
        (physical & ~0x000FFFFFFFFFF000ULL))
        return -1;
    u64 base = rdmsr(MSR_APIC_BASE);
    if (base & APIC_BASE_X2) return -1;
    base &= ~0x000FFFFFFFFFF000ULL;
    base |= (physical & 0x000FFFFFFFFFF000ULL) | APIC_BASE_ENABLE;
    wrmsr(MSR_APIC_BASE, base);
    apic = (volatile u32 *)vm64_ioremap(physical, 4096, VM64_CACHE_UC);
    if (!apic) return -1;
    write_register(APIC_LVT_TIMER, APIC_LVT_MASKED);
    write_register(APIC_LVT_THERMAL, APIC_LVT_MASKED);
    write_register(APIC_LVT_PERF, APIC_LVT_MASKED);
    write_register(APIC_LVT_LINT0, APIC_LVT_MASKED);
    write_register(APIC_LVT_LINT1, APIC_LVT_MASKED);
    write_register(APIC_LVT_ERROR, APIC_LVT_MASKED);
    write_register(APIC_SVR, APIC64_SPURIOUS_VECTOR | (1u << 8));
    return 0;
}

static u64 rdtsc64(void) {
    u32 low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return ((u64)high << 32) | (u64)low;
}

u64 apic64_tsc_now(void) {
    return rdtsc64();
}

// ~10ms guest-time delay via TSC (1 GHz under TCG, so 10^7 ticks ~= 10ms; a faster
// TSC shrinks it proportionally, still far above the INIT/SIPI minimum spacing).
// Not PIT-based: programming PIT counter 0 raises IRQ 0 mid AP bring-up, and QEMU's
// control-word decoding makes the classic control byte unreliable. The spins keep a
// volatile store: pure rdtsc-only loops compile into long read-only TBs under TCG
// that have wedged the vCPU; the store breaks the loop into well-behaved TBs.
static volatile u32 apic64_spin_pad;

static int delay_10ms(void) {
    u64 deadline = rdtsc64() + time64_ticks_from_ns(10000000ULL);
    for (u32 spin = 0; spin < 100000000u; spin++) {
        apic64_spin_pad = spin;
        if (rdtsc64() >= deadline) return 0;
    }
    return -1;
}

int apic64_delay_ms(u32 milliseconds) {
    if (!milliseconds || milliseconds > 1000 || milliseconds % 10) return -1;
    for (u32 elapsed = 0; elapsed < milliseconds; elapsed += 10)
        if (delay_10ms()) return -1;
    return 0;
}

// ICR2 [31:24] carries the destination APIC id in xAPIC physical mode. Delivery is
// synchronous inside the ICR1 store in QEMU, and the TCG APIC never clears the ICR
// busy bit afterwards (latched until APIC reset), so polling the read-back never
// succeeds under TCG and the MMIO loop starves the BSP vCPU under BQL contention
// (measured >6ms per read). Real hardware clears the busy bit in microseconds, so a
// short TSC spacing delay is the portable replacement.
static int icr_send(u32 icr1, u32 icr2) {
    u64 deadline = rdtsc64() + time64_ticks_from_ns(100000ULL);
    write_register(APIC_ICR2, (icr2 & 0xFFu) << 24);
    write_register(APIC_ICR1, icr1);
    for (u32 spin = 0; spin < 1000000u; spin++) {
        apic64_spin_pad = spin;
        if (rdtsc64() >= deadline)
            break;
    }
    return 0;
}

// AP bring-up and IPI primitives. ICR1 encoding (xAPIC, Intel SDM): vector [7:0],
// delivery mode [10:8] (fixed 0, SMI 2, NMI 4, INIT 5, SIPI 6), assert [14], level
// trigger [15]. ICR2 [31:24] is the destination APIC id in physical mode. SIPI
// vector is the 4 KiB page number of the startup address (physical >> 12).
int apic64_ap_start(paddr_t physical, u32 expected_id) {
    if (!apic || !physical || (physical & 0xFFF)) return -1;
    u64 base = rdmsr(MSR_APIC_BASE);
    if (base & APIC_BASE_X2) return -1;
    base &= ~0x000FFFFFFFFFF000ULL;
    base |= (physical & 0x000FFFFFFFFFF000ULL) | APIC_BASE_ENABLE;
    wrmsr(MSR_APIC_BASE, base);
    if ((read_register(APIC_ID) >> 24) != expected_id) return -1;
    write_register(APIC_LVT_TIMER, APIC_LVT_MASKED);
    write_register(APIC_LVT_THERMAL, APIC_LVT_MASKED);
    write_register(APIC_LVT_PERF, APIC_LVT_MASKED);
    write_register(APIC_LVT_LINT0, APIC_LVT_MASKED);
    write_register(APIC_LVT_LINT1, APIC_LVT_MASKED);
    write_register(APIC_LVT_ERROR, APIC_LVT_MASKED);
    write_register(APIC_SVR, APIC64_SPURIOUS_VECTOR | (1u << 8));
    return 0;
}

int apic64_ipi(u8 destination, u8 vector) {
    if (!apic) return -1;
    return icr_send((u32)vector & 0xFFu, destination & 0xFFu);
}

int apic64_send_init(u8 destination) {
    if (!apic) return -1;
    // INIT pulse: assert, then level-triggered deassert. QEMU treats (level=0,
    // trig=0) as another full INIT; (level=0, trig=1) is the clean deassert on both
    // QEMU and real hardware.
    if (icr_send(APIC_ICR_INIT | APIC_ICR_ASSERT, destination & 0xFFu))
        return -1;
    if (apic64_delay_ms(10)) return -1;
    return icr_send(APIC_ICR_INIT | APIC_ICR_LEVEL, destination & 0xFFu);
}

int apic64_send_sipi(u8 destination, u8 vector) {
    if (!apic) return -1;
    return icr_send(APIC_ICR_SIPI | (u32)vector, destination & 0xFFu);
}

int apic64_timer_start(u32 hz) {
    if (!apic || !hz || hz > 1000) return -1;
    write_register(APIC_TIMER_DIVIDE, 0x3);
    write_register(APIC_LVT_TIMER, APIC_LVT_MASKED | APIC64_TIMER_VECTOR);
    write_register(APIC_TIMER_INITIAL, 0xFFFFFFFFu);
    if (delay_10ms()) return -1;
    u32 elapsed = 0xFFFFFFFFu - read_register(APIC_TIMER_CURRENT);
    write_register(APIC_LVT_TIMER, APIC_LVT_MASKED | APIC64_TIMER_VECTOR);
    if (elapsed < 100) return -1;
    u64 per_second = (u64)elapsed * 100;
    u32 initial = (u32)(per_second / hz);
    if (!initial) return -1;
    write_register(APIC_TIMER_DIVIDE, 0x3);
    write_register(APIC_LVT_TIMER,
                   APIC64_TIMER_VECTOR | APIC_TIMER_PERIODIC);
    write_register(APIC_TIMER_INITIAL, initial);
    timer_initial = initial;
    return 0;
}

// Program this CPU's local APIC timer from the BSP calibration. Each CPU sees its
// own APIC at the same MMIO address, so the AP must run this itself; the BSP cannot
// write the AP's LVT.
int apic64_timer_enable(void) {
    if (!apic || !timer_initial) return -1;
    write_register(APIC_TIMER_DIVIDE, 0x3);
    write_register(APIC_LVT_TIMER,
                   APIC64_TIMER_VECTOR | APIC_TIMER_PERIODIC);
    write_register(APIC_TIMER_INITIAL, timer_initial);
    return 0;
}

void apic64_timer_mask(void) {
    if (!apic) return;
    write_register(APIC_LVT_TIMER, APIC_LVT_MASKED | APIC64_TIMER_VECTOR);
}

void apic64_eoi(void) {
    if (apic) write_register(APIC_EOI, 0);
}

u8 apic64_id(void) {
    return apic ? (u8)(read_register(APIC_ID) >> 24) : 0;
}

// Error Status Register: QEMU sets the no-target/invalid-destination
// bits here when an IPI cannot be delivered.
u32 apic64_esr(void) {
    if (!apic) return 0xFFFFFFFFu;
    u32 value = read_register(0x2F0);
    write_register(0x2F0, value);
    return value;
}
