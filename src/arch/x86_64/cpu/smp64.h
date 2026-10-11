#ifndef SMP64_H
#define SMP64_H

#include "types.h"

// The xAPIC destination id is one byte, so 16 CPUs is the practical ceiling
// for this path; past it the tree would need x2APIC.
#define SMP64_MAX 16
#define SMP64_TRAMP_BASE 0x8000
// SIPI vector is the 4 KiB page number of the trampoline (Intel SDM).
#define SMP64_SIPI_VECTOR (SMP64_TRAMP_BASE >> 12)
//
// AP bring-up progress flags: written by the AP trampoline, read by the
// BSP. They live in the trampoline page at 0x550-0x553. The AP writes
// these instead of the shared UART: at bring-up the BSP is using the
// UART at the same moment the AP starts.
//
#define SMP64_AP_FLAG_ENTRY   (SMP64_TRAMP_BASE + 0x550) // 'A' real mode
#define SMP64_AP_FLAG_PROT    (SMP64_TRAMP_BASE + 0x551) // 'B' protected
#define SMP64_AP_FLAG_LONG    (SMP64_TRAMP_BASE + 0x552) // 'C' long mode
#define SMP64_AP_FLAG_CENTRY  (SMP64_TRAMP_BASE + 0x553) // 'D' C entry
#define SMP64_IPI_ACK 0x41
#define SMP64_IPI_WORK 0x42
#define SMP64_IPI_TIMER 0x43
#define SMP64_IPI_TIMER_OFF 0x44
#define SMP64_IPI_USER 0x45
#define SMP64_IPI_TSS 0x46
#define SMP64_IPI_PARK 0x47
// A CPU told to look at its runnable set now: a parked AP takes a task
// pinned to it, and one already in ring 3 switches the way its tick would.
#define SMP64_IPI_RESCHED 0x48
// Test-only: parks every AP in the shared-state stress loop, so the allocator
// and the object table are entered by two CPUs at once on purpose.
#define SMP64_IPI_STRESS 0x49
#define SMP64_IPI_NET_RX 0x4A
// Drop every cached translation: another CPU rewrote page tables this
// one is executing from, and a local invlpg cannot reach it.
#define SMP64_IPI_TLBSHOT 0x4B
#define SMP64_IPI_FIRST 0x41
#define SMP64_IPI_LAST 0x4F
#define SMP64_CURRENT_NONE 0xFFFFFFFFu
#define SMP64_SYSCALL_STACK 32768
#define SMP64_SYSCALL_CANARY 0x4D49434853595343ULL
#define SMP64_SPIN_TURNS 20000
#define SMP64_BOOT_TIMEOUT_MS 1000

// Per-CPU syscall frame at GS base after SWAPGS. Offsets are baked
// into syscall.asm (SC_*); keep the field order stable.
struct smp64_syscall {
    u64 kernel_rsp;
    u64 rsp;
    u64 rdi;
    u64 rsi;
    u64 rdx;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 rip;
    u64 rflags;
    u64 rbx;
    u64 rbp;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    // The sigreturn path parks the interrupted rax, rcx, and r11 here,
    // because sysret can only return rcx as the rip and r11 as the flags
    // while a signal can interrupt user code between any two
    // instructions. Offsets are baked into syscall.asm (SC_SIG_*).
    u64 sigreturn_rax;
    u64 sigreturn_rcx;
    u64 sigreturn_r11;
    // Set when a park, exit, or exec switched the task context under the
    // syscall: the plain sysret return would fold rcx into the resume rip
    // and r11 into the flags, clobbering the resumed task's rcx/r11 even
    // though it never executed a syscall instruction itself. The exit path
    // answers with an iret resume that restores rax/rcx/r11 from the
    // context through the sigreturn slots above. Offset baked into
    // syscall.asm (SC_CTXRES).
    u64 ctx_resume;
};

int smp64_init(void);
int smp64_timer_tick(u64 cs, u64 rsp);
int smp64_syscall_ok(void);
int smp64_catch_ap_user(u64 number);
void smp64_syscall_prepare(void);
void smp64_gs_user(void);
void smp64_ipi_dispatch(u32 vector);
int smp64_tlb_shootdown(void);
u32 smp64_tlb_generation(void);
u32 smp64_tlb_done(u32 index);
void smp64_cow_arm(u32 index, u32 space, vaddr_t virtual);
void smp64_cow_disarm(void);
void smp64_set_current(u32 slot);
u32 smp64_running_slot(void);
void smp64_note_preempt(void);
struct smp64_syscall *smp64_syscall(void);
u32 smp64_cpu_index(void);
u32 smp64_cpu_count(void);
u8 smp64_bsp_apic_id(void);
u8 smp64_cpu_apic_id(u32 index);
int smp64_ipi_cpu(u32 index, u32 vector);
u32 smp64_ipi_ack(u32 index);
void smp64_clear_ipi_ack(u32 index);
u32 smp64_work_done(u32 index);
void smp64_clear_work_done(u32 index);
u32 smp64_ticks(u32 index);
void smp64_clear_ticks(u32 index);
u32 smp64_tr(u32 index);
void smp64_clear_tr(u32 index);
u32 smp64_cpu_current(u32 index);
u32 smp64_user_done(u32 index);
u32 smp64_user_irq(u32 index);
u32 smp64_preempts(u32 index);
void smp64_set_syscall_live(u32 index, u32 live);
int smp64_gs_is_bsp(void);
int smp64_sysstacks_ok(void);
int smp64_sysstack_ok_cpu(u32 index);
void smp64_spin_reset(void);
void smp64_spin_bsp(u32 turns);
u64 smp64_spin_count(void);
#define SMP64_STRESS_TURNS 32
#define SMP64_STRESS_HOLD 4
struct kernel_object;
#define SMP64_STRESS_ALLOC 0u
#define SMP64_STRESS_REFCOUNT 1u
#define SMP64_STRESS_SPAWN 2u
#define SMP64_STRESS_NET 3u
#define SMP64_STRESS_RESOURCE 4u
#define SMP64_STRESS_VECTOR 5u
#define SMP64_STRESS_DOMAIN 6u
#define SMP64_STRESS_MODULE 7u
#define SMP64_STRESS_COW 8u

void smp64_stress_reset(u32 turns, struct kernel_object *shared, u32 mode);
void smp64_net_storm_prepare(struct kernel_object *interface,
                             const u8 *frame, u32 length);
void smp64_driver_storm_prepare(struct kernel_object *device);
u64 smp64_stress_domains(void);
u64 smp64_stress_modules(void);
u64 smp64_stress_instances(void);
void smp64_stress_run(u32 turns);
void smp64_spawn_reset(u32 turns);
u64 smp64_spawn_slots(void);
u64 smp64_stress_detail_value(void);
u64 smp64_stress_pages(void);
u64 smp64_stress_objects(void);
u32 smp64_stress_failed(void);
u32 smp64_stress_done(u32 index);
int smp64_arm_user(u32 index, const u8 *stub, u32 size);
int smp64_pin_user(u32 index, const u8 *stub, u32 size, u32 *slot_out);
void smp64_disarm_user(u32 index);
void smp64_enter_task(u32 index, u32 slot);
int smp64_pick_pinned(u32 index);
int smp64_pick_next(u32 current);
int smp64_resched_cpu(u32 index);
void smp64_net_kick(u32 cpu);
u32 smp64_take_resched(void);
void smp64_enter_pinned(u32 index);
int smp64_pin_task(u32 index, const u8 *stub, u32 size, u32 *slot_out,
                   u64 **counter_out);
int smp64_host_start(void);
int smp64_host_note(u64 cs);

#endif
