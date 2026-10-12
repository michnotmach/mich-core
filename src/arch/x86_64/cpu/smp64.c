#include "smp64.h"
#include "spinlock.h"
#include "types.h"
#include "serial64.h"
#include "apic64.h"
#include "gdt64.h"
#include "idt64.h"
#include "acpi64.h"
#include "irq.h"
#include "scheduler.h"
#include "task.h"
#include "vm64.h"
#include "kernel64_internal.h"
#include "pmm.h"
#include "posix_fd.h"
#include "posix_pipe.h"
#include "net_rx.h"
#include "net_interface.h"
#include "vnic_benchmark.h"
#include "object.h"
#include "resource.h"
#include "driver.h"
#include "driver_supervisor.h"
#include "pci64.h"
#include "vector64.h"

// Trampoline chunks (smp_tramp.asm) placed by the BSP at SMP64_TRAMP_BASE: entry
// 0x000, overlay 0x500, GDTs 0x100, code 0x200/0x300/0x400. SIPI starts the AP at
// that page (vector = physical >> 12).
extern const u8 smp_tramp_gdt[];
extern const u32 smp_tramp_gdt_size;
extern const u8 smp_tramp_code16[];
extern const u32 smp_tramp_code16_size;
extern const u8 smp_tramp_code32[];
extern const u32 smp_tramp_code32_size;
extern const u8 smp_tramp_code64[];
extern const u32 smp_tramp_code64_size;
extern const u8 smp_tramp_entry[];
extern const u32 smp_tramp_entry_size;

#define SMP64_STATE_OFF 0
#define SMP64_STATE_BOOTING 2
#define SMP64_STATE_ONLINE 3
#define SMP64_STACK_SIZE 16384
#define MSR_EFER 0xC0000080ULL
#define MSR_STAR 0xC0000081ULL
#define MSR_LSTAR 0xC0000082ULL
#define MSR_FMASK 0xC0000084ULL
#define MSR_GS_BASE 0xC0000101ULL
#define MSR_KERNEL_GS_BASE 0xC0000102ULL
#define SMP64_USER_GETPID 16
#define SMP64_USER_STUB_AFTER 7

struct smp64_cpu {
    struct smp64_syscall sc;
    u32 active;
    u32 apic_id;
    u32 acpi_id;
    u32 index;
    volatile u32 state;
    volatile u32 ipi_ack;
    volatile u32 work_done;
    volatile u32 ticks;
    volatile u32 current;
    volatile u32 user_done;
    volatile u32 user_irq;
    volatile u32 preempts;
    volatile u32 tr;
    // When set, AP syscalls reach dispatch instead of the test catch.
    volatile u32 syscall_live;
    // Set by the reschedule IPI, consumed by the interrupt tail.
    volatile u32 resched;
    // Set by the shared-state stress when this CPU finishes its turns.
    volatile u32 stress_done;
    // A sender stamps the generation it wants; the target copies it back
    // once its caches are down, which tells an owed flush from a done one.
    volatile u32 tlb_gen;
    volatile u32 tlb_done;
};

struct smp64_stack {
    u64 canary;
    u8 bytes[SMP64_STACK_SIZE];
} __attribute__((aligned(16)));

struct smp64_sysstack {
    u64 canary;
    u64 reserved;
    u8 bytes[SMP64_SYSCALL_STACK];
} __attribute__((aligned(16)));

static struct smp64_cpu smp64_cpus[SMP64_MAX];
static struct smp64_stack smp64_stacks[SMP64_MAX];
static struct smp64_sysstack smp64_sysstacks[SMP64_MAX];
static u32 smp64_online;
static u32 smp64_tlb_generation_count;
static u8 smp64_bsp_id;
static struct smp64_cpu *smp64_cpu_by_apic[256];
static struct spinlock smp64_spin = SPINLOCK_INIT;
static volatile u64 smp64_spin_counter;
static volatile u64 smp64_stress_page_count;
static volatile u64 smp64_stress_object_count;
static volatile u64 smp64_stress_domain_count;
static volatile u64 smp64_stress_module_count;
static volatile u64 smp64_stress_instance_count;
static struct kernel_object *smp64_storm_device;
static volatile u32 smp64_stress_failure;
static u32 smp64_stress_turns;
static u32 smp64_stress_mode;
static struct kernel_object *smp64_stress_object;
static volatile u64 smp64_spawn_slot_count;
static volatile u64 smp64_stress_detail;
static struct kernel_object *smp64_net_storm_interface;
static const u8 *smp64_net_storm_frame;
static u32 smp64_net_storm_length;
static struct kernel_object *smp64_netbench_vnic[SMP64_MAX];
static u8 smp64_netbench_frame[SMP64_MAX][SMP64_NETBENCH_FRAME];
static volatile u64 smp64_netbench_own[SMP64_MAX];
static volatile u32 smp64_netbench_ready[SMP64_MAX];
static u32 smp64_netbench_packets;
static u32 smp64_netbench_size;
static u64 smp64_netbench_opened;
static u64 smp64_netbench_span;
static volatile u32 smp64_spawn_held[MAX_TASKS];
static u64 smp64_kernel_cr3;
static u64 smp64_kernel_cr4;
static u64 smp64_kernel_efer;
static u64 smp64_kernel_star;
static u64 smp64_kernel_lstar;
static u64 smp64_kernel_fmask;
static u64 smp64_user_rip;
static u64 smp64_user_rsp;
static u64 smp64_user_cr3;

extern void user64_enter(u64 rip, u64 rsp, u64 argument, u64 module_flags);

_Static_assert(__builtin_offsetof(struct smp64_syscall, rsp) == 8,
               "syscall.asm SC_RSP");
_Static_assert(__builtin_offsetof(struct smp64_syscall, r15) == 120,
               "syscall.asm SC_R15");
_Static_assert(
    __builtin_offsetof(struct smp64_syscall, sigreturn_rax) == 128,
    "syscall.asm SC_SIG_RAX");
_Static_assert(__builtin_offsetof(struct smp64_cpu, sc) == 0,
               "GS base is smp64_cpu");
_Static_assert(SMP64_MAX == GDT64_CPU_MAX, "TSS slots match SMP");

static void smp64_copy(u8 *dst, const u8 *src, u32 size) {
    for (u32 index = 0; index < size; index++)
        dst[index] = src[index];
}

static u64 smp64_rdmsr(u32 msr) {
    u32 low;
    u32 high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((u64)high << 32) | low;
}

static void smp64_wrmsr(u32 msr, u64 value) {
    __asm__ volatile("wrmsr" : : "c"(msr), "a"((u32)value),
                     "d"((u32)(value >> 32)) : "memory");
}

static struct smp64_cpu *smp64_this(void) {
    struct smp64_cpu *cpu = smp64_cpu_by_apic[apic64_id()];
    return cpu ? cpu : &smp64_cpus[0];
}

u32 smp64_cpu_index(void) {
    return smp64_this()->index;
}

void smp64_set_current(u32 slot) {
    smp64_this()->current = slot;
}

u32 smp64_running_slot(void) {
    struct smp64_cpu *cpu = smp64_this();
    // Every CPU answers from its own record. The shared global holds
    // whichever CPU switched last, which is this CPU's own slot only while
    // no other CPU has switched and this one has not recorded one yet.
    if (cpu->current != SMP64_CURRENT_NONE)
        return cpu->current;
    return current_task_slot;
}

void smp64_note_preempt(void) {
    __atomic_fetch_add(&smp64_this()->preempts, 1, __ATOMIC_RELEASE);
}

struct smp64_syscall *smp64_syscall(void) {
    return &smp64_this()->sc;
}

int smp64_syscall_ok(void) {
    return smp64_sysstacks[smp64_cpu_index()].canary == SMP64_SYSCALL_CANARY;
}

void smp64_syscall_prepare(void) {
    for (u32 index = 0; index < SMP64_MAX; index++) {
        smp64_sysstacks[index].canary = SMP64_SYSCALL_CANARY;
        smp64_cpus[index].sc.kernel_rsp =
            (u64)(uptr_t)&smp64_sysstacks[index].bytes[SMP64_SYSCALL_STACK];
    }
}

// Kernel: GS_BASE = pcpu, KERNEL_GS_BASE = 0. User: the reverse, so SWAPGS on
// syscall lands on this CPU's frame. Explicit MSRs, not SWAPGS, so it does not
// depend on the current GS.
static void smp64_gs_kernel(struct smp64_cpu *cpu) {
    u64 addr = (u64)(uptr_t)cpu;
    smp64_wrmsr(MSR_GS_BASE, addr);
    smp64_wrmsr(MSR_KERNEL_GS_BASE, 0);
}

void smp64_gs_user(void) {
    u64 addr = (u64)(uptr_t)smp64_this();
    smp64_wrmsr(MSR_GS_BASE, 0);
    smp64_wrmsr(MSR_KERNEL_GS_BASE, addr);
}

// Live AP userspace test: never fall through to BSP current_task_slot. Park on the
// kernel CR3 so the BSP can free the task's space.
int smp64_catch_ap_user(u64 number) {
    struct smp64_cpu *cpu = smp64_this();
    u64 rsp;
    u32 ds;
    if (cpu->index == 0 || cpu->current == SMP64_CURRENT_NONE)
        return 0;
    if (__atomic_load_n(&cpu->syscall_live, __ATOMIC_ACQUIRE))
        return 0;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp));
    u64 base = (u64)(uptr_t)smp64_sysstacks[cpu->index].bytes;
    u64 end = base + SMP64_SYSCALL_STACK;
    int ok = number == SMP64_USER_GETPID &&
             rsp > base && rsp <= end &&
             smp64_rdmsr(MSR_GS_BASE) == (u64)(uptr_t)cpu &&
             cpu->sc.rip == smp64_user_rip + SMP64_USER_STUB_AFTER;
    ds = GDT64_KERNEL_DS;
    __asm__ volatile("mov %0, %%ds; mov %0, %%es" : : "r"(ds));
    smp64_gs_kernel(cpu);
    vm64_activate(smp64_kernel_cr3);
    apic64_timer_mask();
    if (ok)
        __atomic_store_n(&cpu->user_done, 1, __ATOMIC_RELEASE);
    return 1;
}

static struct smp64_cpu *smp64_cpu(u32 index);
int smp64_pick_pinned(u32 index);

// IPI from hlt is same-privilege: the frame has no SS/RSP, so it cannot be
// rewritten into a user iret. EOI here because this path never returns through
// irq64_common.
static void smp64_ap_enter_user(struct smp64_cpu *cpu) {
    if (!cpu || cpu->current == SMP64_CURRENT_NONE) return;
    apic64_eoi();
    smp64_gs_user();
    vm64_activate(smp64_user_cr3);
    user64_enter(smp64_user_rip, smp64_user_rsp, 0, 0);
    for (;;)
        __asm__ volatile("cli; hlt" ::: "memory");
}

// The reschedule IPI from hlt is same-privilege: there is no user frame to
// rewrite, so this CPU enters a task pinned to it the way the host entry
// does. The pool is the authority; nothing here waits for an arm.
// The entry itself, for a slot this CPU has already decided to run. It
// never returns: the caller's context is the task's from here on, and the
// per-CPU user counters belong to the task that just took over.
void smp64_enter_task(u32 index, u32 slot) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    if (!cpu || slot >= MAX_TASKS) return;
    cpu->current = slot;
    cpu->user_done = 0;
    cpu->user_irq = 0;
    cpu->preempts = 0;
    cpu->syscall_live = 0;
    smp64_gs_user();
    vm64_activate(task_pool[slot].page_dir);
    user64_enter(task_contexts[slot].rip, task_contexts[slot].rsp,
                 task_contexts[slot].rdi, task_contexts[slot].rsi);
    for (;;)
        __asm__ volatile("cli; hlt" ::: "memory");
}

// Enter whatever this CPU has pinned and runnable. An interrupt that lands
// in ring 0 has no frame to rewrite, so this is how a parked AP starts a
// task; EOI here because the entry never returns through irq64_common.
void smp64_enter_pinned(u32 index) {
    int slot = smp64_pick_pinned(index);
    if (slot < 0) return;
    apic64_eoi();
    smp64_enter_task(index, (u32)slot);
}

// Runs on the secondary CPU in long mode after the trampoline, which still uses the
// bootloader PML4 at 0x70000: switch to kernel CR3 before any ioremap or NX access.
// ONLINE is stored after sti so an IPI cannot land with IF=0.
static void smp64_ap_entry(u32 expected_id) {
    const struct acpi_madt_info *madt = acpi64_madt();
    struct smp64_cpu *cpu = 0;
    int rc;
    *(volatile u8 *)(uptr_t)SMP64_AP_FLAG_CENTRY = 'D';
    *(volatile u32 *)(uptr_t)(SMP64_TRAMP_BASE + 0x554) = expected_id;
    *(volatile u32 *)(uptr_t)(SMP64_TRAMP_BASE + 0x55C) = 0xC0DEU;
    smp64_wrmsr(MSR_EFER, smp64_kernel_efer);
    smp64_wrmsr(MSR_STAR, smp64_kernel_star);
    smp64_wrmsr(MSR_LSTAR, smp64_kernel_lstar);
    smp64_wrmsr(MSR_FMASK, smp64_kernel_fmask);
    __asm__ volatile("mov %0, %%cr4" : : "r"(smp64_kernel_cr4) : "memory");
    __asm__ volatile("mov %0, %%cr3" : : "r"(smp64_kernel_cr3) : "memory");
    *(volatile u32 *)(uptr_t)(SMP64_TRAMP_BASE + 0x55C) = 0xC0DFU;
    for (u32 index = 0; index < SMP64_MAX; index++) {
        if (smp64_cpus[index].active &&
            smp64_cpus[index].apic_id == expected_id)
            cpu = &smp64_cpus[index];
    }
    rc = (!madt || !cpu) ? -2 :
         apic64_ap_start(madt->local_apic_address, expected_id);
    *(volatile u32 *)(uptr_t)(SMP64_TRAMP_BASE + 0x558) = (u32)rc;
    if (rc) {
        if (cpu) cpu->state = SMP64_STATE_OFF;
        for (;;)
            __asm__ volatile("cli; hlt" ::: "memory");
    }
    // Shared GDT, private TSS descriptor. LTR of the BSP selector #GPs (that TSS is
    // busy); this CPU's slot is still free. Reload GDTR first: the trampoline only
    // installed the 7-entry view.
    idt64_reload();
    gdt64_load_cpu(cpu->index);
    smp64_cpu_by_apic[expected_id] = cpu;
    smp64_gs_kernel(cpu);
    __asm__ volatile("sti" ::: "memory");
    __atomic_thread_fence(__ATOMIC_RELEASE);
    cpu->state = SMP64_STATE_ONLINE;
    for (;;)
        __asm__ volatile("hlt" ::: "memory");
}

static void smp64_install_trampoline(void) {
    u8 *page = (u8 *)(uptr_t)SMP64_TRAMP_BASE;
    for (u32 index = 0; index < 0x1000; index++)
        page[index] = 0;
    smp64_copy(page + 0x100, smp_tramp_gdt, smp_tramp_gdt_size);
    smp64_copy(page + 0x200, smp_tramp_code16, smp_tramp_code16_size);
    smp64_copy(page + 0x300, smp_tramp_code32, smp_tramp_code32_size);
    smp64_copy(page + 0x400, smp_tramp_code64, smp_tramp_code64_size);
    smp64_copy(page + 0x000, smp_tramp_entry, smp_tramp_entry_size);
}

static void smp64_fill_overlay(struct smp64_cpu *cpu, u64 stack_top) {
    *(volatile u64 *)(uptr_t)(SMP64_TRAMP_BASE + 0x500) = gdt64_base();
    *(volatile u32 *)(uptr_t)(SMP64_TRAMP_BASE + 0x508) = cpu->apic_id;
    *(volatile u64 *)(uptr_t)(SMP64_TRAMP_BASE + 0x510) = stack_top;
    *(volatile u64 *)(uptr_t)(SMP64_TRAMP_BASE + 0x518) =
        (u64)(uptr_t)smp64_ap_entry;
}

static int smp64_start_cpu(struct smp64_cpu *cpu, u64 stack_top) {
    volatile u8 *page = (volatile u8 *)(uptr_t)SMP64_TRAMP_BASE;
    for (u32 index = 0; index < 0x40; index++)
        page[0x500 + index] = 0;
    cpu->state = SMP64_STATE_BOOTING;
    cpu->ipi_ack = 0;
    cpu->work_done = 0;
    smp64_fill_overlay(cpu, stack_top);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    if (apic64_send_init(cpu->apic_id)) return -1;
    smp64_install_trampoline();
    smp64_fill_overlay(cpu, stack_top);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    // No serial in the INIT/SIPI window: the AP and BSP share COM1.
    apic64_delay_ms(10);
    if (apic64_send_sipi(cpu->apic_id, SMP64_SIPI_VECTOR)) return -1;
    apic64_delay_ms(10);
    if (apic64_send_sipi(cpu->apic_id, SMP64_SIPI_VECTOR)) return -1;
    u32 deadline = SMP64_BOOT_TIMEOUT_MS / 10;
    u32 state = SMP64_STATE_BOOTING;
    while (deadline--) {
        state = __atomic_load_n(&cpu->state, __ATOMIC_ACQUIRE);
        if (state == SMP64_STATE_ONLINE || state == SMP64_STATE_OFF)
            break;
        apic64_delay_ms(10);
    }
    return (state == SMP64_STATE_ONLINE) ? 0 : -1;
}

int smp64_init(void) {
    irq_state_t irq_state = irq_save();
    const struct acpi_madt_info *madt = acpi64_madt();
    if (!madt) {
        irq_restore(irq_state);
        return -1;
    }
    __asm__ volatile("mov %%cr3, %0" : "=r"(smp64_kernel_cr3));
    __asm__ volatile("mov %%cr4, %0" : "=r"(smp64_kernel_cr4));
    smp64_kernel_efer = smp64_rdmsr((u32)MSR_EFER);
    smp64_kernel_star = smp64_rdmsr((u32)MSR_STAR);
    smp64_kernel_lstar = smp64_rdmsr((u32)MSR_LSTAR);
    smp64_kernel_fmask = smp64_rdmsr((u32)MSR_FMASK);
    smp64_bsp_id = apic64_id();
    smp64_cpus[0].active = 1;
    smp64_cpus[0].apic_id = smp64_bsp_id;
    smp64_cpus[0].index = 0;
    smp64_cpus[0].state = SMP64_STATE_ONLINE;
    // The BSP runs the idle task before its first switch, so its record
    // starts at that slot; the first switch replaces it. Secondary CPUs
    // start at NONE and only record a slot once they pick one.
    smp64_cpus[0].current = 0;
    smp64_cpu_by_apic[smp64_bsp_id] = &smp64_cpus[0];
    smp64_online = 1;
    smp64_gs_kernel(&smp64_cpus[0]);
    if (madt->enabled_cpus < 2) {
        serial64_write("Mich x86_64: SMP disabled (single CPU)\n");
        irq_restore(irq_state);
        return 0;
    }
    serial64_write("Mich x86_64: SMP MADT enumeration pass\n");
    for (u32 index = 0; index < SMP64_MAX; index++)
        smp64_stacks[index].canary = 0x4D494348534D5031ULL;
    serial64_write("Mich x86_64: SMP per-CPU storage pass\n");
    smp64_install_trampoline();
    u32 started = 1;
    for (u32 index = 0;
         index < madt->cpu_count && started < SMP64_MAX; index++) {
        const struct acpi_cpu_info *info = &madt->cpus[index];
        if (info->apic_id == smp64_bsp_id) continue;
        struct smp64_cpu *cpu = &smp64_cpus[started];
        cpu->active = 1;
        cpu->apic_id = info->apic_id;
        cpu->acpi_id = info->acpi_id;
        cpu->index = started;
        cpu->current = SMP64_CURRENT_NONE;
        cpu->state = SMP64_STATE_OFF;
        u64 stack_top =
            (u64)(uptr_t)&smp64_stacks[started].bytes[SMP64_STACK_SIZE];
        stack_top &= ~0xFULL;
        if (smp64_start_cpu(cpu, stack_top)) {
            serial64_write("Mich x86_64: SMP AP bring-up failed\n");
            serial64_write("Mich x86_64: continuing as single CPU\n");
            cpu->active = 0;
            cpu->state = SMP64_STATE_OFF;
            smp64_online = 1;
            irq_restore(irq_state);
            return 0;
        }
        smp64_online++;
        started++;
    }
    if (started < 2) {
        serial64_write("Mich x86_64: SMP AP bring-up failed\n");
        serial64_write("Mich x86_64: continuing as single CPU\n");
        irq_restore(irq_state);
        return 0;
    }
    serial64_write("Mich x86_64: SMP AP bring-up pass (");
    serial64_hex(smp64_online);
    serial64_write(" cpus online)\n");
    irq_restore(irq_state);
    return 0;
}

static struct smp64_cpu *smp64_cpu(u32 index) {
    if (index >= smp64_online || !smp64_cpus[index].active)
        return 0;
    return &smp64_cpus[index];
}

u8 smp64_cpu_apic_id(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? (u8)cpu->apic_id : 0;
}

static u32 smp64_cow_space[SMP64_MAX];
static vaddr_t smp64_cow_virtual;

void smp64_cow_arm(u32 index, u32 space, vaddr_t virtual) {
    if (index < SMP64_MAX) smp64_cow_space[index] = space;
    smp64_cow_virtual = virtual;
}

void smp64_cow_disarm(void) {
    for (u32 index = 0; index < SMP64_MAX; index++) smp64_cow_space[index] = 0;
}

u32 smp64_tlb_generation(void) {
    return smp64_tlb_generation_count;
}

u32 smp64_tlb_done(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? __atomic_load_n(&cpu->tlb_done, __ATOMIC_ACQUIRE) : 0;
}

static void smp64_tlb_flush_local(void) {
    u64 root;
    __asm__ volatile("mov %%cr3, %0" : "=r"(root));
    __asm__ volatile("mov %0, %%cr3" : : "r"(root) : "memory");
}

// Broadcast outside every klock. A CPU spinning on a klock has interrupts
// off, so a sender that waited while holding one would wait for an ack from
// a CPU that cannot see the request: the callers flush after they unlock.
int smp64_tlb_shootdown(void) {
    struct smp64_cpu *self = smp64_this();
    u32 generation = ++smp64_tlb_generation_count;
    u32 targets = 0;
    for (u32 index = 0; index < smp64_online; index++) {
        struct smp64_cpu *cpu = smp64_cpu(index);
        if (!cpu || cpu == self) continue;
        __atomic_store_n(&cpu->tlb_gen, generation, __ATOMIC_RELEASE);
        if (smp64_ipi_cpu(index, SMP64_IPI_TLBSHOT)) return -1;
        targets++;
    }
    smp64_tlb_flush_local();
    if (!targets) return 0;
    for (u32 index = 0; index < smp64_online; index++) {
        struct smp64_cpu *cpu = smp64_cpu(index);
        if (!cpu || cpu == self) continue;
        while (__atomic_load_n(&cpu->tlb_done, __ATOMIC_ACQUIRE) < generation)
            __builtin_ia32_pause();
    }
    return 0;
}

int smp64_ipi_cpu(u32 index, u32 vector) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    if (!cpu) return -1;
    return apic64_ipi((u8)cpu->apic_id, (u8)vector);
}

// Wake a CPU up to a task it owns. A CPU kicking itself has nothing to do.
// The mailbox kick: a frame posted for another CPU cannot wait for that
// CPU's next tick if the driver is polling in a tight loop, so the post
// breaks it out of hlt the way a wake does.
void smp64_net_kick(u32 cpu) {
    struct smp64_cpu *target = smp64_cpu(cpu);
    if (!target || target->index == smp64_this()->index) return;
    smp64_ipi_cpu(cpu, SMP64_IPI_NET_RX);
}

int smp64_resched_cpu(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    if (!cpu) return -1;
    if (cpu->index == smp64_this()->index) return 0;
    return smp64_ipi_cpu(index, SMP64_IPI_RESCHED);
}

u32 smp64_take_resched(void) {
    struct smp64_cpu *cpu = smp64_this();
    u32 pending = cpu->resched;
    cpu->resched = 0;
    return pending;
}

u32 smp64_ipi_ack(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? __atomic_load_n(&cpu->ipi_ack, __ATOMIC_ACQUIRE) : 0;
}

void smp64_clear_ipi_ack(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    if (cpu) cpu->ipi_ack = 0;
}

u32 smp64_work_done(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? __atomic_load_n(&cpu->work_done, __ATOMIC_ACQUIRE) : 0;
}

void smp64_clear_work_done(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    if (cpu) cpu->work_done = 0;
}

u32 smp64_ticks(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? __atomic_load_n(&cpu->ticks, __ATOMIC_ACQUIRE) : 0;
}

void smp64_clear_ticks(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    if (cpu) cpu->ticks = 0;
}

u32 smp64_tr(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? __atomic_load_n(&cpu->tr, __ATOMIC_ACQUIRE) : 0;
}

void smp64_clear_tr(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    if (cpu) cpu->tr = 0;
}

u32 smp64_cpu_current(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? cpu->current : SMP64_CURRENT_NONE;
}

u32 smp64_user_done(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? __atomic_load_n(&cpu->user_done, __ATOMIC_ACQUIRE) : 0;
}

u32 smp64_user_irq(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? __atomic_load_n(&cpu->user_irq, __ATOMIC_ACQUIRE) : 0;
}

u32 smp64_preempts(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? __atomic_load_n(&cpu->preempts, __ATOMIC_ACQUIRE) : 0;
}

void smp64_set_syscall_live(u32 index, u32 live) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    if (cpu)
        __atomic_store_n(&cpu->syscall_live, live, __ATOMIC_RELEASE);
}

int smp64_gs_is_bsp(void) {
    return smp64_rdmsr(MSR_GS_BASE) == (u64)(uptr_t)&smp64_cpus[0];
}

int smp64_sysstack_ok_cpu(u32 index) {
    if (index >= smp64_online) return 0;
    return smp64_sysstacks[index].canary == SMP64_SYSCALL_CANARY;
}

int smp64_sysstacks_ok(void) {
    if (!smp64_gs_is_bsp()) return 0;
    for (u32 index = 0; index < smp64_online; index++) {
        u64 rsp = smp64_cpus[index].sc.kernel_rsp;
        u64 base = (u64)(uptr_t)smp64_sysstacks[index].bytes;
        u64 end = base + SMP64_SYSCALL_STACK;
        if (smp64_sysstacks[index].canary != SMP64_SYSCALL_CANARY)
            return 0;
        if (rsp <= base || rsp > end) return 0;
        for (u32 other = 0; other < index; other++)
            if (smp64_cpus[other].sc.kernel_rsp == rsp) return 0;
    }
    return 1;
}

void smp64_spin_reset(void) {
    smp64_spin_counter = 0;
}

void smp64_spin_bsp(u32 turns) {
    for (u32 turn = 0; turn < turns; turn++) {
        spin_lock(&smp64_spin);
        smp64_spin_counter++;
        spin_unlock(&smp64_spin);
    }
}

u64 smp64_spin_count(void) {
    return smp64_spin_counter;
}

// The two-CPU hammer the allocator and refcount tests share. Four pages are
// held at once, so a page handed out to both CPUs at the same time is caught
// here and not by the free count alone; the shared object takes one retain
// and one release per turn, so a lost refcount update ends the storm with a
// count that cannot come from the arithmetic.
// One storm turn runs the whole spawn sequence: a pool slot, a pipe with
// both ends in the descriptor table, then the teardown. The claim word is
// what makes the one failure silence would hide visible, a slot handed to
// two CPUs at once: the loser of that race sets the failure flag.
static void smp64_spawn_turn(void) {
    struct task *task = task_alloc_slot();
    if (!task) {
        __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
        return;
    }
    u32 slot = (u32)(task - task_pool);
    if (slot >= (u32)MAX_TASKS ||
        __sync_lock_test_and_set(&smp64_spawn_held[slot], 1u)) {
        __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
        task_free_slot(task);
        return;
    }
    int created = posix_pipe_create();
    if (created < 0 ||
        posix_fd_install_pipe(task, (u32)created, POSIX_PIPE_END_READ,
                              POSIX_FD_ACCESS_READ) < 0 ||
        posix_fd_install_pipe(task, (u32)created, POSIX_PIPE_END_WRITE,
                              POSIX_FD_ACCESS_WRITE) < 0)
        __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
    posix_fd_close_all(task);
    __atomic_store_n(&smp64_spawn_held[slot], 0u, __ATOMIC_RELEASE);
    task_free_slot(task);
    __atomic_fetch_add(&smp64_spawn_slot_count, 1, __ATOMIC_RELAXED);
}

static void smp64_stress_fail(u64 code, u64 detail);

static const char *const smp64_module_names[SMP64_MAX] = {
    "smpmod00", "smpmod01", "smpmod02", "smpmod03",
    "smpmod04", "smpmod05", "smpmod06", "smpmod07",
    "smpmod08", "smpmod09", "smpmod10", "smpmod11",
    "smpmod12", "smpmod13", "smpmod14", "smpmod15"
};

static int smp64_driver_start(struct driver_instance *instance) {
    return instance ? 0 : -1;
}

static void smp64_domain_turn(u32 turn) {
    u32 cpu = (u32)scheduler_cpu_id();
    u32 count = pci64_count();
    struct kernel_object *device = smp64_storm_device;
    if (count > 1)
        device = pci64_object((cpu + turn) % count);
    struct driver_domain_manifest manifest;
    manifest.name = "smpstorm";
    manifest.capabilities = 0;
    manifest.restart_policy = DRIVER_RESTART_NEVER;
    manifest.max_restarts = 0;
    manifest.backoff_ticks = 0;
    manifest.image_id = 0;
    manifest.reset_policy = DRIVER_RESET_NONE;
    manifest.weight = 0;
    manifest.argument = 0;
    struct driver_domain *domain = driver_domain_create(&manifest, device);
    if (!domain) return;
    if (!domain->id)
        smp64_stress_fail(0x31, 0);
    driver_domain_destroy(domain);
    __atomic_fetch_add(&smp64_stress_domain_count, 1, __ATOMIC_RELAXED);
}

static void smp64_module_turn(u32 turn) {
    u32 cpu = (u32)scheduler_cpu_id();
    struct driver_descriptor descriptor;
    descriptor.name = smp64_module_names[cpu % SMP64_MAX];
    descriptor.abi_version = DRIVER_ABI_VERSION;
    descriptor.flags = 0;
    descriptor.probe = 0;
    descriptor.start = smp64_driver_start;
    descriptor.stop = 0;
    int module = driver_register(&descriptor);
    if (module <= 0) {
        smp64_stress_fail(0x41, (u64)driver_module_count());
        return;
    }
    u32 count = pci64_count();
    struct driver_instance *instance = 0;
    if (count)
        instance = driver_bind(module, pci64_object((cpu + turn) % count));
    if (instance) {
        __atomic_fetch_add(&smp64_stress_instance_count, 1, __ATOMIC_RELAXED);
        driver_unbind(instance);
    }
    __atomic_fetch_add(&smp64_stress_module_count, 1, __ATOMIC_RELAXED);
    if (driver_unregister(module))
        smp64_stress_fail(0x42, (u64)driver_module_count());
}

static void smp64_stress_fail(u64 code, u64 detail) {
    u64 expected = 0;
    __atomic_compare_exchange_n(&smp64_stress_failure, &expected, code, 0,
                                __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    if (!expected)
        __atomic_store_n(&smp64_stress_detail, detail, __ATOMIC_RELEASE);
}

static void smp64_resource_turn(u32 turn) {
    u32 cpu = (u32)scheduler_cpu_id();
    paddr_t physical = 0xF0000000u + (paddr_t)cpu * 0x1000;
    struct kernel_object *mmio =
        mmio_resource_create(physical, 0x1000, MMIO_CACHE_UC);
    struct kernel_object *irq = irq_resource_create_kind(
        IRQ_CONTROLLER_MSI, 1, 40, IRQ_TRIGGER_EDGE, IRQ_POLARITY_HIGH);
    struct kernel_object *page = page_resource_create();
    const struct mmio_resource *mmio_info = mmio_resource_get(mmio);
    const struct irq_resource *irq_info = irq_resource_get(irq);
    struct page_resource *page_info = page_resource_get(page);
    // The address is the CPU's own, so a slot handed to two CPUs at once
    // shows up here as a foreign address rather than as a silent overwrite.
    if (!mmio || !mmio_info)
        smp64_stress_fail(0x11, ((u64)turn << 32) |
                          (u64)resource_active_count(KOBJECT_MMIO));
    else if (mmio_info->physical != physical)
        smp64_stress_fail(0x12, mmio_info->physical);
    if (!irq || !irq_info)
        smp64_stress_fail(0x13, ((u64)turn << 32) |
                          (u64)resource_active_count(KOBJECT_IRQ));
    else if (irq_info->controller != IRQ_CONTROLLER_MSI)
        smp64_stress_fail(0x14, irq_info->controller);
    if (!page || !page_info)
        smp64_stress_fail(0x15, ((u64)turn << 32) |
                          (u64)resource_active_count(KOBJECT_PAGE));
    else if (page_info->pages != 1)
        smp64_stress_fail(0x16, page_info->pages);
    if (page) object_release(page);
    if (irq) object_release(irq);
    if (mmio) object_release(mmio);
}

static void smp64_vector_turn(void) {
    u32 cpu = (u32)scheduler_cpu_id();
    uptr_t token = 0x1000u + (uptr_t)cpu;
    int vector = vector64_allocate(token);
    if (vector < 0 || vector64_owner((u8)vector) != token ||
        vector64_release((u8)vector, token)) {
        smp64_stress_fail(0x21, (u64)vector64_available());
        return;
    }
    u8 group[4];
    if (vector64_allocate_group(token, 4, group)) {
        smp64_stress_fail(0x22, (u64)vector64_available());
        return;
    }
    for (u32 index = 0; index < 4; index++)
        if (vector64_owner(group[index]) != token)
            __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
    if (vector64_release_group(group, 4, token))
        __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
}

// One turn per CPU: after the first fault the page is private, so the
// storm arms a single turn and every CPU has to win its own copy.
static void smp64_cow_turn(void) {
    struct smp64_cpu *cpu = smp64_this();
    u32 space = cpu ? smp64_cow_space[cpu->index] : 0;
    if (!space || vm64_handle_cow(space, smp64_cow_virtual))
        __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
}

// Each CPU drives the VNIC it was armed with, so the streams share no ring,
// no packet pool, and no frame buffer: a shared one is what the aggregate
// would otherwise end up measuring.
static void smp64_netbench_turn(void) {
    struct smp64_cpu *cpu = smp64_this();
    u32 index = cpu ? cpu->index : 0;
    struct kernel_object *vnic = smp64_netbench_vnic[index];
    u64 cycles = 0;
    if (!vnic ||
        vnic_bench64_batch(vnic, VNIC_BENCH64_ECHO, smp64_netbench_size,
                           smp64_netbench_packets,
                           smp64_netbench_frame[index], &cycles)) {
        __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&smp64_netbench_own[index], cycles, __ATOMIC_RELEASE);
    __atomic_store_n(&smp64_netbench_ready[index], 1, __ATOMIC_RELEASE);
}

void smp64_stress_run(u32 turns) {
    for (u32 turn = 0; turn < turns; turn++) {
        paddr_t held[SMP64_STRESS_HOLD];
        if (smp64_stress_mode == SMP64_STRESS_SPAWN) {
            smp64_spawn_turn();
            continue;
        }
        if (smp64_stress_mode == SMP64_STRESS_RESOURCE) {
            smp64_resource_turn(turn);
            continue;
        }
        if (smp64_stress_mode == SMP64_STRESS_DOMAIN) {
            smp64_domain_turn(turn);
            continue;
        }
        if (smp64_stress_mode == SMP64_STRESS_MODULE) {
            smp64_module_turn(turn);
            continue;
        }
        if (smp64_stress_mode == SMP64_STRESS_COW) {
            smp64_cow_turn();
            continue;
        }
        if (smp64_stress_mode == SMP64_STRESS_NETBENCH) {
            smp64_netbench_turn();
            continue;
        }
        if (smp64_stress_mode == SMP64_STRESS_VECTOR) {
            smp64_vector_turn();
            continue;
        }
        if (smp64_stress_mode == SMP64_STRESS_NET) {
            if (net_interface_receive_frame(smp64_net_storm_interface,
                                            smp64_net_storm_frame,
                                            smp64_net_storm_length,
                                            timer_ticks))
                __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
            continue;
        }
        for (u32 slot = 0; slot < SMP64_STRESS_HOLD; slot++) {
            held[slot] = pmm_alloc_page();
            if (!held[slot]) {
                __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
                return;
            }
            for (u32 other = 0; other < slot; other++)
                if (held[other] == held[slot]) {
                    __atomic_store_n(&smp64_stress_failure, 1,
                                     __ATOMIC_RELEASE);
                    return;
                }
        }
        for (u32 slot = 0; slot < SMP64_STRESS_HOLD; slot++)
            pmm_free_page(held[slot]);
        __atomic_fetch_add(&smp64_stress_page_count, SMP64_STRESS_HOLD,
                           __ATOMIC_RELAXED);
        if (!smp64_stress_object) continue;
        if (object_retain(smp64_stress_object)) {
            __atomic_store_n(&smp64_stress_failure, 1, __ATOMIC_RELEASE);
            return;
        }
        object_release(smp64_stress_object);
        __atomic_fetch_add(&smp64_stress_object_count, 1, __ATOMIC_RELAXED);
    }
}

void smp64_netbench_reset(void) {
    for (u32 index = 0; index < SMP64_MAX; index++) {
        smp64_netbench_vnic[index] = 0;
        smp64_netbench_own[index] = 0;
        smp64_netbench_ready[index] = 0;
    }
    smp64_netbench_packets = 0;
    smp64_netbench_size = 0;
    smp64_netbench_opened = 0;
    smp64_netbench_span = 0;
}

int smp64_netbench_arm(u32 index, struct kernel_object *vnic) {
    if (index >= SMP64_MAX || !vnic) return -1;
    smp64_netbench_vnic[index] = vnic;
    return 0;
}

int smp64_netbench_begin(u32 cpus, u32 packets, u32 frame_size) {
    u32 online = smp64_cpu_count();
    if (!cpus || cpus > online || cpus > SMP64_MAX || !packets ||
        !frame_size || frame_size > SMP64_NETBENCH_FRAME)
        return -1;
    for (u32 index = 0; index < SMP64_MAX; index++) {
        smp64_netbench_own[index] = 0;
        smp64_netbench_ready[index] = 0;
        if (index < cpus && !smp64_netbench_vnic[index]) return -1;
    }
    smp64_netbench_packets = packets;
    smp64_netbench_size = frame_size;
    smp64_netbench_span = 0;
    smp64_stress_reset(1, 0, SMP64_STRESS_NETBENCH);
    // Stamped before the kicks, not after: an AP is running the moment its
    // IPI lands, and a window opened later than that can be shorter than
    // the stream it is supposed to bound.
    smp64_netbench_opened = apic64_tsc_now();
    for (u32 index = 1; index < cpus; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) return -1;
    return 0;
}

void smp64_netbench_finish(void) {
    smp64_netbench_span = apic64_tsc_now() - smp64_netbench_opened;
}

u64 smp64_netbench_window(void) {
    return smp64_netbench_span;
}

u64 smp64_netbench_cycles(u32 index) {
    return index < SMP64_MAX ? smp64_netbench_own[index] : 0;
}

u32 smp64_netbench_done(u32 index) {
    return index < SMP64_MAX ? smp64_netbench_ready[index] : 0;
}

void smp64_stress_reset(u32 turns, struct kernel_object *shared, u32 mode) {
    smp64_stress_turns = turns;
    smp64_stress_mode = mode;
    smp64_stress_object = shared;
    smp64_stress_page_count = 0;
    smp64_stress_object_count = 0;
    smp64_stress_domain_count = 0;
    smp64_stress_module_count = 0;
    smp64_stress_instance_count = 0;
    smp64_stress_failure = 0;
    smp64_stress_detail = 0;
    for (u32 index = 0; index < SMP64_MAX; index++)
        smp64_cpus[index].stress_done = 0;
}

void smp64_driver_storm_prepare(struct kernel_object *device) {
    smp64_storm_device = device;
}

u64 smp64_stress_domains(void) {
    return smp64_stress_domain_count;
}

u64 smp64_stress_modules(void) {
    return smp64_stress_module_count;
}

u64 smp64_stress_instances(void) {
    return smp64_stress_instance_count;
}

void smp64_net_storm_prepare(struct kernel_object *interface,
                             const u8 *frame, u32 length) {
    smp64_net_storm_interface = interface;
    smp64_net_storm_frame = frame;
    smp64_net_storm_length = length;
}

void smp64_spawn_reset(u32 turns) {
    smp64_stress_reset(turns, 0, SMP64_STRESS_SPAWN);
    smp64_spawn_slot_count = 0;
    for (u32 slot = 0; slot < MAX_TASKS; slot++) smp64_spawn_held[slot] = 0;
}

u64 smp64_stress_detail_value(void) {
    return __atomic_load_n(&smp64_stress_detail, __ATOMIC_RELAXED);
}

u64 smp64_spawn_slots(void) {
    return smp64_spawn_slot_count;
}

u64 smp64_stress_pages(void) {
    return smp64_stress_page_count;
}

u64 smp64_stress_objects(void) {
    return smp64_stress_object_count;
}

u32 smp64_stress_failed(void) {
    return smp64_stress_failure;
}

u32 smp64_stress_done(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    return cpu ? cpu->stress_done : 0;
}

// Dedicated AP user slot, never init64-two. Stub bytes come from the caller (tests
// pass fixtures, host_start passes the idle spin). pin maps the task; arm also makes
// it this CPU's current for IPI_USER.
static int smp64_pin_stub(u32 index, const u8 *stub, u32 size, u32 *slot_out,
                          paddr_t *stack_out) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    struct task *task;
    struct task_context64 *context;
    u32 slot;
    u32 space;
    paddr_t code;
    paddr_t stack;
    u8 *bytes;
    if (!cpu || !stub || !size || size > 4096 || !slot_out) return -1;
    task = task_alloc_slot();
    if (!task) return -1;
    slot = (u32)(task - task_pool);
    context = &task_contexts[slot];
    if (vm64_create_space(&space)) {
        task_free_slot(task);
        return -1;
    }
    context->vm_space = space;
    context->vm_valid = 1;
    code = vm64_alloc_page();
    stack = vm64_alloc_page();
    if (!code || !stack) {
        if (code) vm64_free_page(code);
        if (stack) vm64_free_page(stack);
        task_free_slot(task);
        return -1;
    }
    bytes = (u8 *)(uptr_t)code;
    for (u32 byte = 0; byte < 4096; byte++) bytes[byte] = 0;
    for (u32 byte = 0; byte < size; byte++) bytes[byte] = stub[byte];
    if (vm64_map(space, VM64_PROGRAM_BASE, code, 0, 1)) {
        vm64_free_page(code);
        vm64_free_page(stack);
        task_free_slot(task);
        return -1;
    }
    if (vm64_map(space, VM64_STACK_TOP - 4096, stack, 1, 0)) {
        vm64_free_page(stack);
        task_free_slot(task);
        return -1;
    }
    task->ring = 3;
    task->page_dir = vm64_root(space);
    task->parent_id = 0;
    task_cpu_claim(task, (int)cpu->index);
    task_set_name(task, "ap-user");
    context->rflags = USER_EFLAGS;
    context->rip = VM64_PROGRAM_BASE;
    context->rsp = VM64_STACK_TOP;
    if (stack_out) *stack_out = stack;
    *slot_out = slot;
    return 0;
}

int smp64_pin_user(u32 index, const u8 *stub, u32 size, u32 *slot_out) {
    return smp64_pin_stub(index, stub, size, slot_out, 0);
}

// A task the CPU picks up on its own, with no arm and no handshake. The
// stub counts its turns in the stack page, the writable one, and the
// kernel reads that count through the physical address handed back here.
int smp64_pin_task(u32 index, const u8 *stub, u32 size, u32 *slot_out,
                   u64 **counter_out) {
    paddr_t stack;
    if (!counter_out) return -1;
    if (smp64_pin_stub(index, stub, size, slot_out, &stack)) return -1;
    *counter_out = (u64 *)(uptr_t)(stack + 4096u - 8u);
    return 0;
}

int smp64_arm_user(u32 index, const u8 *stub, u32 size) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    struct task_context64 *context;
    u32 slot;
    if (!cpu) return -1;
    if (smp64_pin_user(index, stub, size, &slot)) return -1;
    context = &task_contexts[slot];
    smp64_user_rip = VM64_PROGRAM_BASE;
    smp64_user_rsp = VM64_STACK_TOP;
    smp64_user_cr3 = task_pool[slot].page_dir;
    // Cleared so a later AP timer save must refill them from the frame.
    context->rip = 0;
    context->rsp = 0;
    cpu->current = slot;
    cpu->user_done = 0;
    cpu->user_irq = 0;
    cpu->preempts = 0;
    cpu->syscall_live = 0;
    return 0;
}

// A task this CPU may run: pinned to it and runnable. The scan is task.c's,
// under the pool lock, so a pinned task cannot be freed under it.
static int smp64_pick_owned(u32 index, int current) {
    return task_pick_pinned((int)index, current);
}

// Only tasks already on this CPU. Does not steal TASK_CPU_NONE (init64-two).
int smp64_pick_next(u32 current) {
    int next;
    if (current >= MAX_TASKS) return -1;
    next = smp64_pick_owned(smp64_this()->index, (int)current);
    return next < 0 ? (int)current : next;
}

int smp64_pick_pinned(u32 index) {
    return smp64_pick_owned(index, 0);
}

void smp64_disarm_user(u32 index) {
    struct smp64_cpu *cpu = smp64_cpu(index);
    u32 slot;
    if (!cpu || cpu->current == SMP64_CURRENT_NONE) return;
    slot = cpu->current;
    cpu->syscall_live = 0;
    cpu->current = SMP64_CURRENT_NONE;
    if (slot < MAX_TASKS)
        task_free_slot(&task_pool[slot]);
}

// jmp $ - AP host idle in ring3. Timer stays masked: TCG timeslice vs the 12s
// smoke if the AP runs 100 Hz.
static const u8 smp64_host_spin[] = { 0xEB, 0xFE };
static u32 smp64_host_noted;

int smp64_host_start(void) {
    u32 slot;
    if (smp64_online < 2) return 0;
    if (smp64_arm_user(1, smp64_host_spin, sizeof(smp64_host_spin)))
        return -1;
    slot = smp64_cpus[1].current;
    if (slot < MAX_TASKS) {
        task_set_name(&task_pool[slot], "ap-idle");
        // Lowest priority like the BSP idle: this host spin never blocks, so the
        // scheduler must prefer any real runnable task.
        task_pool[slot].is_idle = 1;
    }
    __atomic_thread_fence(__ATOMIC_RELEASE);
    if (smp64_ipi_cpu(1, SMP64_IPI_USER)) {
        smp64_disarm_user(1);
        return -1;
    }
    return 0;
}

int smp64_host_note(u64 cs) {
    if (smp64_host_noted || smp64_online < 2) return 0;
    if ((cs & 3) != 3) return 0;
    if (smp64_cpus[1].current == SMP64_CURRENT_NONE) return 0;
    smp64_host_noted = 1;
    return 1;
}

int smp64_timer_tick(u64 cs, u64 rsp) {
    if (smp64_online < 2) return 0;
    struct smp64_cpu *cpu = smp64_cpu_by_apic[apic64_id()];
    if (!cpu || cpu->index == 0) return 0;
    __atomic_fetch_add(&cpu->ticks, 1, __ATOMIC_RELEASE);
    if ((cs & 3) == 3 &&
        cpu->current != SMP64_CURRENT_NONE &&
        gdt64_on_ring0(cpu->index, rsp))
        __atomic_fetch_add(&cpu->user_irq, 1, __ATOMIC_RELEASE);
    return 1;
}

void smp64_ipi_dispatch(u32 vector) {
    struct smp64_cpu *cpu = smp64_cpu_by_apic[apic64_id()];
    if (!cpu) return;
    if (vector == SMP64_IPI_ACK) {
        if (smp64_rdmsr(MSR_GS_BASE) == (u64)(uptr_t)cpu)
            cpu->ipi_ack++;
    } else if (vector == SMP64_IPI_WORK) {
        for (u32 turn = 0; turn < SMP64_SPIN_TURNS; turn++) {
            spin_lock(&smp64_spin);
            smp64_spin_counter++;
            spin_unlock(&smp64_spin);
        }
        __atomic_store_n(&cpu->work_done, 1, __ATOMIC_RELEASE);
    } else if (vector == SMP64_IPI_STRESS) {
        smp64_stress_run(smp64_stress_turns);
        __atomic_store_n(&cpu->stress_done, 1, __ATOMIC_RELEASE);
    } else if (vector == SMP64_IPI_TLBSHOT) {
        smp64_tlb_flush_local();
        __atomic_store_n(&cpu->tlb_done,
                         __atomic_load_n(&cpu->tlb_gen, __ATOMIC_ACQUIRE),
                         __ATOMIC_RELEASE);
    } else if (vector == SMP64_IPI_TIMER) {
        apic64_timer_enable();
    } else if (vector == SMP64_IPI_TIMER_OFF) {
        apic64_timer_mask();
    } else if (vector == SMP64_IPI_USER) {
        smp64_ap_enter_user(cpu);
    } else if (vector == SMP64_IPI_PARK) {
        u32 ds;
        apic64_eoi();
        apic64_timer_mask();
        ds = GDT64_KERNEL_DS;
        __asm__ volatile("mov %0, %%ds; mov %0, %%es" : : "r"(ds));
        smp64_gs_kernel(cpu);
        vm64_activate(smp64_kernel_cr3);
        __atomic_store_n(&cpu->user_done, 1, __ATOMIC_RELEASE);
        // sti: a later IPI_USER must be able to land (cli;hlt blocked it).
        for (;;)
            __asm__ volatile("sti; hlt" ::: "memory");
    } else if (vector == SMP64_IPI_RESCHED) {
        __atomic_store_n(&cpu->resched, 1, __ATOMIC_RELEASE);
    } else if (vector == SMP64_IPI_NET_RX) {
        // The receive mailbox's worker entry: the frame is processed on the
        // CPU that owns the interface, which is the whole point of the
        // hand-off. A drain that finds the slot empty is a coalesced kick
        // and nothing else.
        net_rx_drain(cpu->index);
    } else if (vector == SMP64_IPI_TSS) {
        u16 tr;
        __asm__ volatile("str %0" : "=m"(tr));
        __atomic_store_n(&cpu->tr, tr, __ATOMIC_RELEASE);
    }
}

u32 smp64_cpu_count(void) {
    return smp64_online;
}

u8 smp64_bsp_apic_id(void) {
    return smp64_bsp_id;
}
