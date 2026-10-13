#include "tests64.h"
#include "test_report.h"
#include "smp64.h"
#include "apic64.h"
#include "time64.h"
#include "gdt64.h"
#include "irq.h"
#include "scheduler.h"
#include "task.h"
#include "vm64.h"
#include "kernel64_internal.h"
#include "serial64.h"
#include "pmm.h"
#include "object.h"
#include "klock.h"
#include "posix_fd.h"
#include "posix_pipe.h"
#include "net_buffer.h"
#include "net_rx.h"
#include "net_test.h"
#include "vector64.h"
#include "route.h"
#include "socket.h"
#include "vnic.h"
#include "driver.h"
#include "driver_supervisor.h"
#include "pci64.h"

#define SMP64_USER_GETPID 16
#define SMP64_USER_STUB_AFTER 7
#define SMP64_AP 1

// mov eax, 16; syscall; jmp $
static const u8 smp64_user_stub[] = {
    0xB8, SMP64_USER_GETPID, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    0xEB, 0xFE
};

// jmp $ - stays in ring3 with IF=1 so the AP timer can use TSS.RSP0.
static const u8 smp64_user_spin[] = {
    0xEB, 0xFE
};

// inc qword [VM64_STACK_TOP - 8]; jmp back - counts this task's turns in
// the stack page, the writable one, where the kernel can read the count.
// The pin does not zero that page, so the tests clear the count through
// the kernel pointer before the task is allowed to start.
static const u8 smp64_spin_stub[] = {
    0x48, 0xFF, 0x05, 0xF1, 0xFF, 0x1F, 0x00, 0xEB, 0xF7
};

// Waits for the word at VM64_STACK_TOP - 8 to go nonzero, then returns from
// a syscall with a stack pointer that maps nowhere: that is the bad return
// the containment has to answer. The stack pointer is the register to
// plant, not rcx, because syscall overwrites rcx with its return address;
// the entry saves rsp before it switches to the kernel stack. The gate is
// there because the entry path clears the per-CPU syscall flag: the test
// has to arm the real dispatch after this task is already in ring 3, and
// only then open the gate.
//   movabs rax, [VM64_STACK_TOP - 8]; test rax, rax; jz -15
//   mov rsp, 1; mov eax, 16; syscall; jmp $
static const u8 smp64_bad_return_stub[] = {
    0x48, 0xA1, 0xF8, 0xFF, 0x1F, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x85, 0xC0,
    0x74, 0xF1,
    0x48, 0xC7, 0xC4, 0x01, 0x00, 0x00, 0x00,
    0xB8, SMP64_USER_GETPID, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    0xEB, 0xFE
};

static int wait_rounds(u32 (*load)(u32), u32 index, u32 rounds) {
    while (rounds--) {
        if (load(index)) return 0;
        apic64_delay_ms(10);
    }
    return -1;
}

static int wait_flag(u32 (*load)(u32), u32 index) {
    return wait_rounds(load, index, SMP64_BOOT_TIMEOUT_MS / 10);
}

static int test_smp64_ipi(void) {
    u32 n = smp64_cpu_count();
    for (u32 index = 1; index < n; index++) {
        smp64_clear_ipi_ack(index);
        __atomic_thread_fence(__ATOMIC_RELEASE);
        if (smp64_ipi_cpu(index, SMP64_IPI_ACK)) return -1;
        if (wait_flag(smp64_ipi_ack, index)) return -1;
    }
    return 0;
}

static int test_smp64_spin(void) {
    u32 n = smp64_cpu_count();
    smp64_spin_reset();
    for (u32 index = 1; index < n; index++)
        smp64_clear_work_done(index);
    for (u32 index = 1; index < n; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_WORK))
            return -1;
    smp64_spin_bsp(SMP64_SPIN_TURNS);
    // Ten times the ordinary window: the APs share one ticket lock and one
    // host core can carry several of them, so under TCG the last to finish
    // can be many seconds behind the BSP. That is slowness, not a lost CPU,
    // and a CPU that never reports still fails here.
    for (u32 index = 1; index < n; index++)
        if (wait_rounds(smp64_work_done, index,
                        SMP64_BOOT_TIMEOUT_MS / 10 * 10)) {
            serial64_write("Mich x86_64: SMP spinlock stress lost cpu ");
            serial64_hex(index);
            serial64_write("\n");
            return -1;
        }
    if (smp64_spin_count() != (u64)n * SMP64_SPIN_TURNS) {
        serial64_write("Mich x86_64: SMP spinlock stress short count\n");
        return -1;
    }
    return 0;
}

static int test_smp64_timer(void) {
    u32 n = smp64_cpu_count();
    int failed = 0;
    for (u32 index = 1; index < n; index++) {
        smp64_clear_ticks(index);
        if (smp64_ipi_cpu(index, SMP64_IPI_TIMER))
            return -1;
    }
    for (u32 index = 1; index < n; index++)
        if (wait_flag(smp64_ticks, index)) failed = 1;
    for (u32 index = 1; index < n; index++)
        smp64_ipi_cpu(index, SMP64_IPI_TIMER_OFF);
    return failed ? -1 : 0;
}

static int test_smp64_tss(void) {
    u16 tr;
    u32 n = smp64_cpu_count();
    __asm__ volatile("str %0" : "=m"(tr));
    if (tr != gdt64_tss_selector(0)) return -1;
    if (!gdt64_tss_ok()) return -1;
    for (u32 index = 1; index < n; index++) {
        smp64_clear_tr(index);
        __atomic_thread_fence(__ATOMIC_RELEASE);
        if (smp64_ipi_cpu(index, SMP64_IPI_TSS)) return -1;
        if (wait_flag(smp64_tr, index)) return -1;
        if (smp64_tr(index) != gdt64_tss_selector(index)) return -1;
        if (smp64_tr(index) == gdt64_tss_selector(0)) return -1;
    }
    return 0;
}

static int test_smp64_current(void) {
    u32 n = smp64_cpu_count();
    int pinned = 2;
    int saved;
    int next;
    if (smp64_cpu_current(0) == SMP64_CURRENT_NONE)
        return -1;
    for (u32 index = 1; index < n; index++) {
        if (smp64_cpu_current(index) != SMP64_CURRENT_NONE)
            return -1;
        if (smp64_cpu_current(index) == smp64_cpu_current(0))
            return -1;
    }
    // Pin init64-two so BSP pick_next must skip it. Restores on_cpu.
    if (pinned >= task_pool_count ||
        task_pool[pinned].state != TASK_RUNNING)
        return -1;
    saved = task_pool[pinned].on_cpu;
    task_pool[pinned].on_cpu = (int)SMP64_AP;
    next = scheduler_pick_next(1);
    task_pool[pinned].on_cpu = saved;
    if (next == pinned || next < 0) return -1;
    return 0;
}

static int test_smp64_syscall(void) {
    return smp64_sysstacks_ok() ? 0 : -1;
}

static int test_smp64_user(void) {
    u32 slot;
    if (smp64_arm_user(SMP64_AP, smp64_user_stub, sizeof(smp64_user_stub)))
        return -1;
    slot = smp64_cpu_current(SMP64_AP);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    if (smp64_ipi_cpu(SMP64_AP, SMP64_IPI_USER)) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    if (wait_flag(smp64_user_done, SMP64_AP) ||
        smp64_cpu_current(SMP64_AP) != slot ||
        task_pool[slot].on_cpu != (int)SMP64_AP ||
        !smp64_sysstack_ok_cpu(SMP64_AP)) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    smp64_disarm_user(SMP64_AP);
    return 0;
}

static int test_smp64_user_irq(void) {
    u32 slot;
    u32 bsp = current_task_slot;
    u64 bsp_rip;
    if (bsp >= MAX_TASKS) return -1;
    bsp_rip = task_contexts[bsp].rip;
    if (smp64_arm_user(SMP64_AP, smp64_user_spin, sizeof(smp64_user_spin)))
        return -1;
    slot = smp64_cpu_current(SMP64_AP);
    smp64_clear_ticks(SMP64_AP);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    if (smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER) ||
        smp64_ipi_cpu(SMP64_AP, SMP64_IPI_USER)) {
        smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    if (wait_flag(smp64_user_irq, SMP64_AP)) {
        smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
    if (smp64_ipi_cpu(SMP64_AP, SMP64_IPI_PARK)) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    if (wait_flag(smp64_user_done, SMP64_AP) ||
        smp64_cpu_current(SMP64_AP) != slot ||
        !gdt64_stack_ok() ||
        !smp64_sysstack_ok_cpu(SMP64_AP)) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    if (!smp64_preempts(SMP64_AP) ||
        current_task_slot != bsp ||
        task_contexts[bsp].rip != bsp_rip ||
        task_contexts[slot].rip != VM64_PROGRAM_BASE ||
        task_contexts[slot].rsp != VM64_STACK_TOP) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    smp64_disarm_user(SMP64_AP);
    return 0;
}

static int test_smp64_live(void) {
    u32 slot;
    u32 bsp = current_task_slot;
    u64 bsp_rip;
    u64 pid;
    u32 deadline;
    if (bsp >= MAX_TASKS) return -1;
    bsp_rip = task_contexts[bsp].rip;
    if (smp64_arm_user(SMP64_AP, smp64_user_stub, sizeof(smp64_user_stub)))
        return -1;
    slot = smp64_cpu_current(SMP64_AP);
    pid = (u64)(u32)task_pool[slot].id;
    smp64_clear_ticks(SMP64_AP);
    smp64_set_syscall_live(SMP64_AP, 1);
    if (smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER) ||
        smp64_ipi_cpu(SMP64_AP, SMP64_IPI_USER)) {
        smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    // First ring3 tick can land before syscall; wait for saved getpid.
    deadline = SMP64_BOOT_TIMEOUT_MS / 10;
    while (deadline--) {
        if (smp64_preempts(SMP64_AP) && task_contexts[slot].rax == pid)
            break;
        apic64_delay_ms(10);
    }
    if (task_contexts[slot].rax != pid) {
        smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
    if (smp64_ipi_cpu(SMP64_AP, SMP64_IPI_PARK)) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    if (wait_flag(smp64_user_done, SMP64_AP) ||
        smp64_cpu_current(SMP64_AP) != slot ||
        !gdt64_stack_ok() ||
        !smp64_sysstack_ok_cpu(SMP64_AP)) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    if (!smp64_preempts(SMP64_AP) ||
        current_task_slot != bsp ||
        task_contexts[bsp].rip != bsp_rip ||
        task_contexts[slot].rax != pid ||
        task_contexts[slot].rax == (u64)(u32)task_pool[bsp].id ||
        task_contexts[slot].rip != VM64_PROGRAM_BASE + SMP64_USER_STUB_AFTER ||
        task_contexts[slot].rsp != VM64_STACK_TOP) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    smp64_disarm_user(SMP64_AP);
    return 0;
}

static void drop_ap_tasks(u32 a, u32 b) {
    smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
    smp64_disarm_user(SMP64_AP);
    if (a < MAX_TASKS && task_pool[a].state != TASK_FREE)
        task_free_slot(&task_pool[a]);
    if (b < MAX_TASKS && b != a && task_pool[b].state != TASK_FREE)
        task_free_slot(&task_pool[b]);
}

static int test_smp64_schedule(void) {
    u32 a;
    u32 b;
    u32 seen_a = 0;
    u32 seen_b = 0;
    u32 deadline;
    u32 bsp = current_task_slot;
    if (smp64_pin_user(SMP64_AP, smp64_user_spin, sizeof(smp64_user_spin), &b))
        return -1;
    if (smp64_arm_user(SMP64_AP, smp64_user_spin, sizeof(smp64_user_spin))) {
        task_free_slot(&task_pool[b]);
        return -1;
    }
    a = smp64_cpu_current(SMP64_AP);
    if (a >= MAX_TASKS || b >= MAX_TASKS || a == b) {
        drop_ap_tasks(a, b);
        return -1;
    }
    smp64_clear_ticks(SMP64_AP);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    if (smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER) ||
        smp64_ipi_cpu(SMP64_AP, SMP64_IPI_USER)) {
        drop_ap_tasks(a, b);
        return -1;
    }
    deadline = SMP64_BOOT_TIMEOUT_MS / 10;
    while (deadline--) {
        u32 cur = smp64_cpu_current(SMP64_AP);
        if (cur == a) seen_a = 1;
        if (cur == b) seen_b = 1;
        if (seen_a && seen_b) break;
        apic64_delay_ms(10);
    }
    smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
    if (smp64_ipi_cpu(SMP64_AP, SMP64_IPI_PARK)) {
        drop_ap_tasks(a, b);
        return -1;
    }
    if (wait_flag(smp64_user_done, SMP64_AP) ||
        current_task_slot != bsp ||
        !seen_a || !seen_b) {
        drop_ap_tasks(a, b);
        return -1;
    }
    drop_ap_tasks(a, b);
    return 0;
}

// Park the CPU before the slot goes: freeing a task another CPU is still
// running would leave that CPU on a recycled slot.
static int drop_pinned(u32 slot, u32 index) {
    smp64_ipi_cpu(index, SMP64_IPI_PARK);
    if (wait_flag(smp64_user_done, index)) return -1;
    smp64_ipi_cpu(index, SMP64_IPI_TIMER_OFF);
    smp64_disarm_user(index);
    if (slot < MAX_TASKS && task_pool[slot].state != TASK_FREE)
        task_free_slot(&task_pool[slot]);
    return 0;
}

// The kick is asynchronous: the counter may already sit past the sample,
// so the wait has to be for the IPI being handled, which is the preempt
// this CPU records when it takes the frame path.
static int wait_preempts(u64 above) {
    u32 deadline = SMP64_BOOT_TIMEOUT_MS / 10 * 4;
    while (deadline--) {
        if (smp64_preempts(SMP64_AP) > above) return 0;
        apic64_delay_ms(10);
    }
    return -1;
}

static int wait_counter(volatile u64 *counter, u64 above) {
    u32 deadline = SMP64_BOOT_TIMEOUT_MS / 10 * 4;
    while (deadline--) {
        if (__atomic_load_n(counter, __ATOMIC_ACQUIRE) > above) return 0;
        apic64_delay_ms(10);
    }
    return -1;
}

// An ordinary task pinned to an AP: with the AP parked in ring 0 and its
// tick masked, only the reschedule IPI can start it, and the AP picks it
// out of the pool on its own.
// Every branch of the pinned test is a separate timing assertion, so a bare
// -1 says nothing about which one slipped. The marker names the branch.
static int pinned_fail(u32 where) {
    char buf[] = "Mich x86_64: SMP AP pinned fail at 0\n";
    buf[sizeof(buf) - 3] = (char)('0' + where);
    serial64_write(buf);
    return -1;
}

static int test_smp64_pinned(void) {
    volatile u64 *counter = 0;
    u64 turns;
    u64 preempts;
    u32 slot;
    if (smp64_pin_task(SMP64_AP, smp64_spin_stub, sizeof(smp64_spin_stub),
                       &slot, (u64 **)&counter))
        return pinned_fail(1);
    counter[0] = 0;
    apic64_delay_ms(20);
    if (counter[0] || smp64_cpu_current(SMP64_AP) != SMP64_CURRENT_NONE) {
        drop_pinned(slot, SMP64_AP);
        return pinned_fail(2);
    }
    if (smp64_resched_cpu(SMP64_AP) ||
        wait_counter(counter, 0) ||
        smp64_cpu_current(SMP64_AP) != slot ||
        task_pool[slot].state != TASK_RUNNING) {
        drop_pinned(slot, SMP64_AP);
        return pinned_fail(3);
    }
    // A second kick lands in ring 3: the frame is rewritten the way the
    // tick rewrites it and the same task keeps the CPU.
    turns = counter[0];
    preempts = (u64)smp64_preempts(SMP64_AP);
    if (smp64_resched_cpu(SMP64_AP) ||
        wait_preempts(preempts) ||
        counter[0] <= turns ||
        smp64_cpu_current(SMP64_AP) != slot) {
        drop_pinned(slot, SMP64_AP);
        return pinned_fail(4);
    }
    if (drop_pinned(slot, SMP64_AP)) return pinned_fail(5);
    if (smp64_cpu_current(SMP64_AP) != SMP64_CURRENT_NONE) return pinned_fail(6);
    return 0;
}

// A pinned task that returns from a syscall to an unmapped address is
// contained: the task goes, the CPU stays, and the next task pinned to it
// takes over. Without the handover the AP would sit in cli; hlt for the
// rest of the boot and every later test on it would hang.
static int test_smp64_contain(void) {
    volatile u64 *gate = 0;
    volatile u64 *counter = 0;
    u32 bad;
    u32 next;
    u32 deadline;
    if (smp64_pin_task(SMP64_AP, smp64_bad_return_stub,
                       sizeof(smp64_bad_return_stub), &bad,
                       (u64 **)&gate)) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    if (smp64_pin_task(SMP64_AP, smp64_spin_stub, sizeof(smp64_spin_stub),
                       &next, (u64 **)&counter)) {
        smp64_disarm_user(SMP64_AP);
        return -1;
    }
    gate[0] = 0;
    counter[0] = 0;
    // The bad task has to be the one this CPU picks, or the test would prove
    // nothing; the pool hands out the lowest free slot, and this checks that
    // instead of trusting it.
    if (smp64_pick_pinned(SMP64_AP) != (int)bad) {
        drop_pinned(next, SMP64_AP);
        drop_pinned(bad, SMP64_AP);
        return -1;
    }
    if (smp64_resched_cpu(SMP64_AP)) {
        drop_pinned(next, SMP64_AP);
        drop_pinned(bad, SMP64_AP);
        return -1;
    }
    // The pickup records the slot before it enters ring 3, so the record is
    // the fact to wait for. The gate holds the syscall back, which is what
    // lets the test arm the real dispatch after the entry cleared it.
    deadline = SMP64_BOOT_TIMEOUT_MS / 10;
    while (deadline-- && smp64_cpu_current(SMP64_AP) != bad)
        apic64_delay_ms(10);
    if (smp64_cpu_current(SMP64_AP) != bad) {
        drop_pinned(next, SMP64_AP);
        drop_pinned(bad, SMP64_AP);
        return -1;
    }
    smp64_set_syscall_live(SMP64_AP, 1);
    gate[0] = 1;
    if (wait_counter(counter, 0)) {
        smp64_set_syscall_live(SMP64_AP, 0);
        drop_pinned(next, SMP64_AP);
        drop_pinned(bad, SMP64_AP);
        return -1;
    }
    if (smp64_cpu_current(SMP64_AP) != next ||
        task_pool[bad].state == TASK_RUNNING) {
        smp64_set_syscall_live(SMP64_AP, 0);
        drop_pinned(next, SMP64_AP);
        drop_pinned(bad, SMP64_AP);
        return -1;
    }
    smp64_set_syscall_live(SMP64_AP, 0);
    smp64_ipi_cpu(SMP64_AP, SMP64_IPI_TIMER_OFF);
    if (drop_pinned(next, SMP64_AP)) return -1;
    if (drop_pinned(bad, SMP64_AP)) return -1;
    return 0;
}

// The allocator is shared the moment two CPUs run at once. Every CPU holds
// four pages at a time, so a page handed to both of them is caught here, and
// the free-page count has to land exactly back on the baseline: that is what
// no lost update means for the bitmap and the refcounts.
static int test_smp64_alloc_concur(void) {
    u32 n = smp64_cpu_count();
    u64 before = pmm_free_pages();
    smp64_stress_reset(SMP64_STRESS_TURNS, 0, SMP64_STRESS_ALLOC);
    for (u32 index = 1; index < n; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) return -1;
    smp64_stress_run(SMP64_STRESS_TURNS);
    for (u32 index = 1; index < n; index++)
        if (wait_rounds(smp64_stress_done, index,
                        SMP64_BOOT_TIMEOUT_MS / 10 * 4))
            return -1;
    if (smp64_stress_failed()) return -1;
    if (smp64_stress_pages() !=
        (u64)n * SMP64_STRESS_TURNS * SMP64_STRESS_HOLD)
        return -1;
    if (pmm_free_pages() != before) return -1;
    return 0;
}

static volatile u32 smp64_destroy_count;

static void smp64_stress_destroy(struct kernel_object *object) {
    (void)object;
    __atomic_fetch_add(&smp64_destroy_count, 1, __ATOMIC_RELAXED);
}

// One object both CPUs retain and release while they hammer the table. The
// arithmetic is exact: every turn takes one reference and drops it, so the
// count after the storm is the count before it. A lost update shows as a
// count that cannot come from that arithmetic, and the destroy callback
// firing more than once shows the object died early.
static int test_smp64_refcount_concur(void) {
    u32 n = smp64_cpu_count();
    u32 active = object_active_count();
    int failed = 0;
    smp64_destroy_count = 0;
    struct kernel_object *shared =
        object_create(KOBJECT_PAGE, 0, smp64_stress_destroy);
    if (!shared) return -1;
    smp64_stress_reset(SMP64_STRESS_TURNS, shared, SMP64_STRESS_REFCOUNT);
    for (u32 index = 1; index < n; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) failed = 1;
    if (!failed) {
        smp64_stress_run(SMP64_STRESS_TURNS);
        for (u32 index = 1; index < n; index++)
            if (wait_rounds(smp64_stress_done, index,
                            SMP64_BOOT_TIMEOUT_MS / 10 * 4))
                failed = 1;
    }
    if (smp64_stress_failed()) failed = 1;
    if (smp64_stress_objects() != (u64)n * SMP64_STRESS_TURNS) failed = 1;
    if (shared->references != 1) failed = 1;
    object_release(shared);
    if (smp64_destroy_count != 1) failed = 1;
    if (object_active_count() != active) failed = 1;
    return failed ? -1 : 0;
}

// A storm turn does far more per turn than the allocator hammer, so its
// window is longer: four CPUs share one host here, and a CPU that is only
// slow must not read as a CPU that stopped.
#define SMP64_SPAWN_ROUNDS (SMP64_BOOT_TIMEOUT_MS / 10 * 15)
#define SMP64_PARALLEL_WINDOW_MS 20
#define SMP64_PARALLEL_ROUNDS 20

// What the storm must not move is the pool's capacity, not the free-slot
// count: allocating past the grown part of the pool turns a never-used slot
// (state RUNNING by the zero-init) into a reusable one, so the free count
// can legitimately rise by one while the pool still holds the same number
// of slots it can hand out.
static u32 spawn_capacity(void) {
    u32 capacity = (u32)MAX_TASKS - (u32)task_pool_count;
    for (u32 slot = 0; slot < (u32)MAX_TASKS; slot++)
        if (task_pool[slot].state == TASK_FREE) capacity++;
    return capacity;
}

static u32 spawn_free_mask(void) {
    u32 mask = 0;
    for (u32 slot = 0; slot < (u32)MAX_TASKS; slot++)
        if (task_pool[slot].state == TASK_FREE) mask |= 1u << slot;
    return mask;
}

// A spawn rewrites the pool, the descriptor table and a pipe, so the storm
// runs that whole sequence on every CPU at once. The arithmetic is exact
// again: each CPU finishes its own turns and the counters land back on the
// baseline, which is what a lost update would move.
static int test_smp64_spawn(void) {
    u32 n = smp64_cpu_count();
    u32 fds = posix_fd_active_count();
    u32 pipes = posix_pipe_active_count();
    u32 capacity_before = spawn_capacity();
    u32 mask_before = spawn_free_mask();
    u32 reason = 0;
    smp64_spawn_reset(SMP64_STRESS_TURNS);
    for (u32 index = 1; index < n; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) reason = 1;
    if (!reason) {
        smp64_stress_run(SMP64_STRESS_TURNS);
        for (u32 index = 1; index < n; index++)
            if (wait_rounds(smp64_stress_done, index, SMP64_SPAWN_ROUNDS))
                reason = 1;
    }
    if (!reason && smp64_stress_failed()) reason = 2;
    if (!reason && smp64_spawn_slots() != (u64)n * SMP64_STRESS_TURNS)
        reason = 3;
    if (!reason && posix_fd_active_count() != fds) reason = 4;
    if (!reason && posix_pipe_active_count() != pipes) reason = 5;
    if (!reason && spawn_capacity() != capacity_before) reason = 6;
    // The failure line carries the numbers the check read: a red run should
    // not need a second instrumented build to say which count moved.
    if (reason) {
        serial64_write("Mich x86_64: spawn storm check failed: ");
        serial64_hex(reason);
        serial64_write(" cpus="); serial64_hex(n);
        serial64_write(" want="); serial64_hex((u64)n * SMP64_STRESS_TURNS);
        serial64_write(" got="); serial64_hex(smp64_spawn_slots());
        serial64_write(" storm="); serial64_hex(smp64_stress_failed());
        serial64_write(" fds="); serial64_hex(posix_fd_active_count());
        serial64_write(" base="); serial64_hex(fds);
        serial64_write(" pipes="); serial64_hex(posix_pipe_active_count());
        serial64_write(" base="); serial64_hex(pipes);
        serial64_write(" cap="); serial64_hex(spawn_capacity());
        serial64_write(" base="); serial64_hex(capacity_before);
        serial64_write(" mask="); serial64_hex(spawn_free_mask());
        serial64_write(" base="); serial64_hex(mask_before);
        for (u32 index = 1; index < n; index++) {
            serial64_write(" d"); serial64_hex(index);
            serial64_write("="); serial64_hex(smp64_stress_done(index));
        }
        serial64_write("\n");
    }
    return reason ? -1 : 0;
}

// The receive path is shared the moment a frame can arrive on one CPU while
// another CPU runs the protocol stack: the driver capsule's batch, the tick
// and a second driver's poll are all inside it. Every CPU here delivers the
// same frame the way the driver does, and the receive counter has to land
// exactly on what the arithmetic says: that is what no lost update means on
// a path this wide.
static int test_smp64_net_storm(void) {
    u32 n = smp64_cpu_count();
    u32 free_pages = pmm_free_pages();
    u32 objects = object_active_count();
    u32 interfaces = net_interface_active_count();
    u32 pools = packet_pool_active_count();
    u32 vnics = vnic_active_count();
    u32 rings = ring_active_count();
    int reason = 0;
    struct driver_domain owner;
    u8 *owner_bytes = (u8 *)&owner;
    for (usize_t index = 0; index < sizeof(owner); index++)
        owner_bytes[index] = 0;
    owner.id = 79;
    owner.pid = 0;
    owner.state = DRIVER_DOMAIN_RUNNING;
    owner.active = 1;
    const u8 mac[6] = {0x02, 0x4D, 0x49, 0x43, 0x48, 0x21};
    struct kernel_object *vnic = vnic_create(16, 16);
    struct kernel_object *interface = vnic ? net_interface_create(
        &owner, vnic_pool(vnic), vnic_rx_ring(vnic), vnic_tx_ring(vnic),
        mac, 1500, "eth-storm") : 0;
    if (!vnic || !interface || net_interface_register(interface) ||
        net_interface_set_ipv4(interface, &owner, 0x0A090002u, 0xFFFFFF00u) ||
        net_interface_set_link(interface, &owner, 1))
        reason = 1;
    static u8 storm_frame[64];
    const u8 peer[6] = {0x02, 0x4D, 0x49, 0x43, 0x48, 0x22};
    const u8 empty[6] = {0, 0, 0, 0, 0, 0};
    if (!reason) {
        for (u32 index = 0; index < sizeof(storm_frame); index++)
            storm_frame[index] = (u8)index;
        build_ethernet_frame(storm_frame, mac, peer, 0x0806,
                             sizeof(storm_frame));
        // A request for somebody else's address: the interface consumes it
        // (one received packet) and answers nothing, so the storm drives the
        // receive path alone and never touches the transmit ring.
        build_arp_payload(storm_frame + 14, 1, peer, 0x0A090001u, empty,
                          0x0A0900FFu);
        struct net_interface *info = net_interface_get(interface);
        if (!info) reason = 1;
        else {
            smp64_net_storm_prepare(interface, storm_frame,
                                    sizeof(storm_frame));
            smp64_stress_reset(SMP64_STRESS_TURNS, 0, SMP64_STRESS_NET);
            for (u32 index = 1; index < n; index++)
                if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) reason = 2;
            if (!reason) {
                smp64_stress_run(SMP64_STRESS_TURNS);
                for (u32 index = 1; index < n; index++)
                    if (wait_rounds(smp64_stress_done, index,
                                    SMP64_BOOT_TIMEOUT_MS / 10 * 4))
                        reason = 3;
            }
            if (!reason) {
                if (smp64_stress_failed()) reason = 4;
                else if (info->stats.rx_packets !=
                         (u64)n * SMP64_STRESS_TURNS) reason = 5;
                else if (info->stats.rx_drops) reason = 6;
            }
            smp64_net_storm_prepare(0, 0, 0);
        }
    }
    if (reason) {
        struct net_interface *info = net_interface_get(interface);
        serial64_write("Mich x86_64: net storm check failed: ");
        serial64_hex(reason);
        serial64_write(" cpus="); serial64_hex(n);
        serial64_write(" want=");
        serial64_hex((u64)n * SMP64_STRESS_TURNS);
        serial64_write(" rx=");
        serial64_hex(info ? info->stats.rx_packets : 0);
        serial64_write(" drops=");
        serial64_hex(info ? info->stats.rx_drops : 0);
        serial64_write(" storm="); serial64_hex(smp64_stress_failed());
        for (u32 index = 1; index < n; index++) {
            serial64_write(" d"); serial64_hex(index);
            serial64_write("="); serial64_hex(smp64_stress_done(index));
        }
        serial64_write("\n");
    }
    if (interface) {
        net_interface_revoke(interface);
        net_interface_remove(interface);
        object_release(interface);
    }
    if (vnic) object_release(vnic);
    if (pmm_free_pages() != free_pages || object_active_count() != objects ||
        net_interface_active_count() != interfaces ||
        packet_pool_active_count() != pools || vnic_active_count() != vnics ||
        ring_active_count() != rings)
        reason = 7;
    return reason ? -1 : 0;
}

static u32 smp64_mailbox_kicks;

static void smp64_mailbox_kick(u32 cpu) {
    (void)cpu;
    smp64_mailbox_kicks++;
}

// The receive mailbox is a hand-off, not a queue: the frame either takes the
// slot or goes back to its caller, so the slot can add latency to a frame
// and never a drop or a second copy. The kick is the worker entry's signal,
// and one post has to mean exactly one kick.
static int test_smp64_rx_mailbox(void) {
    struct kernel_object *carrier = object_create(KOBJECT_PAGE, 0, 0);
    if (!carrier) return -1;
    net_rx_init();
    net_rx_set_kick(smp64_mailbox_kick);
    smp64_mailbox_kicks = 0;
    u32 cpu = smp64_cpu_count() > 1 ? 1u : 0u;
    u64 handoffs = net_rx_handoffs();
    u64 drains = net_rx_drains(cpu);
    int failed = 0;
    if (!net_rx_post(cpu, carrier, 7, 16, 32, 9)) failed = 1;
    if (net_rx_post(cpu, carrier, 8, 16, 32, 9)) failed = 2;
    if (smp64_mailbox_kicks != 1) failed = 3;
    if (net_rx_handoffs() != handoffs + 1) failed = 4;
    if (!net_rx_drain(cpu)) failed = 5;
    if (net_rx_drain(cpu)) failed = 6;
    if (net_rx_drains(cpu) != drains + 1) failed = 7;
    if (!net_rx_post(cpu, carrier, 9, 0, 8, 9)) failed = 8;
    if (!net_rx_drain(cpu)) failed = 9;
    if (smp64_mailbox_kicks != 2) failed = 10;
    if (net_rx_post(NET_RX_SLOT_MAX, carrier, 1, 0, 1, 0)) failed = 11;
    if (net_rx_post(cpu, 0, 1, 0, 1, 0)) failed = 12;
    net_rx_set_kick(smp64_net_kick);
    object_release(carrier);
    return failed ? -1 : 0;
}

// The device tables take the same treatment the pool got: every CPU creates
// and destroys one memory, one interrupt and one page resource per turn, and
// the tail counts have to land exactly on the baselines. The memory address
// is per-CPU, so two CPUs handed the same slot read back each other's
// address instead of overwriting in silence.
static int test_smp64_resource_storm(void) {
    u32 n = smp64_cpu_count();
    u32 objects = object_active_count();
    u32 mmio = resource_active_count(KOBJECT_MMIO);
    u32 irqs = resource_active_count(KOBJECT_IRQ);
    u32 pages = resource_active_count(KOBJECT_PAGE);
    u32 free_pages = pmm_free_pages();
    int reason = 0;
    smp64_stress_reset(SMP64_STRESS_TURNS, 0, SMP64_STRESS_RESOURCE);
    for (u32 index = 1; index < n; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) reason = 1;
    if (!reason) {
        smp64_stress_run(SMP64_STRESS_TURNS);
        for (u32 index = 1; index < n; index++)
            if (wait_rounds(smp64_stress_done, index,
                            SMP64_BOOT_TIMEOUT_MS / 10 * 4))
                reason = 2;
    }
    if (!reason) {
        if (smp64_stress_failed()) reason = 3;
        else if (object_active_count() != objects) reason = 4;
        else if (resource_active_count(KOBJECT_MMIO) != mmio) reason = 5;
        else if (resource_active_count(KOBJECT_IRQ) != irqs) reason = 6;
        else if (resource_active_count(KOBJECT_PAGE) != pages) reason = 7;
        else if (pmm_free_pages() != free_pages) reason = 8;
    }
    if (reason) {
        serial64_write("Mich x86_64: resource storm check failed: ");
        serial64_hex(reason);
        serial64_write(" cpus="); serial64_hex(n);
        serial64_write(" objects="); serial64_hex(objects);
        serial64_write(" mmio="); serial64_hex(resource_active_count(KOBJECT_MMIO));
        serial64_write(" irq="); serial64_hex(resource_active_count(KOBJECT_IRQ));
        serial64_write(" pages="); serial64_hex(resource_active_count(KOBJECT_PAGE));
        serial64_write(" free="); serial64_hex(pmm_free_pages());
        serial64_write(" storm="); serial64_hex(smp64_stress_failed());
        serial64_write(" detail="); serial64_hex(smp64_stress_detail_value());
        serial64_write(" turn=");
        serial64_hex(smp64_stress_detail_value() >> 32);
        for (u32 index = 1; index < n; index++) {
            serial64_write(" d"); serial64_hex(index);
            serial64_write("="); serial64_hex(smp64_stress_done(index));
        }
        serial64_write("\n");
    }
    return reason ? -1 : 0;
}

// The vector table is what the MSI and MSI-X paths allocate from, so the same
// storm: every CPU takes a vector and a group of four, checks the table names
// it as the owner, and hands both back. One vector handed to two CPUs cannot
// pass the owner check on both of them, and the available count has to return
// to its baseline.
static int test_smp64_domain_storm(void) {
    u32 n = smp64_cpu_count();
    u32 domains = driver_domain_count();
    u32 objects = object_active_count();
    u32 free_pages = pmm_free_pages();
    int reason = 0;
    smp64_driver_storm_prepare(pci64_object(0));
    smp64_stress_reset(SMP64_STRESS_TURNS, 0, SMP64_STRESS_DOMAIN);
    for (u32 index = 1; index < n; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) reason = 1;
    if (!reason) {
        smp64_stress_run(SMP64_STRESS_TURNS);
        for (u32 index = 1; index < n; index++)
            if (wait_rounds(smp64_stress_done, index,
                            SMP64_BOOT_TIMEOUT_MS / 10 * 4))
                reason = 2;
    }
    if (!reason) {
        if (smp64_stress_failed()) reason = 3;
        else if (!smp64_stress_domains()) reason = 4;
        else if (driver_domain_count() != domains) reason = 5;
        else if (object_active_count() != objects) reason = 6;
        else if (pmm_free_pages() != free_pages) reason = 7;
    }
    if (reason) {
        u64 detail = smp64_stress_detail_value();
        serial64_write("Mich x86_64: SMP domain storm failed reason=");
        serial64_hex((u64)reason);
        serial64_write(" detail="); serial64_hex(detail);
        serial64_write(" turn="); serial64_hex(detail >> 32);
        serial64_write(" successes="); serial64_hex(smp64_stress_domains());
        serial64_write(" domains="); serial64_hex(driver_domain_count());
        serial64_write("\n");
        return -1;
    }
    return 0;
}

static int test_smp64_module_storm(void) {
    u32 n = smp64_cpu_count();
    u32 modules = driver_module_count();
    u32 instances = driver_instance_count();
    int reason = 0;
    smp64_stress_reset(SMP64_STRESS_TURNS, 0, SMP64_STRESS_MODULE);
    for (u32 index = 1; index < n; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) reason = 1;
    if (!reason) {
        smp64_stress_run(SMP64_STRESS_TURNS);
        for (u32 index = 1; index < n; index++)
            if (wait_rounds(smp64_stress_done, index,
                            SMP64_BOOT_TIMEOUT_MS / 10 * 4))
                reason = 2;
    }
    if (!reason) {
        if (smp64_stress_failed()) reason = 3;
        else if (!smp64_stress_modules()) reason = 4;
        else if (driver_module_count() != modules) reason = 5;
        else if (driver_instance_count() != instances) reason = 6;
    }
    if (reason) {
        u64 detail = smp64_stress_detail_value();
        serial64_write("Mich x86_64: SMP module storm failed reason=");
        serial64_hex((u64)reason);
        serial64_write(" detail="); serial64_hex(detail);
        serial64_write(" turn="); serial64_hex(detail >> 32);
        serial64_write(" modules="); serial64_hex(smp64_stress_modules());
        serial64_write(" binds="); serial64_hex(smp64_stress_instances());
        serial64_write("\n");
        return -1;
    }
    return 0;
}

static int test_smp64_vector_storm(void) {
    u32 n = smp64_cpu_count();
    u32 available = vector64_available();
    int reason = 0;
    smp64_stress_reset(SMP64_STRESS_TURNS, 0, SMP64_STRESS_VECTOR);
    for (u32 index = 1; index < n; index++)
        if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) reason = 1;
    if (!reason) {
        smp64_stress_run(SMP64_STRESS_TURNS);
        for (u32 index = 1; index < n; index++)
            if (wait_rounds(smp64_stress_done, index,
                            SMP64_BOOT_TIMEOUT_MS / 10 * 4))
                reason = 2;
    }
    if (!reason) {
        if (smp64_stress_failed()) reason = 3;
        else if (vector64_available() != available) reason = 4;
    }
    if (reason) {
        serial64_write("Mich x86_64: vector storm check failed: ");
        serial64_hex(reason);
        serial64_write(" cpus="); serial64_hex(n);
        serial64_write(" available="); serial64_hex(vector64_available());
        serial64_write(" storm="); serial64_hex(smp64_stress_failed());
        for (u32 index = 1; index < n; index++) {
            serial64_write(" d"); serial64_hex(index);
            serial64_write("="); serial64_hex(smp64_stress_done(index));
        }
        serial64_write("\n");
    }
    return reason ? -1 : 0;
}

// The level checker is what turns a would-be deadlock into a named abort, so
// the battery has to show it rejects the pairs the order forbids and that
// the record follows real nesting. The locks here are the test's own: the
// point is the checker, not the subsystems it guards.
// The level numbers move whenever a subsystem is inserted into the order,
// so the report carries the name next to the number and two runs taken
// either side of such a change still line up.
static const char *klock_level_name(u32 level) {
    switch (level) {
    case KLOCK_LEVEL_MANAGER: return "manager";
    case KLOCK_LEVEL_SUPERVISOR: return "supervisor";
    case KLOCK_LEVEL_MODULE: return "module";
    case KLOCK_LEVEL_WAIT: return "wait";
    case KLOCK_LEVEL_NET: return "net";
    case KLOCK_LEVEL_FD: return "fd";
    case KLOCK_LEVEL_VM: return "vm";
    case KLOCK_LEVEL_VFS: return "vfs";
    case KLOCK_LEVEL_MSI: return "msi";
    case KLOCK_LEVEL_IOMMU: return "iommu";
    case KLOCK_LEVEL_RESOURCE: return "resource";
    case KLOCK_LEVEL_OBJECT: return "object";
    case KLOCK_LEVEL_PIPE: return "pipe";
    case KLOCK_LEVEL_POOL: return "pool";
    case KLOCK_LEVEL_PMM: return "pmm";
    default: return "unknown";
    }
}

static int test_smp64_lock_contention(void) {
    u64 total = 0;
    serial64_write("Mich x86_64: SMP lock contention report\n");
    for (u32 level = 1; level <= KLOCK_LEVEL_PMM; level++) {
        u64 acquires = 0;
        u64 waits = 0;
        klock_stats_read(level, &acquires, &waits);
        if (waits > acquires) return -1;
        total += acquires;
        serial64_write("Mich x86_64: SMP lock contention level=");
        serial64_hex(level);
        serial64_write(" acquires=");
        serial64_hex(acquires);
        serial64_write(" waits=");
        serial64_hex(waits);
        serial64_write(" name=");
        serial64_write(klock_level_name(level));
        serial64_write("\n");
    }
    return total ? 0 : -1;
}

// Every CPU faults the same copy-on-write page at once. The arithmetic is
// exact: each space drops its one reference to the shared page and takes a
// page of its own, so the shared page is left holding only the parent's
// reference and the free count comes back once the spaces go. The
// generation checks are what a dropped shootdown fails: every clone has to
// push each other CPU's completed flush past the point the clone happened.
static int test_smp64_cow_storm(void) {
    u32 n = smp64_cpu_count();
    u64 before = pmm_free_pages();
    u32 spaces[SMP64_MAX];
    u32 created = 0;
    u32 parent = 0;
    int reason = 0;
    for (u32 index = 0; index < SMP64_MAX; index++) spaces[index] = 0;
    paddr_t shared = pmm_alloc_page();
    if (!shared || vm64_create_space(&parent) ||
        vm64_map(parent, VM64_USER_BASE, shared, 1, 0))
        reason = 1;
    u32 stamped = smp64_tlb_generation();
    for (u32 index = 0; !reason && index < n; index++) {
        if (vm64_clone_space(parent, &spaces[index])) {
            reason = 2;
            break;
        }
        created++;
        smp64_cow_arm(index, spaces[index], VM64_USER_BASE);
    }
    u32 generation = smp64_tlb_generation();
    if (!reason && generation - stamped != n) reason = 3;
    if (!reason) {
        smp64_stress_reset(1, 0, SMP64_STRESS_COW);
        for (u32 index = 1; index < n; index++)
            if (smp64_ipi_cpu(index, SMP64_IPI_STRESS)) reason = 4;
        if (!reason) {
            smp64_stress_run(1);
            for (u32 index = 1; index < n; index++)
                if (wait_rounds(smp64_stress_done, index,
                                SMP64_BOOT_TIMEOUT_MS / 10 * 4))
                    reason = 5;
        }
        if (!reason && smp64_stress_failed()) reason = 6;
        if (!reason && pmm_page_refs(shared) != 1) reason = 7;
        for (u32 index = 1; !reason && index < n; index++)
            if (smp64_tlb_done(index) < generation) reason = 8;
    }
    for (u32 index = 0; index < created; index++)
        vm64_destroy_space(spaces[index]);
    if (parent) vm64_destroy_space(parent);
    smp64_cow_disarm();
    if (!reason && pmm_free_pages() != before) reason = 9;
    if (reason) {
        serial64_write("Mich x86_64: cow storm check failed: ");
        serial64_hex(reason);
        serial64_write(" cpus="); serial64_hex(n);
        serial64_write(" refs="); serial64_hex(pmm_page_refs(shared));
        serial64_write(" gen="); serial64_hex(generation - stamped);
        serial64_write("\n");
        return -1;
    }
    serial64_write("Mich x86_64: SMP copy-on-write storm pass\n");
    return 0;
}

#define SMP64_NETBENCH_PACKETS 512u

// Aggregate throughput with N CPUs driving their own loopback streams. The
// driver count is what varies, not the guest CPU count, so one guest yields
// every column of the table and the columns differ in nothing but how many
// CPUs were asked to work. The window is asserted against the slowest single
// stream rather than against a speedup: under TCG the host decides how much
// of a guest CPU it runs, so a ratio is a measurement and an invariant is a
// check, and only the second belongs in a test that has to pass.
static int test_smp64_net_bench(void) {
    u32 online = smp64_cpu_count();
    u32 free_pages = pmm_free_pages();
    u32 objects = object_active_count();
    u32 pools = packet_pool_active_count();
    u32 vnics = vnic_active_count();
    u32 rings = ring_active_count();
    struct kernel_object *vnic[SMP64_MAX];
    u32 created = 0;
    int reason = 0;
    if (online < 2) {
        serial64_write("Mich x86_64: SMP netbench skipped (");
        serial64_hex(online);
        serial64_write(" cpus)\n");
        return 0;
    }
    for (u32 index = 0; index < SMP64_MAX; index++) vnic[index] = 0;
    smp64_netbench_reset();
    for (u32 index = 0; !reason && index < online; index++) {
        vnic[index] = vnic_create(64, 32);
        if (!vnic[index] || smp64_netbench_arm(index, vnic[index])) {
            reason = 1;
            break;
        }
        created = index + 1;
    }
    for (u32 drivers = 1; !reason && drivers <= online; drivers <<= 1) {
        u64 moved = 0;
        u64 slowest = 0;
        if (smp64_netbench_begin(drivers, SMP64_NETBENCH_PACKETS,
                                 SMP64_NETBENCH_FRAME)) {
            reason = 2;
            break;
        }
        smp64_stress_run(1);
        for (u32 index = 1; index < drivers; index++)
            if (wait_rounds(smp64_netbench_done, index,
                            SMP64_BOOT_TIMEOUT_MS)) {
                reason = 3;
                break;
            }
        smp64_netbench_finish();
        if (reason) break;
        if (smp64_stress_failed()) {
            reason = 4;
            break;
        }
        for (u32 index = 0; index < drivers; index++) {
            u64 own = smp64_netbench_cycles(index);
            if (!smp64_netbench_done(index) || !own) {
                reason = 5;
                break;
            }
            if (own > slowest) slowest = own;
            moved += SMP64_NETBENCH_PACKETS;
        }
        if (reason) break;
        u64 window = smp64_netbench_window();
        // The join cannot land before the slowest stream did.
        if (!window || window < slowest) {
            reason = 6;
            break;
        }
        serial64_write("Mich x86_64: netbench-smp drivers=");
        serial64_hex(drivers);
        serial64_write(" packets=");
        serial64_hex(moved);
        serial64_write(" window=0x");
        serial64_hex(window);
        serial64_write(" cycles-per-packet=0x");
        serial64_hex(window / moved);
        serial64_write("\n");
    }
    smp64_netbench_reset();
    for (u32 index = 0; index < created; index++)
        if (vnic[index]) object_release(vnic[index]);
    if (!reason && (pmm_free_pages() != free_pages ||
                    object_active_count() != objects ||
                    packet_pool_active_count() != pools ||
                    vnic_active_count() != vnics ||
                    ring_active_count() != rings))
        reason = 7;
    if (reason) {
        serial64_write("Mich x86_64: SMP netbench check failed: ");
        serial64_hex((u64)reason);
        serial64_write("\n");
        return -1;
    }
    return 0;
}

static int test_smp64_lockorder(void) {
    static struct klock outer = KLOCK_INIT(KLOCK_LEVEL_NET);
    static struct klock inner = KLOCK_INIT(KLOCK_LEVEL_PMM);
    if (klock_order_ok(0, KLOCK_LEVEL_MANAGER) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_MANAGER, KLOCK_LEVEL_SUPERVISOR) != 1)
        return -1;
    if (klock_order_ok(KLOCK_LEVEL_SUPERVISOR, KLOCK_LEVEL_MODULE) != 1)
        return -1;
    if (klock_order_ok(KLOCK_LEVEL_MODULE, KLOCK_LEVEL_NET) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_NET, KLOCK_LEVEL_FD) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_FD, KLOCK_LEVEL_VFS) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_VFS, KLOCK_LEVEL_MSI) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_VFS, KLOCK_LEVEL_RESOURCE) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_VFS, KLOCK_LEVEL_OBJECT) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_FD, KLOCK_LEVEL_MSI) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_MSI, KLOCK_LEVEL_IOMMU) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_IOMMU, KLOCK_LEVEL_RESOURCE) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_RESOURCE, KLOCK_LEVEL_OBJECT) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_OBJECT, KLOCK_LEVEL_PIPE) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_PIPE, KLOCK_LEVEL_POOL) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_POOL, KLOCK_LEVEL_PMM) != 1) return -1;
    if (klock_order_ok(KLOCK_LEVEL_MANAGER, KLOCK_LEVEL_PMM) != 1)
        return -1;
    if (klock_order_ok(KLOCK_LEVEL_PIPE, KLOCK_LEVEL_NET) != 0) return -1;
    if (klock_order_ok(KLOCK_LEVEL_SUPERVISOR, KLOCK_LEVEL_MANAGER) != 0)
        return -1;
    if (klock_order_ok(KLOCK_LEVEL_MODULE, KLOCK_LEVEL_SUPERVISOR) != 0)
        return -1;
    if (klock_order_ok(KLOCK_LEVEL_NET, KLOCK_LEVEL_MODULE) != 0) return -1;
    if (klock_order_ok(KLOCK_LEVEL_MSI, KLOCK_LEVEL_FD) != 0) return -1;
    if (klock_order_ok(KLOCK_LEVEL_VFS, KLOCK_LEVEL_FD) != 0) return -1;
    if (klock_order_ok(KLOCK_LEVEL_RESOURCE, KLOCK_LEVEL_VFS) != 0)
        return -1;
    if (klock_order_ok(KLOCK_LEVEL_RESOURCE, KLOCK_LEVEL_MSI) != 0) return -1;
    if (klock_order_ok(KLOCK_LEVEL_PMM, KLOCK_LEVEL_PMM) != 0) return -1;
    if (klock_order_ok(KLOCK_LEVEL_PMM, KLOCK_LEVEL_POOL) != 0) return -1;
    if (klock_held_level() != 0) return -1;
    klock_acquire(&outer);
    if (klock_held_level() != KLOCK_LEVEL_NET) return -1;
    klock_acquire(&inner);
    if (klock_held_level() != KLOCK_LEVEL_PMM) return -1;
    klock_release(&inner);
    if (klock_held_level() != KLOCK_LEVEL_NET) return -1;
    klock_release(&outer);
    if (klock_held_level() != 0) return -1;
    return 0;
}

// Two ordinary pinned tasks on two CPUs at once. Both counts have to move
// inside one sampling window: that is what concurrent means here, and two
// sequential runs would not move both counts in the same window.
static int test_smp64_parallel(void) {
    const u32 index_a = SMP64_AP;
    const u32 index_b = SMP64_AP + 1;
    volatile u64 *ca = 0;
    volatile u64 *cb = 0;
    u64 a0;
    u64 b0;
    u64 a1;
    u64 b1;
    u32 slot_a;
    u32 slot_b;
    u32 both = 0;
    u64 current_a;
    u64 current_b;
    if (smp64_cpu_count() < 3) {
        serial64_write("Mich x86_64: SMP two-task parallel skipped (");
        serial64_hex(smp64_cpu_count());
        serial64_write(" cpus)\n");
        return 0;
    }
    u32 reason = 0;
    if (smp64_pin_task(index_a, smp64_spin_stub, sizeof(smp64_spin_stub),
                       &slot_a, (u64 **)&ca))
        return -1;
    if (smp64_pin_task(index_b, smp64_spin_stub, sizeof(smp64_spin_stub),
                       &slot_b, (u64 **)&cb)) {
        drop_pinned(slot_a, index_a);
        return -1;
    }
    ca[0] = 0;
    cb[0] = 0;
    apic64_delay_ms(20);
    if (ca[0] || cb[0] ||
        smp64_cpu_current(index_a) != SMP64_CURRENT_NONE ||
        smp64_cpu_current(index_b) != SMP64_CURRENT_NONE)
        reason = 1;
    if (!reason && (smp64_resched_cpu(index_a) || smp64_resched_cpu(index_b) ||
                    wait_counter(ca, 0) || wait_counter(cb, 0) ||
                    smp64_cpu_current(index_a) != slot_a ||
                    smp64_cpu_current(index_b) != slot_b))
        reason = 2;
    a0 = ca[0];
    b0 = cb[0];
    a1 = a0;
    b1 = b0;
    if (!reason) {
        // A starved vCPU can hold one window still, which reads exactly like a
        // task that never ran, so keep sampling until a window shows both
        // counters moving against that window's own base.
        for (u32 round = 0; round < SMP64_PARALLEL_ROUNDS; round++) {
            u64 base_a = ca[0];
            u64 base_b = cb[0];
            apic64_delay_ms(SMP64_PARALLEL_WINDOW_MS);
            a1 = ca[0];
            b1 = cb[0];
            if (a1 > base_a && b1 > base_b) {
                both = 1;
                break;
            }
            a1 = base_a;
            b1 = base_b;
        }
        if (!both) reason = 3;
        if (smp64_cpu_current(index_a) != slot_a ||
            smp64_cpu_current(index_b) != slot_b)
            reason = 4;
    } else {
        a1 = ca[0];
        b1 = cb[0];
    }
    // Same contract as the storm's failure line: a red run names the check
    // and the numbers it read instead of needing a second build.
    if (reason) {
        current_a = (u64)smp64_cpu_current(index_a);
        current_b = (u64)smp64_cpu_current(index_b);
        serial64_write("Mich x86_64: two-task parallel check failed: ");
        serial64_hex(reason);
        serial64_write(" a0="); serial64_hex(a0);
        serial64_write(" a1="); serial64_hex(a1);
        serial64_write(" b0="); serial64_hex(b0);
        serial64_write(" b1="); serial64_hex(b1);
        serial64_write(" cur_a="); serial64_hex(current_a);
        serial64_write(" cur_b="); serial64_hex(current_b);
        serial64_write(" slot_a="); serial64_hex(slot_a);
        serial64_write(" slot_b="); serial64_hex(slot_b);
        serial64_write("\n");
        drop_pinned(slot_a, index_a);
        drop_pinned(slot_b, index_b);
        return -1;
    }
    serial64_write("Mich x86_64: SMP two-task parallel pass (d1=");
    serial64_hex(a1 - a0);
    serial64_write(" d2=");
    serial64_hex(b1 - b0);
    serial64_write(")\n");
    if (drop_pinned(slot_a, index_a)) return -1;
    if (drop_pinned(slot_b, index_b)) return -1;
    return 0;
}

// Two CPU-bound tasks with a fixed amount of work each: the same turn
// count has to be reached once with the pair sharing a CPU and once with a
// CPU each, so the ratio of the two wall times is the speedup. The wall
// time is guest TSC ticks, and the turns are the stub's own increments.
#define SPEEDUP_TURNS 20000000ull
#define SPEEDUP_DEADLINE_MS 8000
#define SPEEDUP_QUANTUM_MS 10

// The measured pair should have the host to itself, and a spinning BSP
// takes a core from it. A ring-0 tick is accounted and returns without
// touching a task context, so this waits in hlt between ticks and leaves
// the caller's interrupt state alone.
static void speedup_wait_ms(u64 milliseconds) {
    u64 deadline = apic64_tsc_now() +
                   time64_ticks_from_ns((u64)milliseconds * 1000000u);
    while (apic64_tsc_now() < deadline)
        __asm__ volatile("sti; hlt; cli" ::: "memory");
}

static void speedup_line(const char *label, u64 us) {
    serial64_write("Mich x86_64: SMP speedup ");
    serial64_write(label);
    serial64_write(" us=");
    serial64_hex(us);
    serial64_write("\n");
}

// Polls the pair until both reach the turn count, kicking a shared pair so
// it alternates the way a tick would. Pinning is the caller's CPU choice.
static int speedup_work(u32 index_a, u32 index_b, u64 *us_out) {
    volatile u64 *ca = 0;
    volatile u64 *cb = 0;
    u64 start;
    u64 stop;
    u64 done = 0;
    u32 slot_a;
    u32 slot_b;
    u32 elapsed;
    if (smp64_pin_task(index_a, smp64_spin_stub, sizeof(smp64_spin_stub),
                       &slot_a, (u64 **)&ca))
        return -1;
    if (smp64_pin_task(index_b, smp64_spin_stub, sizeof(smp64_spin_stub),
                       &slot_b, (u64 **)&cb)) {
        drop_pinned(slot_a, index_a);
        return -1;
    }
    ca[0] = 0;
    cb[0] = 0;
    if (smp64_resched_cpu(index_a) || wait_counter(ca, 0)) {
        drop_pinned(slot_a, index_a);
        drop_pinned(slot_b, index_b);
        return -1;
    }
    if (index_b != index_a &&
        (smp64_resched_cpu(index_b) || wait_counter(cb, 0))) {
        drop_pinned(slot_a, index_a);
        drop_pinned(slot_b, index_b);
        return -1;
    }
    start = apic64_tsc_now();
    for (elapsed = 0; elapsed < SPEEDUP_DEADLINE_MS;
         elapsed += SPEEDUP_QUANTUM_MS) {
        if (ca[0] >= SPEEDUP_TURNS && cb[0] >= SPEEDUP_TURNS) {
            done = 1;
            break;
        }
        speedup_wait_ms(SPEEDUP_QUANTUM_MS);
        if (index_b == index_a && smp64_resched_cpu(index_a)) break;
    }
    stop = apic64_tsc_now();
    if (drop_pinned(slot_a, index_a)) return -1;
    if (drop_pinned(slot_b, index_b)) return -1;
    if (!done) return -1;
    // The TSC runs at a fixed 1 GHz for the emulated CPU, the same rate
    // apic64_delay_ms is built on.
    *us_out = (stop - start) / 1000u;
    return 0;
}

// The claim as a number: two tasks doing the same fixed work take less wall
// time on two CPUs than while sharing one. The table this feeds is a QEMU
// measurement, so it is labelled as one.
static int test_smp64_speedup(void) {
    u64 shared_us = 0;
    u64 split_us = 0;
    if (speedup_work(SMP64_AP, SMP64_AP, &shared_us)) {
        serial64_write("Mich x86_64: SMP speedup shared pair failed\n");
        return -1;
    }
    speedup_line("two-tasks one-cpu", shared_us);
    if (smp64_cpu_count() < 3) {
        serial64_write("Mich x86_64: SMP speedup two-tasks two-cpu skipped\n");
        return 0;
    }
    if (speedup_work(SMP64_AP, SMP64_AP + 1, &split_us)) {
        serial64_write("Mich x86_64: SMP speedup split pair failed\n");
        return -1;
    }
    serial64_write("Mich x86_64: SMP speedup two-tasks two-cpu us=");
    serial64_hex(split_us);
    serial64_write(" x100=");
    serial64_hex(split_us ? (shared_us * 100u) / split_us : 0);
    serial64_write("\n");
    // The ratio is printed, not asserted: the host this runs on has fewer
    // cores than the guest has CPUs, so what the split pair saves is the
    // host's to give. Both pairs still had to reach the turn count.
    return 0;
}

int tests64_run_smp(void) {
    irq_state_t irq_state = irq_save();
    if (smp64_cpu_count() < 2) {
        irq_restore(irq_state);
        return 0;
    }
    if (test_report_record(TEST_ID_SMP_IPI, test_smp64_ipi())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP IPI round-trip pass\n");
    if (test_report_record(TEST_ID_SMP_SPIN, test_smp64_spin())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP spinlock stress pass\n");
    if (test_report_record(TEST_ID_SMP_TIMER, test_smp64_timer())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP AP timer pass\n");
    if (test_report_record(TEST_ID_SMP_TSS, test_smp64_tss())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP per-CPU TSS pass\n");
    if (test_report_record(TEST_ID_SMP_CURRENT, test_smp64_current())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP per-CPU current pass\n");
    if (test_report_record(TEST_ID_SMP_SYSCALL, test_smp64_syscall())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP per-CPU syscall pass\n");
    if (test_report_record(TEST_ID_SMP_USER, test_smp64_user())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP AP userspace pass\n");
    if (test_report_record(TEST_ID_SMP_USER_IRQ, test_smp64_user_irq())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP AP user IRQ pass\n");
    serial64_write("Mich x86_64: SMP AP preempt pass\n");
    if (test_report_record(TEST_ID_SMP_LIVE, test_smp64_live())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP AP live syscall pass\n");
    if (test_report_record(TEST_ID_SMP_SCHED, test_smp64_schedule())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP AP scheduler pass\n");
    if (test_report_record(TEST_ID_SMP_PINNED, test_smp64_pinned())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP AP pinned task pass\n");
    if (test_report_record(TEST_ID_SMP_CONTAIN, test_smp64_contain())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP AP syscall containment pass\n");
    if (test_report_record(TEST_ID_SMP_ALLOC, test_smp64_alloc_concur())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP allocator concurrency pass\n");
    if (test_report_record(TEST_ID_SMP_REFCOUNT,
                           test_smp64_refcount_concur())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP refcount concurrency pass\n");
    if (test_report_record(TEST_ID_SMP_SPAWN, test_smp64_spawn())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP spawn storm pass\n");
    if (test_report_record(TEST_ID_SMP_NET, test_smp64_net_storm())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP net receive storm pass\n");
    if (test_report_record(TEST_ID_SMP_MAILBOX, test_smp64_rx_mailbox())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP receive mailbox pass\n");
    if (test_report_record(TEST_ID_SMP_RESOURCE, test_smp64_resource_storm())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP resource storm pass\n");
    if (test_report_record(TEST_ID_SMP_DOMAIN_STORM,
                           test_smp64_domain_storm())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP driver domain storm pass\n");
    if (test_report_record(TEST_ID_SMP_MODULE_STORM,
                           test_smp64_module_storm())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP driver module storm pass\n");
    if (test_report_record(TEST_ID_SMP_VECTOR, test_smp64_vector_storm())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP vector storm pass\n");
    if (test_report_record(TEST_ID_SMP_COW_STORM, test_smp64_cow_storm())) {
        irq_restore(irq_state);
        return -1;
    }
    // Reports one line per driver count: the aggregate is the claim, and a
    // pass line on its own would not carry the numbers the table needs.
    if (test_report_record(TEST_ID_SMP_NET_BENCH, test_smp64_net_bench())) {
        irq_restore(irq_state);
        return -1;
    }
    if (test_report_record(TEST_ID_SMP_LOCKORDER, test_smp64_lockorder())) {
        irq_restore(irq_state);
        return -1;
    }
    serial64_write("Mich x86_64: SMP lock order pass\n");
    // This one reports its own pass line: the counts it measured are part
    // of the claim, and at two CPUs it says it was skipped instead.
    if (test_report_record(TEST_ID_SMP_PARALLEL, test_smp64_parallel())) {
        irq_restore(irq_state);
        return -1;
    }
    if (test_report_record(TEST_ID_SMP_SPEEDUP, test_smp64_speedup())) {
        irq_restore(irq_state);
        return -1;
    }
    // Last in the battery on purpose: the counts are cumulative from boot,
    // so this is the only point that has seen the storms above it.
    if (test_report_record(TEST_ID_SMP_LOCK_CONTEND,
                           test_smp64_lock_contention())) {
        irq_restore(irq_state);
        return -1;
    }
    irq_restore(irq_state);
    return 0;
}
