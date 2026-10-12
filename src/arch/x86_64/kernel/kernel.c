#include "types.h"
#include "bootinfo.h"
#include "version.h"
#include "vm64.h"
#include "elf64.h"
#include "task.h"
#include "arch_task.h"
#include "posix_fd.h"
#include "posix_socket.h"
#include "posix_tty.h"
#include "posix_pgroup.h"
#include "posix_profile.h"
#include "posix_process.h"
#include "posix_time.h"
#include "posix_signal.h"
#include "posix_poll.h"
#include "posix_pledge.h"
#include "entropy.h"
#include "spinlock.h"
#include "scheduler.h"
#include "service.h"
#include "capability.h"
#include "pmm.h"
#include "ipc64.h"
#include "protos.h"
#include "runtime64.h"
#include "gdt64.h"
#include "idt64.h"
#include "serial64.h"
#include "object.h"
#include "resource.h"
#include "iommu.h"
#include "acpi64.h"
#include "rtc64.h"
#include "time64.h"
#include "vtd64.h"
#include "amd_iommu64.h"
#include "pci64.h"

#include "platform64.h"
#include "driver.h"
#include "driver_supervisor.h"
#include "driver_manager.h"
#include "event.h"
#include "endpoint.h"
#include "bridge.h"
#include "vector64.h"
#include "apic64.h"
#include "smp64.h"
#include "msi64.h"
#include "msix64.h"
#include "handle_transfer.h"
#include "panic64.h"
#include "irq_group.h"
#include "sg.h"
#include "ring.h"
#include "completion.h"
#include "completion_abi.h"
#include "timer_object.h"
#include "wait_many.h"
#include "net_buffer.h"
#include "vnic.h"
#include "net_rx.h"
#include "net_interface.h"
#include "net_interface_abi.h"
#include "net_abi.h"
#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "icmpv6.h"
#include "udpv6.h"
#include "tcp.h"
#include "loopback.h"
#include "udp.h"
#include "route.h"
#include "socket.h"
#include "socket_abi.h"
#include "vfs.h"
#include "vfs_abi.h"
#include "firmware.h"
#include "firmware_abi.h"
#include "block.h"
#include "kernel64_internal.h"
#ifdef MICH_TEST_BUILD
#include "tests64.h"
#include "test_report.h"
#endif
#ifdef MICH_TEST_BUILD
// Keep the fixed test boot blob available for the live fault path. The
// marker text stays byte-for-byte what the harness expects, but the reason
// follows it: a panic that will not say what failed costs far more time to
// chase than the marker is worth.
#define KERNEL_PANIC(reason) \
    panic_str("kernel test failure: " reason)
#else
#define KERNEL_PANIC(reason) panic_str(reason)
#endif
#define MSR_EFER 0xC0000080u
#define MSR_STAR 0xC0000081u
#define MSR_LSTAR 0xC0000082u
#define MSR_FMASK 0xC0000084u
#define BOOT_MODULE_DRIVER_CIRCUIT_TEST (1u << 27)
#define BOOT_MODULE_DRIVER_RECOVERY_TEST (1u << 26)
#define BOOT_MODULE_UNIT_TEST (1u << 28)
#define BOOT_MODULE_DRIVER_RESTART_TEST (1u << 29)
#define BOOT_MODULE_HARDWARE_TEST (1u << 30)
#define BOOT_MODULE_PANIC_TEST (1u << 31)
#define BOOT_MODULE_ALLOW_UNCONFINED_DMA (1u << 24)
#define IOMMU_FAULT_BATCH 8
// The primary capsule's sole test ud2. Its link address depends on the capsule
// toolchain, so the build extracts it from the compiled capsule rather than
// hardcode a literal that silently rots across compilers.
#include "virtio_net_recovery_rip.h"

static const struct driver_manager_recovery_config
    virtio_net_recovery_catalog[] = {
    {
        { 2, 0, 0x564E4554ULL | (1ULL << 32) },
        {
            0x1AF4, 0x1000,
            { DRIVER_CRASH_USER_EXCEPTION, 134, 6, 0,
              VIRTIO_NET_RECOVERY_TEST_RIP, 0 }
        },
        { 0, 0 },
        1, 1, DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT, 0
    }
};

extern void syscall64_entry(void);
extern void user64_enter(u64 rip, u64 rsp, u64 argument,
                         u64 module_flags);
extern u8 _bss_end;

struct interrupt_frame64 {
    u64 r15;
    u64 r14;
    u64 r13;
    u64 r12;
    u64 r11;
    u64 r10;
    u64 r9;
    u64 r8;
    u64 rbp;
    u64 rdi;
    u64 rsi;
    u64 rdx;
    u64 rcx;
    u64 rbx;
    u64 rax;
    u64 rip;
    u64 cs;
    u64 rflags;
    u64 rsp;
    u64 ss;
};

struct task_context64 task_contexts[MAX_TASKS];
u32 current_task_slot;
u32 timer_ticks;

// Set by the wake hook when a task turns runnable, consumed by the device-IRQ
// return path: the precise signal that an IRQ unblocked someone. Without it a
// woken capsule waits for the next 10ms tick, which on single-core netbench costs
// ~9ms of wire latency (the only other runnable task is the ring-3 idle loop).
static u32 resched_pending;
#define SPAWN_IMAGE_MAX DRIVER_USER_IMAGE_MAX
// Stack pages for a spawned user image. One page overflows a TLS client that
// verifies an RSA-4096 anchor; eight leaves headroom, and the unmapped page above
// the top still guards overflow.
#define SPAWN_STACK_PAGES 8u
static const u8 *spawn_images[SPAWN_IMAGE_MAX];
static u32 spawn_image_sizes[SPAWN_IMAGE_MAX];
static u32 spawn_image_capabilities[SPAWN_IMAGE_MAX];
static u32 spawn_image_flags[SPAWN_IMAGE_MAX];
static u32 spawn_image_count;

static int supervisor64_spawn(const struct driver_domain *domain);
static int supervisor64_quiesce(struct kernel_object *device);
static int supervisor64_reset(struct kernel_object *device);
static int supervisor64_revoke(int pid, u32 domain_id,
    const struct driver_domain_resource *resources, u32 count);
static int supervisor64_terminate(int pid);
static int supervisor64_release(struct driver_domain *domain);
static paddr_t highmem_probe;
static struct ethernet_port runtime_loop_port;
static struct ipv4_context runtime_loop_ipv4;
static struct loopback_context runtime_loopback;
static struct icmp_context runtime_icmp;
static struct udp_context runtime_udp;
static struct route_table runtime_routes;
static struct kernel_object *platform_mmio[ACPI_MAX_IOAPICS + 1];
static struct kernel_object *platform_irq[16];
static u32 platform_mmio_count;
// Total number of scheduler64_switch() calls since boot. Exposed for
// benchmarking (e.g. to estimate the FPU save/load cost of the lazy-FPU
// optimization, which saves one fxsave+fxrstor pair per switch).
static u64 switch_count;
u64 scheduler64_switch_count(void) {
    return switch_count;
}

static u64 rdmsr(u32 msr) {
    u32 lo;
    u32 hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((u64)hi << 32) | lo;
}

static void wrmsr(u32 msr, u64 value) {
    __asm__ volatile("wrmsr" : : "c"(msr), "a"((u32)value),
                     "d"((u32)(value >> 32)));
}

int serial64_user_write(u64 address) {
    if (address < VM64_PROGRAM_BASE || address >= VM64_PROGRAM_LIMIT) return -1;
    u64 remaining = VM64_PROGRAM_LIMIT - address;
    if (remaining > 256) remaining = 256;
    for (u64 index = 0; index < remaining; index++) {
        char value;
        if (vm64_copy_from(task_pool[current_task_slot].page_dir,
                           &value, address + index, 1))
            return -1;
        if (!value) return 0;
        serial64_putc(value);
    }
    return -1;
}

static int platform_resource_init(void) {
    const struct acpi_madt_info *madt = acpi64_madt();
    if (!madt || !madt->local_apic_address ||
        madt->ioapic_count > ACPI_MAX_IOAPICS)
        return -1;
    platform_mmio_count = 0;
    platform_mmio[platform_mmio_count] =
        mmio_resource_create(madt->local_apic_address, 4096, MMIO_CACHE_UC);
    if (!platform_mmio[platform_mmio_count++]) return -1;
    for (u32 index = 0; index < madt->ioapic_count; index++) {
        platform_mmio[platform_mmio_count] =
            mmio_resource_create(madt->ioapics[index].address, 4096,
                                 MMIO_CACHE_UC);
        if (!platform_mmio[platform_mmio_count++]) return -1;
    }
    for (u32 irq = 0; irq < 16; irq++) {
        u32 gsi = irq;
        u32 trigger = IRQ_TRIGGER_EDGE;
        u32 polarity = IRQ_POLARITY_HIGH;
        for (u32 index = 0; index < madt->iso_count; index++) {
            const struct acpi_iso_info *override = &madt->overrides[index];
            if (override->bus != 0 || override->source != irq) continue;
            gsi = override->gsi;
            if (((override->flags >> 2) & 3) == 3)
                trigger = IRQ_TRIGGER_LEVEL;
            if ((override->flags & 3) == 3)
                polarity = IRQ_POLARITY_LOW;
            break;
        }
        platform_irq[irq] = irq_resource_create(gsi, 0x30 + irq,
                                                 trigger, polarity);
        if (!platform_irq[irq]) return -1;
    }
    return 0;
}

struct kernel_object *platform64_irq_object(u32 irq) {
    return irq < 16 ? platform_irq[irq] : 0;
}

// Copy interrupted ring-3 state from a device-IRQ/exception frame into a task
// context. Separate from interrupt_save/interrupt_load because exception_frame64
// carries a vector+error pair the general interrupt_frame64 helpers do not.
static void ap64_timer_preempt(struct interrupt_frame64 *frame);
static void ap64_resched(struct exception_frame64 *frame);
static void frame64_save_user(struct task_context64 *context,
                              const struct exception_frame64 *frame) {
    context->rax = frame->rax;
    context->rbx = frame->rbx;
    context->rcx = frame->rcx;
    context->rdx = frame->rdx;
    context->rsi = frame->rsi;
    context->rdi = frame->rdi;
    context->rbp = frame->rbp;
    context->r8 = frame->r8;
    context->r9 = frame->r9;
    context->r10 = frame->r10;
    context->r11 = frame->r11;
    context->r12 = frame->r12;
    context->r13 = frame->r13;
    context->r14 = frame->r14;
    context->r15 = frame->r15;
    context->rsp = frame->rsp;
    context->rip = frame->rip;
    context->rflags = frame->rflags;
}

// Load a task context back into a frame so iret resumes that task. The user
// selectors are reasserted because whatever we switch to always returns to
// ring 3 here.
static void frame64_load_user(struct exception_frame64 *frame,
                              const struct task_context64 *context) {
    frame->rax = context->rax;
    frame->rbx = context->rbx;
    frame->rcx = context->rcx;
    frame->rdx = context->rdx;
    frame->rsi = context->rsi;
    frame->rdi = context->rdi;
    frame->rbp = context->rbp;
    frame->r8 = context->r8;
    frame->r9 = context->r9;
    frame->r10 = context->r10;
    frame->r11 = context->r11;
    frame->r12 = context->r12;
    frame->r13 = context->r13;
    frame->r14 = context->r14;
    frame->r15 = context->r15;
    frame->rsp = context->rsp;
    frame->rip = context->rip;
    frame->rflags = context->rflags;
    frame->cs = 0x23;
    frame->ss = 0x1B;
}

// Switch on iret to the task the current IRQ just unblocked. Mirrors the BSP timer
// preempt but drives off the device-IRQ frame. Hard preconditions: only the BSP
// retires capsule MSIs; a ring-0 frame carries no SS/RSP so a save/load would
// corrupt the interrupted kernel context; and a different runnable task must exist.
static void irq64_preempt(struct exception_frame64 *frame) {
    u32 next;
    if (smp64_cpu_index() != 0) return;
    if ((frame->cs & 3) != 3) return;
    if (current_task_slot >= MAX_TASKS) return;
    next = scheduler64_next_slot();
    if (next == current_task_slot || task_pool[next].state != TASK_RUNNING)
        return;
    frame64_save_user(&task_contexts[current_task_slot], frame);
    fpu64_save(&task_contexts[current_task_slot]);
    scheduler64_set_running(next);
    fpu64_load(&task_contexts[current_task_slot]);
    frame64_load_user(frame, &task_contexts[current_task_slot]);
    vm64_activate(task_pool[current_task_slot].page_dir);
}

// The console's receive side. The UART is armed for the received-data
// interrupt only: the transmit path stays polled and non-blocking, because
// serial64_putc deliberately never touches the line status while writing.
// COM1 is the console's own port and the line the guest answers on; the
// console wire profile moves the receive side to COM2 instead, so a rig can
// type into the machine while the console stays a plain file the runner
// logs. The discipline sees bytes either way and cannot tell them apart.
#define CONSOLE_UART_BASE 0x3F8u
#define CONSOLE_UART_ALT_BASE 0x2F8u
#define CONSOLE_UART_IRQ 4u
#define CONSOLE_UART_ALT_IRQ 3u

// The line the receive drain reads and the vector that arms it, chosen once
// at boot: the console's own port unless the boot asked for the alternate.
static u16 console64_rx_port = CONSOLE_UART_BASE;
static u32 console64_rx_irq = CONSOLE_UART_IRQ;

static inline void console64_outb(u16 port, u8 value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline u8 console64_inb(u16 port) {
    u8 value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

// A host that has a line for the guest raises the received-data interrupt;
// a virtual machine with no console peer simply never raises it and the
// input path stays idle. The divisor is the firmware's 115200, re-armed
// here because the firmware's own setup runs before it hands over.
static int console64_uart_init(void) {
    u16 base = console64_rx_port;
    console64_outb((u16)(base + 3u), 0x80);
    console64_outb(base, 0x01);
    console64_outb((u16)(base + 1u), 0x00);
    console64_outb((u16)(base + 3u), 0x03);
    // The FIFO is enabled and cleared so one interrupt carries a line
    // rather than a byte, which is what keeps a fast host from burying
    // the drain in interrupts.
    console64_outb((u16)(base + 2u), 0xC7);
    console64_outb((u16)(base + 4u), 0x0B);
    console64_outb((u16)(base + 1u), 0x01);
    (void)console64_inb(base);
    return 0;
}

// The receive line opens once the interrupt controllers exist: boot routes
// every legacy line masked, because a line only opens when somebody binds
// it, and the console is the kernel's own line with nothing to bind it.
static int console64_wire_init(u64 boot_flags) {
    if (boot_flags & BD_MODULE_TTY_WIRE) {
        console64_rx_port = CONSOLE_UART_ALT_BASE;
        console64_rx_irq = CONSOLE_UART_ALT_IRQ;
    }
    if (console64_uart_init()) return -1;
    return platform64_irq_enable(console64_rx_irq);
}

// One drain. A byte whose line status carries an error bit is dropped with
// its byte rather than fed to the discipline, a control character goes to
// the line's group as a signal and never reaches the queue, and everything
// else lands in the line discipline, echo included, which is what
// completes a parked read. The guard bounds the loop so a line that keeps
// claiming data cannot hold the IRQ forever.
static void console64_rx_drain(void) {
    for (u32 guard = 0; guard < 256u; guard++) {
        u8 status = console64_inb((u16)(console64_rx_port + 5u));
        if (!(status & 0x01u)) break;
        u8 byte = console64_inb(console64_rx_port);
        if (status & 0x1Eu) continue;
        u32 event = posix_tty_input_byte(0, byte);
        if (event) posix_tty_deliver(0, event);
    }
    // The drain runs on the interrupted task's own stack, and a control
    // character can stop or kill that very task: the IRQ return then has
    // to switch away instead of resuming a task that left the runnable
    // set. The preempt path only does so for a ring-3 interruption, which
    // is where a user typing at the console finds its task.
    if (task_pool[current_task_slot].state != TASK_RUNNING) resched_pending = 1;
}

void irq64_dispatch(struct exception_frame64 *frame) {
    u64 vector = frame->vector;
    // Only wakes raised inside this dispatch should preempt: clear first so
    // a leftover flag from a timer-tick timeout wake cannot trigger a bogus
    // switch on the next unrelated device IRQ.
    resched_pending = 0;
    if (vector >= 0x30 && vector < 0x40) {
        for (u32 irq = 0; irq < 16; irq++) {
            struct kernel_object *object = platform_irq[irq];
            struct irq_resource *resource = irq_resource_get(object);
            if (!resource || resource->vector != vector) continue;
            // The console's receive line is the kernel's own: it has no
            // userspace driver to answer the event or unmask the line
            // again, so IRQ 4 is drained below and left open.
            if (irq != console64_rx_irq) {
                irq_resource_signal(object);
                irq_resource_set_mask(object, 1);
            }
            break;
        }
    } else if (vector >= SMP64_IPI_FIRST && vector <= SMP64_IPI_LAST) {
        smp64_ipi_dispatch((u32)vector);
    } else if (vector >= VECTOR64_MSI_FIRST && vector <= VECTOR64_MSI_LAST) {
        struct kernel_object *object =
            (struct kernel_object *)vector64_owner((u8)vector);
        if (object && object->active && object->type == KOBJECT_IRQ) {
            irq_resource_signal(object);
            irq_resource_set_mask(object, 1);
        }
    }
    if (vector == 0x30u + console64_rx_irq) console64_rx_drain();
    // A device IRQ that unblocked a task hands the CPU over on iret instead
    // of resuming the interrupted ring-3 task until the next timer tick.
    // An AP answers to its own record only: resched_pending and
    // current_task_slot are the BSP's state, and a reschedule IPI to an AP
    // is that CPU's own call.
    if (smp64_cpu_index() != 0) {
        if (smp64_take_resched())
            ap64_resched(frame);
        return;
    }
    if (smp64_take_resched()) resched_pending = 1;
    if (resched_pending)
        irq64_preempt(frame);
}

static int supervisor64_resource(
    struct driver_domain *domain, const struct driver_user_request *request,
    struct kernel_object **objects, u32 capacity) {
    if (!domain || !request || !objects || !capacity) return -1;
    if (request->kind == DRIVER_RESOURCE_BAR) {
        objects[0] = pci64_bar_create(domain->device, request->index);
        return objects[0] ? 1 : -1;
    }
    if (request->kind == DRIVER_RESOURCE_DMA) {
        // Fail closed: without an IOMMU to confine it, a DMA grant is raw
        // physical R/W. Only a boot opt-in (dev/QEMU images with no VT-d or
        // AMD-Vi) permits unconfined DMA; otherwise deny the grant.
        if (!iommu_dma_permitted()) return -1;
        objects[0] = dma_resource_allocate((u32)request->amount,
                                           (paddr_t)request->limit);
        if (!objects[0]) return -1;
        if (iommu_present()) {
            if (!iommu_domain_exists(domain->id) &&
                iommu_domain_create(domain->id, domain->device)) {
                object_release(objects[0]);
                objects[0] = 0;
                return -1;
            }
            const struct dma_resource *dma = dma_resource_get(objects[0]);
            u64 iova = 0;
            if (!dma || iommu_domain_map(
                    domain->id, dma->physical, dma->pages, &iova) ||
                iova > request->limit ||
                dma->pages * 4096ULL - 1 > request->limit - iova ||
                dma_resource_bind_iommu(objects[0], domain->id, iova)) {
                if (iova) iommu_domain_unmap(domain->id, iova, dma->pages);
                object_release(objects[0]);
                objects[0] = 0;
                return -1;
            }
        }
        return 1;
    }
    if (request->kind == DRIVER_RESOURCE_IRQ) {
        objects[0] = platform64_irq_object(request->index);
        return objects[0] && !object_retain(objects[0]) ? 1 : -1;
    }
    if (request->kind == DRIVER_RESOURCE_MSI) {
        u32 count = (u32)request->amount;
        return count <= capacity &&
               !msi64_create_group(domain->device, count, objects, capacity)
            ? (int)count : -1;
    }
    if (request->kind == DRIVER_RESOURCE_MSIX_TABLE) {
        objects[0] = pci64_msix_table_create(domain->device);
        return objects[0] ? 1 : -1;
    }
    if (request->kind == DRIVER_RESOURCE_MSIX_IRQ) {
        u32 count = (u32)request->amount;
        for (u32 index = 0; index < domain->resource_count; index++)
            if (domain->resources[index].kind == DRIVER_RESOURCE_MSIX_TABLE)
                return count <= capacity && !msix64_create_group(
                    domain->resources[index].object, request->index,
                    count, objects, capacity) ? (int)count : -1;
    }
    return -1;
}

static const struct driver_manager_recovery_config *
manager64_recovery_catalog_lookup(u16 vendor_id, u16 device_id) {
    for (u32 index = 0;
         index < sizeof(virtio_net_recovery_catalog) /
                     sizeof(virtio_net_recovery_catalog[0]);
         index++) {
        const struct driver_manager_recovery_config *config =
            &virtio_net_recovery_catalog[index];
        if (config->fallback_selector.vendor_id == vendor_id &&
            config->fallback_selector.device_id == device_id)
            return config;
    }
    return 0;
}

static int manager64_register_virtio_net(int external_probe, int restart_test,
                                         int circuit_test, int recovery_test) {
    if ((circuit_test && !restart_test) ||
        (recovery_test && (!restart_test || circuit_test || !external_probe)))
        return -1;
    if (spawn_image_count < (recovery_test ? 3u : 2u)) return 0;
    struct driver_user_manifest manifest;
    u8 *bytes = (u8 *)&manifest;
    for (usize_t index = 0; index < sizeof(manifest); index++) bytes[index] = 0;
    manifest.abi_version = DRIVER_USER_ABI_VERSION;
    manifest.size = sizeof(manifest);
    const char name[] = "virtio-net";
    for (u32 index = 0; name[index]; index++) manifest.name[index] = name[index];
    manifest.restart_policy = DRIVER_RESTART_ON_FAILURE;
    manifest.max_restarts = 4;
    manifest.backoff_ticks = 10;
    manifest.priority = 1;
    manifest.image_id = 1;
    manifest.reset_policy = DRIVER_RESET_IF_SUPPORTED;
    manifest.firmware_count = 1;
    const char firmware_name[] = "virtio-net";
    for (u32 index = 0; firmware_name[index]; index++)
        manifest.firmware[0][index] = firmware_name[index];
    manifest.argument = 0x564E4554ULL |
        (external_probe ? 1ULL << 32 : 0) |
        (restart_test ? 1ULL << 33 : 0) |
        (circuit_test ? 1ULL << 34 : 0) |
        (recovery_test ? 1ULL << 35 : 0);
    manifest.match_count = 2;
    for (u32 index = 0; index < manifest.match_count; index++) {
        manifest.matches[index].vendor_id = 0x1AF4;
        manifest.matches[index].device_id = index ? 0x1041 : 0x1000;
        manifest.matches[index].class_code = 2;
        manifest.matches[index].subclass = 0;
        manifest.matches[index].programming_interface = 0xFF;
    }
    // The capsule drives the transport in userspace over libvirtio: it opens the
    // BARs at runtime through PCI CONTROL and DMAs the split rings through a
    // granted region, while MSI-X stays for interrupt-driven RX/TX wakeups.
    manifest.request_count = 5;
    manifest.requests[0].kind = DRIVER_RESOURCE_PCI;
    manifest.requests[0].rights = KRIGHT_READ | KRIGHT_CONTROL;
    manifest.requests[1].kind = DRIVER_RESOURCE_MSIX_TABLE;
    manifest.requests[1].rights = KRIGHT_READ | KRIGHT_CONTROL;
    manifest.requests[2].kind = DRIVER_RESOURCE_MSIX_IRQ;
    manifest.requests[2].rights = KRIGHT_WAIT | KRIGHT_CONTROL;
    manifest.requests[2].amount = 3;
    manifest.requests[3].kind = DRIVER_RESOURCE_BRIDGE;
    manifest.requests[3].rights = KRIGHT_READ | KRIGHT_WAIT;
    manifest.requests[4].kind = DRIVER_RESOURCE_DMA;
    // Two 2-page split rings (RX then TX) back to back (VIRTIO_NET_VRING_PAGES).
    manifest.requests[4].amount = 4;
    manifest.requests[4].limit = 0xFFFFFFFFULL;
    manifest.requests[4].rights = KRIGHT_READ | KRIGHT_WRITE | KRIGHT_MAP;
    if (!recovery_test) return driver_manager_register(&manifest) > 0 ? 0 : -1;

    const struct driver_manager_recovery_config *recovery =
        manager64_recovery_catalog_lookup(0x1AF4, 0x1000);
    return recovery && driver_manager_register_recovery(&manifest, recovery) > 0
        ? 0 : -1;
}

// Registered only when a "virtio-blk" boot module is present, so ordinary images
// keep driving virtio-blk in-kernel. Wildcards the class triplet since
// 0x1042/0x1001 already identify virtio-blk uniquely.
static int manager64_register_virtio_blk(u32 image_id) {
    struct driver_user_manifest manifest;
    u8 *bytes = (u8 *)&manifest;
    for (usize_t index = 0; index < sizeof(manifest); index++) bytes[index] = 0;
    manifest.abi_version = DRIVER_USER_ABI_VERSION;
    manifest.size = sizeof(manifest);
    const char name[] = "virtio-blk";
    for (u32 index = 0; name[index]; index++) manifest.name[index] = name[index];
    manifest.restart_policy = DRIVER_RESTART_ON_FAILURE;
    manifest.max_restarts = 4;
    manifest.backoff_ticks = 10;
    manifest.priority = 1;
    manifest.image_id = image_id;
    manifest.reset_policy = DRIVER_RESET_IF_SUPPORTED;
    manifest.firmware_count = 0;
    // Must match the capsule's VIRTIO_BLK_MAGIC ("VBLK") entry check.
    manifest.argument = 0x56424C4BULL;
    manifest.match_count = 2;
    for (u32 index = 0; index < manifest.match_count; index++) {
        manifest.matches[index].vendor_id = 0x1AF4;
        manifest.matches[index].device_id = index ? 0x1001 : 0x1042;
        manifest.matches[index].class_code = 0xFF;
        manifest.matches[index].subclass = 0xFF;
        manifest.matches[index].programming_interface = 0xFF;
    }
    // The capsule opens the transport BARs at runtime through PCI CONTROL and
    // polls the used ring, so no BAR mapping or MSI-X vectors are granted.
    manifest.request_count = 3;
    manifest.requests[0].kind = DRIVER_RESOURCE_PCI;
    manifest.requests[0].rights = KRIGHT_READ | KRIGHT_CONTROL;
    manifest.requests[1].kind = DRIVER_RESOURCE_DMA;
    // 2 pages hold the split ring for queue-size 128 with room to grow to 256
    // (VIRTIO_BLK_VRING_PAGES in capsule.h).
    manifest.requests[1].amount = 2;
    manifest.requests[1].limit = 0xFFFFFFFFULL;
    manifest.requests[1].rights = KRIGHT_READ | KRIGHT_WRITE | KRIGHT_MAP;
    manifest.requests[2].kind = DRIVER_RESOURCE_BRIDGE;
    manifest.requests[2].rights = KRIGHT_READ | KRIGHT_WAIT;
    return driver_manager_register(&manifest) > 0 ? 0 : -1;
}

// Registered only when an "nvme" boot module is present, so ordinary images keep
// driving NVMe in-kernel. Matches the NVMe class triplet (01/08/02) and
// wildcards vendor and device, since any NVMe controller is fair game. The
// capsule polls completions, so no MSI-X vectors are granted.
static int manager64_register_nvme(u32 image_id) {
    struct driver_user_manifest manifest;
    u8 *bytes = (u8 *)&manifest;
    for (usize_t index = 0; index < sizeof(manifest); index++) bytes[index] = 0;
    manifest.abi_version = DRIVER_USER_ABI_VERSION;
    manifest.size = sizeof(manifest);
    const char name[] = "nvme";
    for (u32 index = 0; name[index]; index++) manifest.name[index] = name[index];
    manifest.restart_policy = DRIVER_RESTART_ON_FAILURE;
    manifest.max_restarts = 4;
    manifest.backoff_ticks = 10;
    manifest.priority = 1;
    manifest.image_id = image_id;
    manifest.reset_policy = DRIVER_RESET_IF_SUPPORTED;
    manifest.firmware_count = 0;
    // Must match the capsule's NVME_CAPSULE_MAGIC ("NVME") entry check.
    manifest.argument = 0x4E564D45ULL;
    manifest.match_count = 1;
    manifest.matches[0].vendor_id = 0xFFFF;
    manifest.matches[0].device_id = 0xFFFF;
    manifest.matches[0].class_code = 0x01;
    manifest.matches[0].subclass = 0x08;
    manifest.matches[0].programming_interface = 0x02;
    manifest.request_count = 4;
    manifest.requests[0].kind = DRIVER_RESOURCE_PCI;
    manifest.requests[0].rights = KRIGHT_READ | KRIGHT_CONTROL;
    manifest.requests[1].kind = DRIVER_RESOURCE_BAR;
    manifest.requests[1].index = 0;
    manifest.requests[1].rights = KRIGHT_READ | KRIGHT_WRITE | KRIGHT_MAP;
    manifest.requests[2].kind = DRIVER_RESOURCE_DMA;
    // 5 pages: admin SQ/CQ, I/O SQ/CQ, identify (NVME_QUEUES_PAGES in capsule.h).
    manifest.requests[2].amount = 5;
    manifest.requests[2].limit = 0xFFFFFFFFULL;
    manifest.requests[2].rights = KRIGHT_READ | KRIGHT_WRITE | KRIGHT_MAP;
    manifest.requests[3].kind = DRIVER_RESOURCE_BRIDGE;
    manifest.requests[3].rights = KRIGHT_READ | KRIGHT_WAIT;
    return driver_manager_register(&manifest) > 0 ? 0 : -1;
}

static int manager64_set_pci_inventory(void) {
    struct kernel_object *devices[DRIVER_MANAGER_DEVICE_MAX];
    u32 count = pci64_count();
    if (count > DRIVER_MANAGER_DEVICE_MAX) return -1;
    for (u32 index = 0; index < count; index++)
        devices[index] = pci64_object(index);
    return driver_manager_set_devices(devices, count) < 0 ? -1 : 0;
}

#ifdef MICH_TEST_BUILD
#define DRIVER_LIVE_RECOVERY_PRIMARY_ARGUMENT 21
#define DRIVER_LIVE_RECOVERY_FALLBACK_ARGUMENT 22
#define DRIVER_LIVE_RECOVERY_TIMEOUT_TICKS 128

#define DRIVER_LIVE_RECOVERY_WAIT_PRIMARY_READY 1
#define DRIVER_LIVE_RECOVERY_WAIT_PRIMARY_RESTART 2
#define DRIVER_LIVE_RECOVERY_WAIT_RESTARTED_READY 3
#define DRIVER_LIVE_RECOVERY_WAIT_FALLBACK 4
#define DRIVER_LIVE_RECOVERY_WAIT_FALLBACK_READY 5
#define DRIVER_LIVE_RECOVERY_FALLBACK_HOLD 6
#define DRIVER_LIVE_RECOVERY_COMPLETE 7

struct driver_live_recovery_test {
    struct driver_domain *domain;
    u32 phase;
    u32 deadline;
    u32 hold_deadline;
    int primary_pid;
    int restarted_pid;
    int fallback_pid;
    u32 primary_space;
    u32 restarted_space;
    u32 primary_handle;
    u32 restarted_handle;
    u32 rebind_gap;
    struct kernel_object *primary_bridge;
    struct kernel_object *restarted_bridge;
    u64 fault_rip;
};

static struct driver_live_recovery_test driver_live_recovery;

static int driver_live_recovery_context(int pid, u32 *space) {
    u32 slot = PID_SLOT((u32)pid);
    if (pid <= 0 || slot >= MAX_TASKS || task_pool[slot].id != pid ||
        task_pool[slot].state == TASK_ZOMBIE ||
        task_pool[slot].state == TASK_FREE || !task_contexts[slot].vm_valid)
        return -1;
    *space = task_contexts[slot].vm_space;
    return 0;
}

static int driver_live_recovery_stale(int pid, u32 handle) {
    u32 slot = PID_SLOT((u32)pid);
    if (pid <= 0 || !handle || slot >= MAX_TASKS) return 0;
    if (task_pool[slot].id != pid) return 1;
    return task_pool[slot].state == TASK_ZOMBIE &&
           !handle_get(&task_pool[slot], handle, KRIGHT_READ, KOBJECT_PCI) &&
           !handle_task_count(&task_pool[slot]);
}

static struct kernel_object *driver_live_recovery_bridge(int pid, u32 handle) {
    u32 slot = PID_SLOT((u32)pid);
    if (pid <= 0 || !handle || slot >= MAX_TASKS || task_pool[slot].id != pid ||
        task_pool[slot].state == TASK_ZOMBIE || task_pool[slot].state == TASK_FREE)
        return 0;
    return handle_get(&task_pool[slot], handle, KRIGHT_READ, KOBJECT_ENDPOINT);
}

static int driver_live_recovery_crash(
    const struct driver_domain_status *status, u32 generation, u64 rip) {
    return status->last_crash.kind == DRIVER_CRASH_USER_EXCEPTION &&
           status->last_crash.code == 134 && status->last_crash.generation == generation &&
           status->last_crash.vector == 6 && (!rip || status->last_crash.rip == rip);
}

static int driver_live_recovery_fresh(
    const struct driver_domain_status *status, u32 generation, int old_pid,
    u32 old_space, u32 old_handle, u32 *space) {
    if (status->state != DRIVER_DOMAIN_RUNNING) return -1;
    if (status->generation != generation) return -2;
    if (status->pid == old_pid) return -3;
    if (driver_live_recovery_context(status->pid, space)) return -4;
    if (*space == old_space) return -5;
    if (!driver_live_recovery_stale(old_pid, old_handle)) return -6;
    return 0;
}

static int driver_live_recovery_prepare(void) {
    if (!spawn_image_count ||
        !(spawn_image_capabilities[0] & CAP_SERVICE_REGISTER))
        return -1;
    struct driver_user_manifest manifest;
    u8 *bytes = (u8 *)&manifest;
    for (usize_t index = 0; index < sizeof(manifest); index++) bytes[index] = 0;
    manifest.abi_version = DRIVER_USER_ABI_VERSION;
    manifest.size = sizeof(manifest);
    const char *name = "mich.live.recovery";
    for (u32 index = 0; name[index]; index++) manifest.name[index] = name[index];
    manifest.capabilities = CAP_SERVICE_REGISTER;
    manifest.restart_policy = DRIVER_RESTART_ON_FAILURE;
    manifest.max_restarts = 1;
    manifest.backoff_ticks = 1;
    manifest.image_id = 0;
    manifest.reset_policy = DRIVER_RESET_NONE;
    manifest.argument = DRIVER_LIVE_RECOVERY_PRIMARY_ARGUMENT;
    manifest.match_count = 1;
    manifest.matches[0].vendor_id = 0x1AF4;
    manifest.matches[0].device_id = 0x1042;
    manifest.matches[0].class_code = 0xFF;
    manifest.matches[0].subclass = 0xFF;
    manifest.matches[0].programming_interface = 0xFF;
    manifest.request_count = 2;
    manifest.requests[0].kind = DRIVER_RESOURCE_PCI;
    manifest.requests[0].rights = KRIGHT_READ | KRIGHT_CONTROL;
    manifest.requests[1].kind = DRIVER_RESOURCE_BRIDGE;
    manifest.requests[1].rights = KRIGHT_READ | KRIGHT_WAIT;
    int manifest_id = driver_manager_register(&manifest);
    struct driver_recovery_profile fallback;
    fallback.image_id = 0;
    fallback.capabilities = 0;
    fallback.argument = DRIVER_LIVE_RECOVERY_FALLBACK_ARGUMENT;
    struct driver_crash_circuit_policy policy;
    policy.repeat_limit = DRIVER_CRASH_REPEAT_LIMIT + 1;
    policy.repeat_window_ticks = DRIVER_CRASH_REPEAT_WINDOW_TICKS;
    return manifest_id > 0 &&
           !driver_manager_set_recovery_fallback(manifest_id, &fallback) &&
           !driver_manager_set_recovery_fallback_triggers(
               manifest_id, DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT) &&
           !driver_manager_set_crash_circuit_policy(manifest_id, &policy) ? 0 : -1;
}

static int driver_live_recovery_arm(void) {
    struct kernel_object *device = 0;
    for (u32 index = 0; index < pci64_count(); index++) {
        struct kernel_object *candidate = pci64_object(index);
        const struct pci_resource *pci = pci_resource_get(candidate);
        if (pci && pci->vendor_id == 0x1AF4 &&
            pci->device_id == 0x1042) {
            device = candidate;
            break;
        }
    }
    struct driver_domain *domain = driver_manager_domain(device);
    struct driver_domain_status status;
    u32 handles[DRIVER_DOMAIN_RESOURCE_MAX];
    if (!device || !domain || driver_domain_status(domain, &status) ||
        status.state != DRIVER_DOMAIN_RUNNING || status.pid <= 0 ||
        status.generation != 1 || status.recovery_profile != DRIVER_RECOVERY_PRIMARY ||
        status.fallback_enabled != 1 || status.fallback_used ||
        status.fallback_triggers != DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT ||
        status.last_decision != DRIVER_RECOVERY_DECISION_START ||
        status.capabilities != CAP_SERVICE_REGISTER ||
        status.argument != DRIVER_LIVE_RECOVERY_PRIMARY_ARGUMENT ||
        driver_domain_bundle(domain, handles, DRIVER_DOMAIN_RESOURCE_MAX) != 2 ||
        !handles[0] || !handles[1] ||
        !(driver_live_recovery.primary_bridge =
          driver_live_recovery_bridge(status.pid, handles[1])) ||
        driver_live_recovery_context(status.pid,
                                     &driver_live_recovery.primary_space))
        return -1;
    driver_live_recovery.domain = domain;
    driver_live_recovery.phase = DRIVER_LIVE_RECOVERY_WAIT_PRIMARY_READY;
    driver_live_recovery.deadline = timer_ticks + DRIVER_LIVE_RECOVERY_TIMEOUT_TICKS;
    driver_live_recovery.primary_pid = status.pid;
    driver_live_recovery.primary_handle = handles[0];
    return 0;
}

static void driver_live_recovery_fail(void) {
    // A bare reason string cannot say which of the fourteen call sites
    // fired, and the phases are what distinguish a slow driver from a
    // broken handshake.
    serial64_write("Mich x86_64: live recovery failed phase=0x");
    serial64_hex(driver_live_recovery.phase);
    serial64_write(" ticks=0x");
    serial64_hex(timer_ticks);
    serial64_write(" deadline=0x");
    serial64_hex(driver_live_recovery.deadline);
    serial64_write("\n");
    KERNEL_PANIC("driver live recovery");
}

static __attribute__((cold, noinline, optimize("Os,no-jump-tables"))) void driver_live_recovery_tick(void) {
    struct driver_live_recovery_test *test = &driver_live_recovery;
    if (!test->phase || test->phase == DRIVER_LIVE_RECOVERY_COMPLETE) return;
    if ((i32)(timer_ticks - test->deadline) >= 0) driver_live_recovery_fail();
    struct driver_domain_status status;
    if (driver_domain_status(test->domain, &status)) driver_live_recovery_fail();
    if (test->phase == DRIVER_LIVE_RECOVERY_WAIT_PRIMARY_READY) {
        if (status.state != DRIVER_DOMAIN_RUNNING || status.generation != 1 ||
            status.pid != test->primary_pid)
            driver_live_recovery_fail();
        int owner = service_lookup(SERVICE_TEST);
        if (owner < 0) return;
        if (owner != status.pid ||
            endpoint_signal(test->primary_bridge, DRIVER_CONTROL_STOP))
            driver_live_recovery_fail();
        test->phase = DRIVER_LIVE_RECOVERY_WAIT_PRIMARY_RESTART;
        return;
    }
    if (test->phase == DRIVER_LIVE_RECOVERY_WAIT_PRIMARY_RESTART) {
        if (status.state == DRIVER_DOMAIN_RUNNING && status.generation == 1) return;
        if (driver_live_recovery_fresh(&status, 2, test->primary_pid,
                                       test->primary_space, test->primary_handle,
                                       &test->restarted_space) ||
            status.recovery_profile != DRIVER_RECOVERY_PRIMARY || status.fallback_used ||
            status.last_decision != DRIVER_RECOVERY_DECISION_RESTART ||
            status.capabilities != CAP_SERVICE_REGISTER ||
            !driver_live_recovery_crash(&status, 1, 0))
            driver_live_recovery_fail();
        u32 handles[2];
        test->restarted_pid = status.pid;
        if (driver_domain_bundle(test->domain, handles, 2) != 2 || !handles[0] ||
            !handles[1] ||
            !(test->restarted_bridge =
              driver_live_recovery_bridge(status.pid, handles[1])) ||
            test->restarted_bridge == test->primary_bridge ||
            endpoint_signal(test->primary_bridge, DRIVER_CONTROL_STOP) == 0)
            driver_live_recovery_fail();
        test->restarted_handle = handles[0];
        test->fault_rip = status.last_crash.rip;
        test->phase = DRIVER_LIVE_RECOVERY_WAIT_RESTARTED_READY;
        return;
    }
    if (test->phase == DRIVER_LIVE_RECOVERY_WAIT_RESTARTED_READY) {
        if (status.state != DRIVER_DOMAIN_RUNNING || status.generation != 2 ||
            status.pid != test->restarted_pid)
            driver_live_recovery_fail();
        int owner = service_lookup(SERVICE_TEST);
        if (owner < 0) {
            test->rebind_gap = 1;
            return;
        }
        // Observing the gap used to be mandatory, but it is a sampling
        // artifact: whether it is visible depends on the tick rate, and a
        // slower tick lets the restarted driver register before the first
        // sample. What has to hold is that the service now belongs to the
        // restarted driver and not to the one that was stopped.
        if (owner != status.pid || status.pid == test->primary_pid ||
            endpoint_signal(test->restarted_bridge, DRIVER_CONTROL_STOP))
            driver_live_recovery_fail();
        test->phase = DRIVER_LIVE_RECOVERY_WAIT_FALLBACK;
        return;
    }
    if (test->phase == DRIVER_LIVE_RECOVERY_WAIT_FALLBACK) {
        if (status.state == DRIVER_DOMAIN_RUNNING && status.generation == 2) return;
        u32 fallback_space;
        if (driver_live_recovery_fresh(&status, 3, test->restarted_pid,
                                       test->restarted_space, test->restarted_handle,
                                       &fallback_space) ||
            status.recovery_profile != DRIVER_RECOVERY_FALLBACK ||
            !status.fallback_enabled || !status.fallback_used ||
            status.fallback_triggers != DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT ||
            status.last_decision != DRIVER_RECOVERY_DECISION_FALLBACK ||
            status.capabilities ||
            status.argument != DRIVER_LIVE_RECOVERY_FALLBACK_ARGUMENT ||
            !driver_live_recovery_crash(&status, 2, test->fault_rip) ||
            service_lookup(SERVICE_TEST) >= 0)
            driver_live_recovery_fail();
        u32 handles[2];
        struct kernel_object *bridge = 0;
        if (driver_domain_bundle(test->domain, handles, 2) != 2 || !handles[1] ||
            !(bridge = driver_live_recovery_bridge(status.pid, handles[1])) ||
            bridge == test->restarted_bridge)
            driver_live_recovery_fail();
        test->fallback_pid = status.pid;
        test->deadline = timer_ticks + DRIVER_LIVE_RECOVERY_TIMEOUT_TICKS;
        test->phase = DRIVER_LIVE_RECOVERY_WAIT_FALLBACK_READY;
        return;
    }
    if (test->phase == DRIVER_LIVE_RECOVERY_WAIT_FALLBACK_READY ||
        test->phase == DRIVER_LIVE_RECOVERY_FALLBACK_HOLD) {
        if (status.state != DRIVER_DOMAIN_RUNNING ||
            status.generation != 3 || status.pid != test->fallback_pid ||
            status.recovery_profile != DRIVER_RECOVERY_FALLBACK ||
            !status.fallback_used ||
            status.fallback_triggers != DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT ||
            status.last_decision != DRIVER_RECOVERY_DECISION_FALLBACK ||
            status.capabilities ||
            status.argument != DRIVER_LIVE_RECOVERY_FALLBACK_ARGUMENT ||
            service_lookup(SERVICE_TEST) >= 0)
            driver_live_recovery_fail();
        if (test->phase == DRIVER_LIVE_RECOVERY_WAIT_FALLBACK_READY) {
            u32 fallback_slot = PID_SLOT((u32)test->fallback_pid);
            if (fallback_slot >= MAX_TASKS ||
                task_pool[fallback_slot].id != test->fallback_pid)
                driver_live_recovery_fail();
            if (task_pool[fallback_slot].state != TASK_BLOCKED_EVENT) return;
            test->hold_deadline = timer_ticks + 2;
            test->phase = DRIVER_LIVE_RECOVERY_FALLBACK_HOLD;
            return;
        }
        if ((i32)(timer_ticks - test->hold_deadline) < 0) return;
        serial64_write("Mich test64: driver live recovery isolation pass\n");
        if (task_pool[1].id != 1 || task_pool[2].id != 2)
            driver_live_recovery_fail();
        task_state_set(&task_pool[1], TASK_RUNNING);
        task_state_set(&task_pool[2], TASK_RUNNING);
        test->phase = DRIVER_LIVE_RECOVERY_COMPLETE;
        return;
    }
    driver_live_recovery_fail();
}

#endif

static int udp_unreachable_to_icmp(const struct ipv4_packet_view *packet,
                                   void *context) {
    return icmp_send_port_unreachable((struct icmp_context *)context, packet);
}

static int network_runtime_init(void) {
    const u8 address[6] = {0x02, 0x4D, 0x49, 0x43, 0x48, 0x7E};
    if (ethernet_port_init(&runtime_loop_port, address) ||
        ipv4_init(&runtime_loop_ipv4, &runtime_loop_port,
                  0x7F000001u, 0xFF000000u, 0))
        return -1;
    if (loopback_init(&runtime_loopback, &runtime_loop_ipv4, 32))
        return -1;
    if (icmp_init(&runtime_icmp, &runtime_loop_ipv4, 100, 64) ||
        udp_init(&runtime_udp, &runtime_loop_ipv4) ||
        udp_set_unreachable_callback(&runtime_udp,
                                     udp_unreachable_to_icmp,
                                     &runtime_icmp)) {
        loopback_destroy(&runtime_loopback);
        return -1;
    }
    route_init(&runtime_routes);
    net_rx_init();
    net_rx_set_kick(smp64_net_kick);
    if (net_interface_init(&runtime_routes)) {
        loopback_destroy(&runtime_loopback);
        return -1;
    }
    if (route_add(&runtime_routes, 0x7F000000u, 0xFF000000u, 0,
                  ROUTE_INTERFACE_LOOPBACK, 0) ||
        socket_init(&runtime_udp, &runtime_routes)) {
        loopback_destroy(&runtime_loopback);
        return -1;
    }
    return 0;
}

static void highmem_probe_finish(void) {
    if (!highmem_probe) return;
    volatile u64 *page = (volatile u64 *)(uptr_t)highmem_probe;
    if (page[0] != 0x4D49434848494748ULL ||
        page[1] != 0x5048595350414745ULL)
        KERNEL_PANIC("high memory identity map");
    page[0] = 0x5245555341424C45ULL;
    if (page[0] != 0x5245555341424C45ULL)
        KERNEL_PANIC("high memory write");
    pmm_free_page(highmem_probe);
    highmem_probe = 0;
    serial64_write("Mich x86_64: high memory identity pass\n");
}

static void syscall64_init(void) {
    smp64_syscall_prepare();
    u64 efer = rdmsr(MSR_EFER);
    wrmsr(MSR_EFER, efer | 1 | (1ULL << 11));
    wrmsr(MSR_STAR, (0x10ULL << 48) | (0x08ULL << 32));
    wrmsr(MSR_LSTAR, (u64)(uptr_t)syscall64_entry);
    wrmsr(MSR_FMASK, 0x600);
}

static void context_save(struct task_context64 *context) {
    struct smp64_syscall *sc = smp64_syscall();
    context->rax = 0;
    // The park resumes through an iret that restores rcx and r11, so the
    // save records the values sysret would have folded: after a syscall
    // instruction rcx is the resume rip and r11 the flags.
    context->rcx = sc->rip;
    context->r11 = sc->rflags;
    context->rdi = sc->rdi;
    context->rsi = sc->rsi;
    context->rdx = sc->rdx;
    context->r8 = sc->r8;
    context->r9 = sc->r9;
    context->r10 = sc->r10;
    context->rsp = sc->rsp;
    context->rip = sc->rip;
    context->rflags = sc->rflags;
    context->rbx = sc->rbx;
    context->rbp = sc->rbp;
    context->r12 = sc->r12;
    context->r13 = sc->r13;
    context->r14 = sc->r14;
    context->r15 = sc->r15;
}

void context_load(const struct task_context64 *context) {
    struct smp64_syscall *sc = smp64_syscall();
    // A context switch under a syscall must resume the task with its own
    // rax, rcx, and r11: the sysret path would replace rcx with the rip
    // and r11 with the flags. Publish them through the sigreturn slots
    // and raise the flag that reroutes the exit to the iret resume.
    sc->sigreturn_rax = context->rax;
    sc->sigreturn_rcx = context->rcx;
    sc->sigreturn_r11 = context->r11;
    sc->ctx_resume = 1;
    sc->rdi = context->rdi;
    sc->rsi = context->rsi;
    sc->rdx = context->rdx;
    sc->r8 = context->r8;
    sc->r9 = context->r9;
    sc->r10 = context->r10;
    sc->rsp = context->rsp;
    sc->rip = context->rip;
    sc->rflags = context->rflags;
    sc->rbx = context->rbx;
    sc->rbp = context->rbp;
    sc->r12 = context->r12;
    sc->r13 = context->r13;
    sc->r14 = context->r14;
    sc->r15 = context->r15;
    vm64_activate(task_pool[current_task_slot].page_dir);
}

static void fpu64_enable(void) {
    u64 cr0;
    u64 cr4;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~(1ULL << 2);
    cr0 |= 1ULL << 1;
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 9) | (1ULL << 10);
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(0), "c"(0));
    if (eax >= 7) {
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx),
                         "=c"(ecx), "=d"(edx) : "a"(7), "c"(0));
        if (ebx & (1u << 7)) cr4 |= 1ULL << 20;
        if (ebx & (1u << 20)) cr4 |= 1ULL << 21;
    }
    (void)ecx;
    (void)edx;
    __asm__ volatile("mov %0, %%cr4" : : "r"(cr4) : "memory");
}

void fpu64_save(struct task_context64 *context) {
    __asm__ volatile("fxsave (%0)" : : "r"(context->fxstate) : "memory");
}

void fpu64_load(const struct task_context64 *context) {
    __asm__ volatile("fxrstor (%0)" : : "r"(context->fxstate) : "memory");
}

static void fpu64_init_context(struct task_context64 *context) {
    u32 mxcsr = 0x1F80;
    __asm__ volatile("fninit");
    __asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
    fpu64_save(context);
}


static int spawn64_image(u32 image_id, int parent_id, u32 capabilities,
                         const char *name, u64 argument) {
    if (image_id >= SPAWN_IMAGE_MAX || image_id >= spawn_image_count ||
        (capabilities & ~spawn_image_capabilities[image_id]))
        return -1;
    struct task *task = task_alloc_slot();
    if (!task) return -1;
    u32 slot = (u32)(task - task_pool);
    struct task_context64 *context = &task_contexts[slot];
    u32 space;
    if (vm64_create_space(&space)) {
        task_free_slot(task);
        return -1;
    }
    context->vm_space = space;
    context->vm_valid = 1;
    vaddr_t entry;
    if (elf64_load(space, spawn_images[image_id],
                   spawn_image_sizes[image_id], &entry)) {
        task_free_slot(task);
        return -1;
    }
    // An RSA-4096 anchor validation (e.g. GTS Root R1) drives modexp deep enough
    // to overflow a single stack page. Map several below the top; the unmapped
    // guard above the top makes an overflow fault instead of corrupting the heap.
    vaddr_t stack_top = VM64_STACK_TOP;
    paddr_t stack_pages[SPAWN_STACK_PAGES];
    u32 stack_mapped = 0;
    while (stack_mapped < SPAWN_STACK_PAGES) {
        paddr_t page = vm64_alloc_page();
        if (!page) break;
        if (vm64_map(space, stack_top - (vaddr_t)(stack_mapped + 1u) * 4096u,
                     page, 1, 0)) {
            vm64_free_page(page);
            break;
        }
        stack_pages[stack_mapped++] = page;
    }
    if (stack_mapped != SPAWN_STACK_PAGES) {
        for (u32 index = 0; index < stack_mapped; index++)
            vm64_free_page(stack_pages[index]);
        task_free_slot(task);
        return -1;
    }
    task->ring = 3;
    task->page_dir = vm64_root(space);
    task->parent_id = parent_id;
    task->capabilities = capabilities;
    task_set_name(task, name);
    if ((spawn_image_flags[image_id] & BD_MODULE_POSIX_PROFILE) &&
        posix_profile_admit(task)) {
        task_free_slot(task);
        return -1;
    }
    context->rdi = argument;
    // The init image runs the same sequence in every profile, but only some spawn
    // it with the POSIX modules. Pass the flags so it skips what was never started.
    context->rsi = spawn_image_flags[image_id];
    context->rsp = stack_top;
    context->rip = entry;
    context->rflags = 0x202;
    context->user_break = VM64_HEAP_BASE;
    fpu64_init_context(context);
    return task->id;
}

int spawn64(int parent_id, u32 capabilities,
                   const char *name, u64 argument) {
    return spawn64_image(0, parent_id, capabilities, name, argument);
}

int fork64(void) {
    struct task *parent = &task_pool[current_task_slot];
    struct task_context64 *parent_context = &task_contexts[current_task_slot];
    if (!parent_context->vm_valid) return -1;
    struct task *child = task_alloc_slot();
    if (!child) return -1;
    u32 child_slot = (u32)(child - task_pool);
    u32 space;
    if (vm64_clone_space(parent_context->vm_space, &space)) {
        task_free_slot(child);
        return -1;
    }
    fpu64_save(parent_context);
    struct task_context64 *child_context = &task_contexts[child_slot];
    u8 *dst = (u8 *)child_context;
    const u8 *src = (const u8 *)parent_context;
    for (usize_t index = 0; index < sizeof(*child_context); index++)
        dst[index] = src[index];
    context_save(child_context);
    child_context->vm_space = space;
    child_context->vm_valid = 1;
    child_context->rax = 0;
    child->ring = 3;
    child->page_dir = vm64_root(space);
    child->parent_id = parent->id;
    child->capabilities = 0;
    task_set_name(child, parent->name);
    child->uid = parent->uid;
    child->gid = parent->gid;
    child->umask = parent->umask;
    if (posix_fd_fork(parent, child) || posix_profile_fork(parent, child)) {
        task_free_slot(child);
        return -1;
    }
    posix_signal_fork(parent, child);
    posix_pgroup_fork(parent, child);
    child->stop_report = 0;
    child->continued_report = 0;
    child->stop_answer = 0;
    child->stop_answer_set = 0;
    posix_pledge_fork(parent, child);
    return child->id;
}

int exec64(u64 path_address, u64 argument) {
    struct task *task = &task_pool[current_task_slot];
    struct task_context64 *context = &task_contexts[current_task_slot];
    if (!context->vm_valid) return EINVAL;
    char path[VFS_PATH_MAX];
    for (u32 index = 0; index < VFS_PATH_MAX; index++) path[index] = 0;
    u32 length = 0;
    for (;;) {
        char byte;
        if (length >= VFS_PATH_MAX - 1 ||
            vm64_copy_from(task->page_dir, &byte, path_address + length, 1))
            return EINVAL;
        path[length] = byte;
        if (!byte) break;
        length++;
    }
    if (!path[0] || path[0] != '/') return EINVAL;
    struct kernel_object *node = vfs_resolve(0, path);
    const u8 *image = 0;
    u32 size = 0;
    if (!node || vfs_image(node, &image, &size)) {
        if (node) object_release(node);
        return ENOENT;
    }
    u32 space;
    if (vm64_create_space(&space)) {
        object_release(node);
        return ENOMEM;
    }
    vaddr_t entry;
    if (elf64_load(space, image, size, &entry)) {
        vm64_destroy_space(space);
        object_release(node);
        return EINVAL;
    }
    paddr_t stack = vm64_alloc_page();
    if (!stack || vm64_map(space, VM64_STACK_TOP - 4096, stack, 1, 0)) {
        if (stack) vm64_free_page(stack);
        vm64_destroy_space(space);
        object_release(node);
        return ENOMEM;
    }
    object_release(node);
    posix_fd_close_cloexec(task);
    posix_profile_release(task);
    handle_close_all(task);
    u32 old_space = context->vm_space;
    context->vm_space = space;
    context->vm_valid = 1;
    task->page_dir = vm64_root(space);
    vm64_destroy_space(old_space);
    context->rax = 0;
    context->rbx = 0;
    context->rcx = 0;
    context->rdx = 0;
    context->rsi = 0;
    context->rdi = argument;
    context->rbp = 0;
    context->r8 = 0;
    context->r9 = 0;
    context->r10 = 0;
    context->r11 = 0;
    context->r12 = 0;
    context->r13 = 0;
    context->r14 = 0;
    context->r15 = 0;
    context->rsp = VM64_STACK_TOP;
    context->rip = entry;
    context->user_break = VM64_HEAP_BASE;
    context->rflags = 0x202;
    fpu64_init_context(context);
    task_set_name(task, path);
    return 0;
}

// Scratch for argv/envp staging plus the initial stack page. One static
// record under one lock: execve is rare, every path that holds the lock is
// bounded and non-sleeping, and no other lock is ever taken through it in
// reverse order.
static struct {
    struct spinlock lock;
    struct posix_exec_vectors vectors;
    char arena[POSIX_ARG_BYTES_MAX];
    u8 stack_page[POSIX_STACK_PAGE];
} posix_exec_stage;

static int copy_stage_string(u64 address) {
    struct task *task = &task_pool[current_task_slot];
    if (posix_exec_stage.vectors.arena_bytes >= POSIX_ARG_BYTES_MAX)
        return POSIX_PROCESS_E2BIG;
    u32 base = posix_exec_stage.vectors.arena_bytes;
    u32 cursor = base;
    for (;;) {
        char byte;
        if (vm64_copy_from(task->page_dir, &byte, address + (cursor - base),
                           1))
            return POSIX_PROCESS_EINVAL;
        posix_exec_stage.arena[cursor] = byte;
        cursor++;
        if (!byte) break;
        if (cursor >= POSIX_ARG_BYTES_MAX) return POSIX_PROCESS_E2BIG;
    }
    posix_exec_stage.vectors.arena_bytes = cursor;
    return 0;
}

static int copy_stage_vector(u64 array, const char **slots, u32 *count) {
    struct task *task = &task_pool[current_task_slot];
    if (!array) return POSIX_PROCESS_EINVAL;
    for (u32 index = 0; index < POSIX_ARG_COUNT_MAX; index++) {
        u64 string_address;
        if (vm64_copy_from(task->page_dir, &string_address, array + index * 8,
                           8))
            return POSIX_PROCESS_EINVAL;
        if (!string_address) {
            *count = index;
            return 0;
        }
        u32 offset = posix_exec_stage.vectors.arena_bytes;
        int result = copy_stage_string(string_address);
        if (result) return result;
        slots[index] = posix_exec_stage.arena + offset;
    }
    return POSIX_PROCESS_E2BIG;
}

int posix_execve64(u64 path_address, u64 argv_address, u64 envp_address) {
    struct task *task = &task_pool[current_task_slot];
    struct task_context64 *context = &task_contexts[current_task_slot];
    if (!context->vm_valid) return POSIX_PROCESS_EINVAL;

    spin_lock(&posix_exec_stage.lock);
    posix_exec_stage.vectors.argc = 0;
    posix_exec_stage.vectors.envc = 0;
    posix_exec_stage.vectors.arena_bytes = 0;
    posix_exec_stage.vectors.arena = posix_exec_stage.arena;

    char path[VFS_PATH_MAX];
    for (u32 index = 0; index < VFS_PATH_MAX; index++) path[index] = 0;
    u32 length = 0;
    for (;;) {
        char byte;
        if (length >= VFS_PATH_MAX - 1 ||
            vm64_copy_from(task->page_dir, &byte, path_address + length, 1)) {
            spin_unlock(&posix_exec_stage.lock);
            return POSIX_PROCESS_EINVAL;
        }
        path[length] = byte;
        if (!byte) break;
        length++;
    }
    if (!path[0]) {
        spin_unlock(&posix_exec_stage.lock);
        return POSIX_PROCESS_EINVAL;
    }

    // Resolution honors the caller's cwd, including the detached-cwd
    // contract; profile codes are errno-compatible negatives and pass
    // through unchanged.
    struct kernel_object *node = 0;
    int result = posix_profile_resolve(task, path, &node);
    if (result) {
        spin_unlock(&posix_exec_stage.lock);
        return result;
    }
    // The veil stays in force across exec; a hidden image answers ENOENT
    // and a visible one without the x permission answers EACCES. The veil
    // answers before the vector validation: a rule violation is EACCES
    // even when the caller's argv/envp would not have survived the copy.
    result = posix_pledge_veil_check(task, path, POSIX_VEIL_EXECUTE, 0);
    if (result) {
        object_release(node);
        spin_unlock(&posix_exec_stage.lock);
        return result;
    }
    result = copy_stage_vector(argv_address, posix_exec_stage.vectors.argv,
                               &posix_exec_stage.vectors.argc);
    if (!result)
        result = copy_stage_vector(envp_address,
                                   posix_exec_stage.vectors.envp,
                                   &posix_exec_stage.vectors.envc);
    if (result) {
        object_release(node);
        spin_unlock(&posix_exec_stage.lock);
        return result;
    }
    struct vfs_node_info info;
    const u8 *image = 0;
    u32 size = 0;
    if (vfs_stat(node, &info)) result = POSIX_PROCESS_ENOENT;
    else if (info.type == VFS_NODE_DIRECTORY) result = POSIX_PROCESS_EISDIR;
    else if (!posix_mode_allows(&info, task, 0100u))
        result = POSIX_PROCESS_EACCES;
    // A present non-directory node without image backing is not a valid
    // static Mich image; v0 maps that to EINVAL rather than inventing an
    // exec-permission error surface.
    else if (vfs_image(node, &image, &size)) result = POSIX_PROCESS_EINVAL;
    if (result) {
        object_release(node);
        spin_unlock(&posix_exec_stage.lock);
        return result;
    }

    u32 space;
    if (vm64_create_space(&space)) {
        object_release(node);
        spin_unlock(&posix_exec_stage.lock);
        return ENOMEM;
    }
    vaddr_t entry;
    if (elf64_load(space, image, size, &entry)) {
        vm64_destroy_space(space);
        object_release(node);
        spin_unlock(&posix_exec_stage.lock);
        return POSIX_PROCESS_EINVAL;
    }
    paddr_t stack = vm64_alloc_page();
    if (!stack || vm64_map(space, VM64_STACK_TOP - 4096, stack, 1, 0)) {
        if (stack) vm64_free_page(stack);
        vm64_destroy_space(space);
        object_release(node);
        spin_unlock(&posix_exec_stage.lock);
        return ENOMEM;
    }
    u64 stack_rsp = 0;
    if (posix_process_build_stack(posix_exec_stage.stack_page,
                                  &posix_exec_stage.vectors,
                                  VM64_STACK_TOP - 4096, &stack_rsp) ||
        vm64_copy_to(vm64_root(space), VM64_STACK_TOP - 4096,
                     posix_exec_stage.stack_page, POSIX_STACK_PAGE)) {
        vm64_destroy_space(space);
        object_release(node);
        spin_unlock(&posix_exec_stage.lock);
        return POSIX_PROCESS_E2BIG;
    }
    spin_unlock(&posix_exec_stage.lock);
    object_release(node);

    // Commit: nothing below can fail, so descriptors and the old image are
    // intact for every failure path above. POSIX keeps non-CLOEXEC
    // descriptors and the profile across execve; native handles follow the
    // exec64 policy.
    posix_fd_close_cloexec(task);
    handle_close_all(task);
    posix_signal_exec(task);
    posix_pledge_exec(task);
    u32 old_space = context->vm_space;
    context->vm_space = space;
    context->vm_valid = 1;
    task->page_dir = vm64_root(space);
    vm64_destroy_space(old_space);
    context->rax = 0;
    context->rbx = 0;
    context->rcx = 0;
    context->rdx = 0;
    context->rsi = 0;
    context->rdi = 0;
    context->rbp = 0;
    context->r8 = 0;
    context->r9 = 0;
    context->r10 = 0;
    context->r11 = 0;
    context->r12 = 0;
    context->r13 = 0;
    context->r14 = 0;
    context->r15 = 0;
    context->rsp = stack_rsp;
    context->rip = entry;
    context->rflags = 0x202;
    context->user_break = VM64_HEAP_BASE;
    fpu64_init_context(context);
    task_set_name(task, path);
    return 0;
}

int scheduler_cpu_id(void) {
    return (int)smp64_cpu_index();
}

u32 scheduler64_next_slot(void) {
    // The claim happens inside the pick: two CPUs on the shared queue would
    // otherwise both choose the same task between the pick and the switch.
    u32 here = smp64_running_slot();
    int next = task_pick_and_claim((int)here, (int)smp64_cpu_index());
    return next < 0 ? here : (u32)next;
}

// One helper for all three switch paths. The voluntary switch and the two AP
// rotations deliberately differ in what else they touch, but not in the fact
// that one task stopped running and another started. The clock is read here
// and handed down, because the bookkeeping is portable and the clock is not.
static void task_account_switch(u32 outgoing, u32 incoming) {
    u64 now = time64_ns();
    if (outgoing < MAX_TASKS) task_runtime_charge(&task_pool[outgoing], now);
    if (incoming < MAX_TASKS) task_runtime_arm(&task_pool[incoming], now);
}

void scheduler64_set_running(u32 slot) {
    // The task to unpark is the one this CPU ran, not the shared slot's: off
    // this CPU the shared slot belongs to whoever switched last, and
    // clearing its owner bit would free a task another CPU is running.
    u32 old = smp64_running_slot();
    int cpu = (int)smp64_cpu_index();
    if (old < MAX_TASKS && old != slot)
        task_cpu_release(&task_pool[old]);
    task_account_switch(old, slot);
    current_task_slot = slot;
    scheduler_set_current((int)slot);
    smp64_set_current(slot);
    if (slot < MAX_TASKS)
        task_cpu_claim(&task_pool[slot], cpu);
}

void scheduler64_switch(void) {
    switch_count++;
    u32 parked = smp64_running_slot();
    context_save(&task_contexts[parked]);
    fpu64_save(&task_contexts[parked]);
    scheduler64_set_running(scheduler64_next_slot());
    u32 next = smp64_running_slot();
    fpu64_load(&task_contexts[next]);
    context_load(&task_contexts[next]);
}

void task64_set_result(u32 slot, i64 result) {
    if (slot < MAX_TASKS) {
        task_contexts[slot].rax = (u64)result;
        // Record that a task became runnable so the device-IRQ return path
        // can preempt into it instead of waiting for the next timer tick.
        // A task pinned to an AP is that CPU's to start, and its tick can
        // be masked, so the wake has to reach it as a reschedule IPI.
        if (task_pool[slot].on_cpu > 0)
            smp64_resched_cpu((u32)task_pool[slot].on_cpu);
        else
            resched_pending = 1;
    }
}

i64 task64_self_stop(u32 slot) {
    scheduler64_switch();
    return (i64)task_contexts[slot].rax;
}

void task64_terminate(u32 slot, u32 signo) {
    if (slot >= (u32)task_pool_count) return;
    task_exit_signal_set(&task_pool[slot], signo);
    terminate64(slot, 128 + (int)signo);
}

i64 task64_block_switch(void) {
    // A wake stages its answer in the parking slot alone: reading the
    // loaded slot here answered a recv with a byte count it never took.
    u32 parked = current_task_slot;
    scheduler64_switch();
    return (i64)task_contexts[parked].rax;
}

static void interrupt_save(struct task_context64 *context,
                           const struct interrupt_frame64 *frame) {
    context->rax = frame->rax;
    context->rbx = frame->rbx;
    context->rcx = frame->rcx;
    context->rdx = frame->rdx;
    context->rsi = frame->rsi;
    context->rdi = frame->rdi;
    context->rbp = frame->rbp;
    context->r8 = frame->r8;
    context->r9 = frame->r9;
    context->r10 = frame->r10;
    context->r11 = frame->r11;
    context->r12 = frame->r12;
    context->r13 = frame->r13;
    context->r14 = frame->r14;
    context->r15 = frame->r15;
    context->rsp = frame->rsp;
    context->rip = frame->rip;
    context->rflags = frame->rflags;
}

static void interrupt_load(struct interrupt_frame64 *frame,
                           const struct task_context64 *context) {
    u32 slot = smp64_running_slot();
    frame->rax = context->rax;
    frame->rbx = context->rbx;
    frame->rcx = context->rcx;
    frame->rdx = context->rdx;
    frame->rsi = context->rsi;
    frame->rdi = context->rdi;
    frame->rbp = context->rbp;
    frame->r8 = context->r8;
    frame->r9 = context->r9;
    frame->r10 = context->r10;
    frame->r11 = context->r11;
    frame->r12 = context->r12;
    frame->r13 = context->r13;
    frame->r14 = context->r14;
    frame->r15 = context->r15;
    frame->rsp = context->rsp;
    frame->rip = context->rip;
    frame->rflags = context->rflags;
    frame->cs = 0x23;
    frame->ss = 0x1B;
    if (slot < MAX_TASKS)
        vm64_activate(task_pool[slot].page_dir);
}

static int wake_waiting_parent(u32 child_slot) {
    struct task *child = &task_pool[child_slot];
    u32 parent_slot = PID_SLOT((u32)child->parent_id);
    if (parent_slot == 0 || parent_slot >= (u32)task_pool_count) return -1;
    struct task *parent = &task_pool[parent_slot];
    if (parent->id != child->parent_id) return -1;
    int code = child->exit_code;
    if (!task_wait_wake(parent, child->id)) return -1;
    if (parent->wait_posix) {
        parent->wait_posix = 0;
        u64 status_address = parent->wait_status_address;
        parent->wait_status_address = 0;
        // Match the 4-byte int status contract; a wider store would
        // clobber the woken parent's frame past the status slot. The child
        // died, so its death is the report: a stop or continue the parent
        // never collected must not hide the exit status behind itself.
        u32 status = posix_wait_status((u32)code, child->exit_signal, 0, 0);
        child->stop_report = 0;
        child->continued_report = 0;
        if (status_address)
            vm64_copy_to(parent->page_dir, status_address, &status, 4);
        task_contexts[parent_slot].rax = (u64)(u32)child->id;
    } else {
        task_contexts[parent_slot].rax = (u64)(u32)code;
    }
    task_free_slot(child);
    return code;
}

// A child stopped or resumed: publish the report to a parent that is
// parked in a waitpid and asked for it. The parent keeps running when it
// did not ask, and the report stays on the child for a later waitpid, so
// a shell that waits without WUNTRACED still learns the state when it
// asks. The child itself stays alive either way.
void task64_report_child(u32 child_slot) {
    if (child_slot >= (u32)task_pool_count) return;
    struct task *child = &task_pool[child_slot];
    if (!child->stop_report && !child->continued_report) return;
    u32 parent_slot = PID_SLOT((u32)child->parent_id);
    if (parent_slot == 0 || parent_slot >= (u32)task_pool_count) return;
    struct task *parent = &task_pool[parent_slot];
    if (parent->id != child->parent_id || !parent->wait_posix) return;
    if (child->stop_report && !(parent->wait_options & POSIX_WAIT_UNTRACED))
        return;
    if (child->continued_report &&
        !(parent->wait_options & POSIX_WAIT_CONTINUED))
        return;
    if (!task_wait_wake(parent, child->id)) return;
    u32 status = posix_wait_status((u32)child->exit_code, 0,
                                   child->stop_report,
                                   child->continued_report);
    uptr_t status_address = parent->wait_status_address;
    child->stop_report = 0;
    child->continued_report = 0;
    parent->wait_posix = 0;
    parent->wait_options = 0;
    parent->wait_status_address = 0;
    if (status_address)
        vm64_copy_to(parent->page_dir, status_address, &status, 4);
    task_contexts[parent_slot].rax = (u64)(u32)child->id;
}

static void reparent_children(int dead_pid) {
    int adopter = service_lookup(SERVICE_INIT);
    if (adopter == dead_pid || adopter < 0) adopter = 0;
    for (int slot = 1; slot < task_pool_count; slot++) {
        struct task *child = &task_pool[slot];
        if (child->state == TASK_FREE || child->parent_id != dead_pid) continue;
        child->parent_id = adopter;
        if (child->state != TASK_ZOMBIE) continue;
        if (adopter > 0) wake_waiting_parent((u32)slot);
        else task_free_slot(child);
    }
}

void terminate64(u32 slot, int code) {
    struct task *task = &task_pool[slot];
    net_interface_task_died(task->id);
    // The supervisor reaches here from its own teardown while it holds its
    // lock, and all three of these would take it again. The manager gets its
    // turn from the tick that runs right after the supervisor's.
    if (!driver_supervisor_terminating()) {
        driver_manager_task_exiting(task->id, code);
        driver_supervisor_task_died(task->id, code, timer_ticks);
        driver_manager_tick();
    }
    ipc64_task_died((u32)task->id);
    event_cancel_task(slot, ESRCH);
    handle_close_all(task);
    reparent_children(task->id);
    service_release_owner((u32)task->id);
    // An ignored SIGCHLD is the POSIX auto-reap contract: no zombie, the
    // slot frees at once, and a later waitpid answers ECHILD. The signal
    // state ride has to happen before the zombie transition wipes it.
    if (posix_signal_child_exiting(task)) {
        task_free_slot(task);
        return;
    }
    task_mark_zombie(task, code);
    wake_waiting_parent(slot);
}

static int supervisor64_spawn(const struct driver_domain *domain) {
    if (iommu_present() && iommu_domain_exists(domain->id)) {
        if (!iommu_enabled() && iommu_enable()) return -1;
        if (iommu_domain_resume(domain->id)) return -1;
    }
    return spawn64_image(domain->image_id, 0, domain->capabilities,
                         domain->name, domain->argument);
}

static int supervisor64_quiesce(struct kernel_object *device) {
    return pci64_quiesce(device);
}

static int supervisor64_reset(struct kernel_object *device) {
    return pci64_reset(device);
}

static int supervisor64_revoke(int pid, u32 domain_id,
    const struct driver_domain_resource *resources, u32 count) {
    u32 slot = PID_SLOT((u32)pid);
    if (slot >= MAX_TASKS || task_pool[slot].id != pid ||
        !task_contexts[slot].vm_valid)
        return -1;
    struct kernel_object *objects[DRIVER_DOMAIN_RESOURCE_MAX];
    for (u32 index = 0; index < count; index++)
        objects[index] = resources[index].object;
    vm64_revoke_objects(task_contexts[slot].vm_space, objects, count);
    if (iommu_present() && iommu_domain_exists(domain_id) &&
        iommu_domain_suspend(domain_id))
        return -1;
    return 0;
}

static int supervisor64_terminate(int pid) {
    u32 slot = PID_SLOT((u32)pid);
    if (!pid || slot == current_task_slot || slot >= (u32)task_pool_count ||
        task_pool[slot].id != pid || task_pool[slot].state == TASK_FREE ||
        task_pool[slot].state == TASK_ZOMBIE)
        return -1;
    terminate64(slot, 137);
    return 0;
}

static int supervisor64_release(struct driver_domain *domain) {
    if (!domain || !iommu_present() || !iommu_domain_exists(domain->id))
        return 0;
    return iommu_domain_destroy(domain->id);
}

static void reap_orphan_zombies(void) {
    for (int slot = 1; slot < task_pool_count; slot++) {
        struct task *task = &task_pool[slot];
        if ((u32)slot != current_task_slot && task->state == TASK_ZOMBIE &&
            task->parent_id <= 0)
            task_free_slot(task);
    }
}

void exception64_dispatch(struct exception_frame64 *frame) {
        // NMI is serviceable, not fatal: firmware on a secondary CPU during bring-up
    // can raise one, and it carries no error state to act on. Just return.
    u32 slot;
    if (frame->vector == 2)
        return;
    if ((frame->cs & 3) != 3)
        panic64_frame("kernel exception", frame);
    slot = smp64_running_slot();
    u64 cr2 = 0;
    if (frame->vector == 14) {
        __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
        if ((frame->error & 7) == 7 && slot < MAX_TASKS &&
            !vm64_handle_cow(task_contexts[slot].vm_space, cr2))
            return;
    }
    if (slot < MAX_TASKS)
        driver_supervisor_report_user_fault(task_pool[slot].id, frame->vector,
                                            frame->error, frame->rip, cr2,
                                            timer_ticks);
    if (smp64_cpu_index() != 0) {
        if (slot < MAX_TASKS)
            terminate64(slot, 128 + (int)frame->vector);
        smp64_set_current(SMP64_CURRENT_NONE);
        for (;;)
            __asm__ volatile("cli; hlt" ::: "memory");
    }
    u32 fault_signo = posix_signal_fault_signo(frame->vector);
    if (fault_signo && slot < MAX_TASKS && slot == current_task_slot &&
        posix_profile_admitted(&task_pool[slot])) {
        struct posix_signal_regs regs;
        regs.rax = frame->rax;
        regs.rcx = frame->rcx;
        regs.rdx = frame->rdx;
        regs.rsi = frame->rsi;
        regs.rdi = frame->rdi;
        regs.r8 = frame->r8;
        regs.r9 = frame->r9;
        regs.r10 = frame->r10;
        regs.r11 = frame->r11;
        regs.rip = frame->rip;
        regs.rsp = frame->rsp;
        regs.rflags = frame->rflags;
        int delivered = posix_signal_deliver(&task_pool[slot], &regs,
                                             fault_signo);
        if (delivered > 0) {
            frame->rip = regs.rip;
            frame->rsp = regs.rsp;
            frame->rdi = regs.rdi;
            return;
        }
    }
    serial64_write("Mich x86_64: user fault vec=");
    serial64_hex(frame->vector);
    serial64_write(" rip=");
    serial64_hex(frame->rip);
    // Name the faulting task so a contained user fault points at the capsule or
    // the workload directly rather than leaving the reader to map a bare rip.
    serial64_write(" task=");
    serial64_write(task_pool[current_task_slot].name);
    serial64_write("\n");
#ifdef MICH_TEST_BUILD
    if (frame->vector == 14) {
        serial64_write("Mich x86_64: user page fault error=");
        serial64_hex(frame->error);
        serial64_write(" cr2=");
        serial64_hex(cr2);
        serial64_write(" rsp=");
        serial64_hex(frame->rsp);
        serial64_write("\n");
    }
#endif
    struct task_context64 *context = &task_contexts[current_task_slot];
    frame64_save_user(context, frame);
    fpu64_save(context);
    // The death code stays 128 + vector because the crash passport and the
    // driver recovery catalog match on it. A POSIX parent still reads a
    // real termsig: the waitpid packing looks at exit_signal first.
    if (fault_signo)
        task_exit_signal_set(&task_pool[current_task_slot], fault_signo);
    terminate64(current_task_slot, 128 + (int)frame->vector);
    u32 next = scheduler64_next_slot();
    if (next == current_task_slot || task_pool[next].state != TASK_RUNNING) {
        serial64_write("Mich x86_64: no runnable task\n");
        for (;;) __asm__ volatile("cli; hlt");
    }
    scheduler64_set_running(next);
    context = &task_contexts[current_task_slot];
    fpu64_load(context);
    frame64_load_user(frame, context);
    vm64_activate(task_pool[current_task_slot].page_dir);
    serial64_write("Mich x86_64: user exception contained\n");
}


static void iommu64_fault_tick(void) {
    if (!iommu_enabled()) return;
    for (u32 i = 0; i < IOMMU_FAULT_BATCH; i++) {
        struct iommu_fault fault;
        int rc = iommu_fault_poll(&fault);
        if (rc <= 0) return;
        serial64_write("Mich x86_64: IOMMU DMA fault sid=");
        serial64_hex(fault.source_id);
        serial64_write(" iova=");
        serial64_hex(fault.address);
        serial64_write(" reason=");
        serial64_hex(fault.reason);
        serial64_write("\n");
        if (fault.owner) {
            driver_supervisor_report_iommu_fault(
                fault.owner, fault.segment, fault.source_id, fault.reason,
                fault.write, fault.address, timer_ticks);
            driver_domain_quarantine(fault.owner);
        }
    }
}

// AP user tick: save and rotate this CPU's tasks, never
// current_task_slot. Same-privilege hlt frames have no SS/RSP.
static void ap64_timer_preempt(struct interrupt_frame64 *frame) {
    u32 slot = smp64_running_slot();
    int next;
    if ((frame->cs & 3) != 3 || slot >= MAX_TASKS ||
        slot == current_task_slot)
        return;
    interrupt_save(&task_contexts[slot], frame);
    fpu64_save(&task_contexts[slot]);
    smp64_note_preempt();
    next = smp64_pick_next(slot);
    if (next < 0 || (u32)next == slot) return;
    task_account_switch(slot, (u32)next);
    smp64_set_current((u32)next);
    fpu64_load(&task_contexts[next]);
    interrupt_load(frame, &task_contexts[next]);
    vm64_activate(task_pool[next].page_dir);
}

// The same rotation, driven by the reschedule IPI through an exception
// frame; that frame carries a vector and an error word, so it pairs with
// the frame64_* helpers. An AP parked in ring 0 has no user frame to
// rewrite and enters a pinned task instead.
static void ap64_resched(struct exception_frame64 *frame) {
    u32 slot = smp64_running_slot();
    int next;
    if ((frame->cs & 3) != 3) {
        smp64_enter_pinned(smp64_cpu_index());
        return;
    }
    if (slot >= MAX_TASKS || slot == current_task_slot) return;
    frame64_save_user(&task_contexts[slot], frame);
    fpu64_save(&task_contexts[slot]);
    smp64_note_preempt();
    next = smp64_pick_next(slot);
    if (next < 0 || (u32)next == slot) return;
    task_account_switch(slot, (u32)next);
    smp64_set_current((u32)next);
    fpu64_load(&task_contexts[next]);
    frame64_load_user(frame, &task_contexts[next]);
    vm64_activate(task_pool[next].page_dir);
}

void timer64_dispatch(struct interrupt_frame64 *frame) {
    if (smp64_timer_tick(frame->cs, (u64)(uptr_t)frame)) {
        ap64_timer_preempt(frame);
        return;
    }
    if (!gdt64_stack_ok() || !smp64_syscall_ok()) {
        serial64_write("Mich x86_64: kernel stack failure\n");
        for (;;) __asm__ volatile("cli; hlt");
    }
    // Same-privilege frames carry no SS/RSP, so a save/load round trip
    // would corrupt the context. The IF protocol (no sti in ring 0,
    // MSR_FMASK clears IF on syscall entry) means this should never
    // fire; the guard keeps a future sti from turning a tick into
    // silent context corruption, mirroring the AP path above.
    if ((frame->cs & 3) != 3) return;
    interrupt_save(&task_contexts[current_task_slot], frame);
    fpu64_save(&task_contexts[current_task_slot]);
    scheduler64_set_running(scheduler64_next_slot());
    fpu64_load(&task_contexts[current_task_slot]);
    interrupt_load(frame, &task_contexts[current_task_slot]);
    // A pending signal can now be delivered to the task the frame returns
    // to, which is the asynchronous path: a user loop with no syscalls
    // still reaches its handler within one tick.
    if ((frame->cs & 3) == 3 &&
        posix_profile_admitted(&task_pool[current_task_slot])) {
        struct posix_signal_regs regs;
        regs.rax = frame->rax;
        regs.rcx = frame->rcx;
        regs.rdx = frame->rdx;
        regs.rsi = frame->rsi;
        regs.rdi = frame->rdi;
        regs.r8 = frame->r8;
        regs.r9 = frame->r9;
        regs.r10 = frame->r10;
        regs.r11 = frame->r11;
        regs.rip = frame->rip;
        regs.rsp = frame->rsp;
        regs.rflags = frame->rflags;
        int delivered = posix_signal_deliver(&task_pool[current_task_slot],
                                             &regs, 0u);
        if (delivered > 0) {
            frame->rip = regs.rip;
            frame->rsp = regs.rsp;
            frame->rdi = regs.rdi;
        } else if (delivered < 0) {
            terminate64(current_task_slot, 128 - delivered);
            scheduler64_set_running(scheduler64_next_slot());
            fpu64_load(&task_contexts[current_task_slot]);
            interrupt_load(frame, &task_contexts[current_task_slot]);
        }
    }
    timer_ticks++;
    ipc64_tick(timer_ticks);
    posix_time_tick(timer_ticks);
    posix_poll_tick(timer_ticks);
    event_tick(timer_ticks, ETIMEDOUT);
    completion_tick(timer_ticks, ETIMEDOUT);
    timer_object_tick(timer_ticks);
    driver_supervisor_tick(timer_ticks);
    driver_manager_tick();
#ifdef MICH_TEST_BUILD
    driver_live_recovery_tick();
#endif
    iommu64_fault_tick();
    reap_orphan_zombies();
    // The mailbox backstop: the drain on this CPU's slot, so a frame handed
    // over while the owning CPU had nothing to run it still lands.
    net_rx_drain((u32)scheduler_cpu_id());
    if (timer_ticks == 8)
        serial64_write("Mich x86_64: preemptive scheduler pass\n");
    if (smp64_host_note(frame->cs))
        serial64_write("Mich x86_64: SMP dual-core userspace pass\n");
}

// The console tty is the serial port: its bytes go out through the same
// putc the kernel's own markers use, and the line discipline sits between
// the two so an application sees canonical input and echo.
static void console64_output(void *context, u8 byte) {
    (void)context;
    serial64_putc((char)byte);
}

static int console64_init(void) {
    if (posix_tty_create() != 0) return -1;
    posix_tty_set_output(0, console64_output, 0);
    return 0;
}

static int devfs64_init(void) {
    struct kernel_object *root = vfs_root();
    struct kernel_object *directory = root ?
        vfs_create_mode(root, "dev", VFS_NODE_DIRECTORY,
                        VFS_MODE_DIRECTORY_READONLY) : 0;
    struct kernel_object *node = directory ? vfs_create_urandom(directory) : 0;
    if (!root || !directory || !node) {
        if (node) object_release(node);
        if (directory) {
            object_release(directory);
            vfs_unlink(root, "dev");
        }
        if (root) object_release(root);
        return -1;
    }
    object_release(node);
    node = vfs_create_console(directory);
    if (!node) {
        object_release(directory);
        vfs_unlink(root, "dev");
        object_release(root);
        return -1;
    }
    object_release(node);
    node = vfs_create_null(directory);
    if (!node) {
        object_release(directory);
        vfs_unlink(root, "dev");
        object_release(root);
        return -1;
    }
    object_release(node);
    node = vfs_create_tty(directory);
    if (!node) {
        object_release(directory);
        vfs_unlink(root, "dev");
        object_release(root);
        return -1;
    }
    object_release(node);
    object_release(directory);
    object_release(root);
    return 0;
}

// Not test-only: production matches the "virtio-blk" boot module by name.
static int module_name_is(const struct bd_module *module, const char *name) {
    if (module->cmdline < 0x1000 || module->cmdline >= 0x100000) return 0;
    const char *text = (const char *)(uptr_t)module->cmdline;
    u32 index = 0;
    for (; index < 32 && name[index]; index++)
        if (text[index] != name[index]) return 0;
    return !text[index];
}

static int bootfs64_init(const struct bd_module *modules, u32 count) {
    if (!modules || !count || count > VFS_BOOTFS_ENTRY_MAX) return -1;
    struct kernel_object *root = vfs_root();
    struct kernel_object *directory = root ?
        vfs_create(root, "boot", VFS_NODE_DIRECTORY) : 0;
    if (!root || !directory) {
        if (root) object_release(root);
        return -1;
    }
    struct vfs_bootfs_entry entries[VFS_BOOTFS_ENTRY_MAX];
    for (u32 index = 0; index < count; index++) {
        if (modules[index].cmdline < 0x1000 ||
            modules[index].cmdline >= 0x100000) {
            object_release(directory);
            vfs_unlink(root, "boot");
            object_release(root);
            return -1;
        }
        entries[index].name = (const char *)(uptr_t)modules[index].cmdline;
        entries[index].data = (const void *)(uptr_t)modules[index].start;
        entries[index].size = modules[index].end - modules[index].start;
    }
    int result = vfs_mount_bootfs(directory, entries, count);
    object_release(directory);
    if (result) vfs_unlink(root, "boot");
    object_release(root);
    return result;
}


void arch_task_release(struct task *task) {
    u32 slot = (u32)(task - task_pool);
    if (slot >= MAX_TASKS) return;
    if (task_contexts[slot].vm_valid) {
        vm64_destroy_space(task_contexts[slot].vm_space);
    }
    u8 *bytes = (u8 *)&task_contexts[slot];
    for (usize_t i = 0; i < sizeof(task_contexts[slot]); i++) bytes[i] = 0;
}

void kernel64_main(u32 magic, struct bd_info *info) {
    if (magic != BD_MAGIC || !info || info->magic != BD_MAGIC ||
        (info->version != BD_VERSION && info->version != BD_VERSION_UEFI)) {
        serial64_write("Mich x86_64: bad boot protocol\n");
        for (;;) __asm__ volatile("cli; hlt");
    }
    if (info->version == BD_VERSION_UEFI)
        acpi64_set_rsdp(info->rsdp_ptr);
    if (!info->mmap_ptr || !info->mmap_count || info->mmap_count > 32 ||
        info->mods_count > 8 || (info->mods_count && !info->mods_ptr)) {
        serial64_write("Mich x86_64: invalid boot tables\n");
        for (;;) __asm__ volatile("cli; hlt");
    }
    serial64_write("Mich Core " MICH_VERSION_STRING " x86_64: long mode alive\n");
    gdt64_init();
    serial64_write("Mich x86_64: GDT and TSS alive\n");
    idt64_init();
    serial64_write("Mich x86_64: IDT alive\n");
    serial64_write("Mich x86_64: panic subsystem ready\n");
    if (!info->mods_count) {
        serial64_write("Mich x86_64: missing init64 module\n");
        for (;;) __asm__ volatile("cli; hlt");
    }
    struct bd_module *modules = (struct bd_module *)(uptr_t)info->mods_ptr;
    for (u32 index = 0; index < info->mods_count; index++) {
        if (modules[index].end <= modules[index].start ||
            modules[index].end > 0x40000000U ||
            modules[index].end - modules[index].start > 0x100000) {
            serial64_write("Mich x86_64: invalid boot module\n");
            for (;;) __asm__ volatile("cli; hlt");
        }
    }
    struct bd_module *init_module = &modules[0];
    if (init_module->end <= init_module->start ||
        init_module->end - init_module->start > 0x100000) {
        serial64_write("Mich x86_64: invalid init64 module\n");
        for (;;) __asm__ volatile("cli; hlt");
    }
    spawn_image_count = info->mods_count;
    for (u32 index = 0; index < spawn_image_count; index++) {
        spawn_images[index] = (const u8 *)(uptr_t)modules[index].start;
        spawn_image_sizes[index] = modules[index].end - modules[index].start;
        spawn_image_capabilities[index] =
            modules[index].flags & CAP_BOOT_ALLOWED;
        spawn_image_flags[index] = modules[index].flags;
    }
    pmm_init((uptr_t)info->mmap_ptr, (usize_t)info->mmap_count * 24,
             24, (paddr_t)(uptr_t)&_bss_end);
    pmm_set_alloc_limit(0x40000000ULL);
    for (u32 index = 0; index < info->mods_count; index++)
        pmm_reserve(modules[index].start,
                    (usize_t)(modules[index].end - modules[index].start));
    highmem_probe = pmm_alloc_page_range(0x20000000ULL, 0x40000000ULL);
    if (highmem_probe) {
        volatile u64 *page = (volatile u64 *)(uptr_t)highmem_probe;
        page[0] = 0x4D49434848494748ULL;
        page[1] = 0x5048595350414745ULL;
    }
    serial64_write("Mich x86_64: E820 PMM alive\n");
    syscall64_init();
    serial64_write("Mich x86_64: syscall MSRs alive\n");
    if (vm64_init()) KERNEL_PANIC("VM64 init");
    service_init();
    object_init();
    vfs_init();
    posix_fd_init();
    posix_socket_init();
    posix_pgroup_init();
    posix_tty_init();
    if (console64_init()) KERNEL_PANIC("console tty");
    posix_profile_init();
    entropy_init();
    if (bootfs64_init(modules, info->mods_count)) KERNEL_PANIC("bootfs mount");
    if (devfs64_init()) KERNEL_PANIC("dev nodes");
    resource_init();
    iommu_init();
    iommu_set_unconfined_dma_allowed(
        (init_module->flags & BOOT_MODULE_ALLOW_UNCONFINED_DMA) != 0);
    if (page_resource_set_revoke_backend(vm64_revoke_object_all))
        KERNEL_PANIC("page revoke backend");
    ring_init();
    driver_init();
    driver_supervisor_init(supervisor64_spawn, supervisor64_quiesce,
                           supervisor64_reset, supervisor64_revoke,
                           supervisor64_terminate);
    driver_manager_init(supervisor64_resource);
    event_init(task64_set_result);
    completion_init();
    timer_object_init();
    packet_pool_init();
    vnic_init();
    block_init();
    endpoint_init();
    bridge_init();
    vector64_init();
    ipc64_init();
    if (acpi64_init()) KERNEL_PANIC("ACPI discovery");
    // After ACPI because the century register index lives in the FADT, and
    // before anything that may want a wall clock.
    if (rtc64_init()) KERNEL_PANIC("CMOS clock");
    // Ahead of the APIC timer calibration, which delays by wall time, and
    // ahead of the test suite, which asserts the calibration.
    if (time64_init()) KERNEL_PANIC("time base calibration");
    if (platform_resource_init()) KERNEL_PANIC("platform resources");
    serial64_write("Mich x86_64: ACPI tables pass\n");
    serial64_write("Mich x86_64: wall clock anchored\n");
    serial64_write("Mich x86_64: platform MMIO objects pass\n");
    serial64_write("Mich x86_64: PML4 address space alive\n");
    task_pool_count = 0;
    fpu64_enable();
    int idle_pid = spawn64(-1, 0, "idle64", 0);
    u32 init_capabilities = init_module->flags & CAP_BOOT_ALLOWED;
    int init_one_pid = spawn64(0, init_capabilities, "init64-one", 1);
    int init_two_pid = spawn64(init_one_pid, 0, "init64-two", 2);
    if (idle_pid != 0 || init_one_pid != 1 || init_two_pid != 2) {
        serial64_write("Mich x86_64: process spawn failure\n");
        for (;;) __asm__ volatile("cli; hlt");
    }
    // The BSP idle task busy-loops in ring 3 and never blocks; flag it so the
    // scheduler runs it only when no real task is runnable (see task.h).
    task_pool[0].is_idle = 1;
#ifdef MICH_TEST_BUILD
    // A crash harness boot packs a crash64 marker module and runs the crash
    // workload in place of the battery, against the NVMe drive the harness
    // keeps alive across kills.
    int crash_boot = 0;
    for (u32 index = 0; index < info->mods_count; index++)
        if (module_name_is(&modules[index], "crash64")) {
            crash_boot = 1;
            break;
        }
    test_report_reset();
    struct test64_env test_env;
    test_env.owner = &task_pool[1];
    test_env.target = &task_pool[2];
    test_env.owner_space = task_contexts[1].vm_space;
    test_env.target_space = task_contexts[2].vm_space;
    test_env.owner_slot = 1;
    test_env.target_slot = 2;
    test_env.target_result = &task_contexts[2].rax;
    test_env.platform_mmio = platform_mmio[0];
    test_env.resource_provider = supervisor64_resource;
    test_env.spawn = supervisor64_spawn;
    test_env.quiesce = supervisor64_quiesce;
    test_env.reset = supervisor64_reset;
    test_env.revoke = supervisor64_revoke;
    test_env.terminate = supervisor64_terminate;
    test_env.module_flags = spawn_image_flags[0];
    if (!crash_boot && tests64_run(&test_env))
        KERNEL_PANIC("independent kernel tests");
    if (!crash_boot && tests64_run_network(&test_env))
        KERNEL_PANIC("independent network tests");
    if (!crash_boot &&
        (spawn_image_flags[0] & BD_MODULE_POSIX_PROFILE) &&
        !posix_profile_admitted(&task_pool[1]) &&
        posix_profile_admit(&task_pool[1]))
        KERNEL_PANIC("POSIX profile restore");
#endif
    if (network_runtime_init()) KERNEL_PANIC("network runtime init");
    serial64_write("Mich x86_64: network runtime ready\n");
    serial64_write("Mich x86_64: external ELF64 init loaded\n");
    serial64_write("Mich x86_64: driver image registry pass\n");
    scheduler64_set_running(1);
    fpu64_load(&task_contexts[1]);
    timer_ticks = 0;
    vm64_activate(task_pool[1].page_dir);
    if (vtd64_init()) KERNEL_PANIC("Intel VT-d discovery");
    if (amd_iommu64_init()) KERNEL_PANIC("AMD-Vi discovery");
    if (vtd64_present() && amd_iommu64_present())
        KERNEL_PANIC("multiple IOMMU backends");
    if (vtd64_present()) {
        if (vtd64_register_backend() ||
            dma_resource_set_iommu_backend(iommu_dma_release) ||
            driver_supervisor_set_release_backend(supervisor64_release))
            KERNEL_PANIC("IOMMU backend registration");
        serial64_write("Mich x86_64: Intel VT-d discovery pass\n");
        serial64_write("Mich x86_64: IOMMU backend registration pass\n");
    }
    if (amd_iommu64_present()) {
        serial64_write("Mich x86_64: AMD-Vi discovery pass\n");
        if (amd_iommu64_prepare() || amd_iommu64_register_backend() ||
            dma_resource_set_iommu_backend(iommu_dma_release) ||
            driver_supervisor_set_release_backend(supervisor64_release))
            KERNEL_PANIC("AMD-Vi backend registration");
        serial64_write("Mich x86_64: AMD-Vi device table pass\n");
        serial64_write("Mich x86_64: IOMMU backend registration pass\n");
        serial64_write("Mich x86_64: AMD-Vi command and event buffers pass\n");
        serial64_write("Mich x86_64: AMD-Vi completion command pass\n");
    }
    if (init_module->flags & BOOT_MODULE_PANIC_TEST) {
        serial64_write("Mich x86_64: panic profile trigger\n");
        volatile u64 value = *(volatile u64 *)(uptr_t)0x0000000DEADBE000ULL;
        (void)value;
        KERNEL_PANIC("panic profile did not fault");
    }
    if (pci64_init()) KERNEL_PANIC("PCI enumeration");
#ifdef MICH_TEST_BUILD
    if (amd_iommu64_present()) {
        if (amd_iommu64_test_domain(pci64_object(0)))
            KERNEL_PANIC("AMD-Vi domain test");
        serial64_write("Mich test64: AMD-Vi DTE and domain pass\n");
        serial64_write("Mich test64: AMD-Vi page invalidation pass\n");
    }
    if (vtd64_present()) {
        if (test_vtd64_tables(pci64_object(0)))
            KERNEL_PANIC("Intel VT-d table tests");
        serial64_write("Mich test64: Intel VT-d translation tables pass\n");
        serial64_write("Mich test64: Intel VT-d command engine pass\n");
        serial64_write("Mich test64: Intel VT-d revoke and resume pass\n");
        serial64_write("Mich test64: Intel VT-d fault decode pass\n");
        if (test_iommu64_forbidden_dma())
            KERNEL_PANIC("Intel VT-d forbidden DMA test");
        serial64_write("Mich test64: Intel VT-d forbidden DMA blocked\n");
        if (vtd64_ir_active()) {
            if (test_vtd64_interrupt_remapping())
                KERNEL_PANIC("Intel VT-d interrupt remapping test");
            serial64_write(
                "Mich test64: Intel VT-d interrupt remapping pass\n");
        }
    }
    if (!crash_boot && tests64_run_driver(&test_env))
        KERNEL_PANIC("independent driver tests");
#endif
    serial64_write("Mich x86_64: PCI enumeration pass\n");
    if (pci64_uses_ecam())
        serial64_write("Mich x86_64: PCIe ECAM pass\n");
    if (platform64_interrupts_init(acpi64_madt()))
        KERNEL_PANIC("APIC platform init");
    if (console64_wire_init(init_module->flags))
        KERNEL_PANIC("console wire");
    if (msi64_init(apic64_id())) KERNEL_PANIC("MSI backend init");
    if (msix64_init(apic64_id())) KERNEL_PANIC("MSI-X backend init");
#ifdef MICH_TEST_BUILD
    // NVMe has to be probed here: after the MSI-X backend exists and before
    // smp64_init() parks the APs. What counts as a pass lives in the test.
    if (crash_boot) {
        if (tests64_run_crash()) KERNEL_PANIC("crash workload");
    } else if (tests64_run_nvme(&test_env)) {
        KERNEL_PANIC("independent kernel tests");
    }
#endif
    if (smp64_init()) KERNEL_PANIC("SMP bring-up");
#ifdef MICH_TEST_BUILD
    if (!crash_boot && tests64_run_smp()) KERNEL_PANIC("independent SMP tests");
    int msi_test;
    int msix_test;
    int destructive = (init_module->flags & BOOT_MODULE_HARDWARE_TEST) != 0;
    if (destructive)
        serial64_write("Mich x86_64: hardware destructive test profile\n");
    if (!crash_boot &&
        tests64_run_hardware(&test_env, destructive, &msi_test, &msix_test))
        KERNEL_PANIC("independent hardware tests");
#endif
    int virtio_net_restart_test =
        (init_module->flags & BOOT_MODULE_DRIVER_RESTART_TEST) != 0;
    int virtio_net_circuit_test =
        (init_module->flags & BOOT_MODULE_DRIVER_CIRCUIT_TEST) != 0;
    int virtio_net_recovery_test =
        (init_module->flags & BOOT_MODULE_DRIVER_RECOVERY_TEST) != 0;
    if (manager64_register_virtio_net(
            (init_module->flags & BOOT_MODULE_HARDWARE_TEST) != 0,
            virtio_net_restart_test, virtio_net_circuit_test,
            virtio_net_recovery_test))
        KERNEL_PANIC("virtio-net manifest");
    for (u32 index = 0; index < info->mods_count; index++) {
        if (!module_name_is(&modules[index], "virtio-blk")) continue;
        if (manager64_register_virtio_blk(index))
            KERNEL_PANIC("virtio-blk manifest");
        break;
    }
    for (u32 index = 0; index < info->mods_count; index++) {
        if (!module_name_is(&modules[index], "nvme")) continue;
        if (manager64_register_nvme(index))
            KERNEL_PANIC("nvme manifest");
        break;
    }
#ifdef MICH_TEST_BUILD
    // A netbench boot measures loopback cycles and needs a quiescent kernel. The
    // driver-live-recovery lab crashes and restarts a capsule against a tight tick
    // deadline and rebind-gap that both assume the capsule is the only userspace
    // task; netbench is loopback-only (never blocks off the run queue like dnsprobe
    // does), so its second runnable task perturbs that cadence into a spurious
    // recovery panic and skews the counts. The tcp wire demo holds one stream
    // connection across its whole exchange, which the lab's capsule restarts would
    // tear down mid-flight, so its boot skips the lab too.
    int bench_boot = 0;
    for (u32 index = 0; index < info->mods_count; index++)
        if (module_name_is(&modules[index], "netbench") ||
            module_name_is(&modules[index], "tcpwire")) {
            bench_boot = 1;
            break;
        }
    if (!bench_boot && !crash_boot &&
        !(init_module->flags & BOOT_MODULE_UNIT_TEST) &&
        driver_live_recovery_prepare())
        KERNEL_PANIC("driver live recovery setup");
#endif
    if (manager64_set_pci_inventory())
        KERNEL_PANIC("driver PCI inventory");
#ifdef MICH_TEST_BUILD
    // The dns probe and the tcp wire demo are ordinary processes, not
    // driver capsules: they own no interface and reach the network purely
    // through routed sockets.
    for (u32 index = 0; index < info->mods_count; index++) {
        if (!module_name_is(&modules[index], "dnsprobe") &&
            !module_name_is(&modules[index], "netbench") &&
            !module_name_is(&modules[index], "tcpwire")) continue;
        if (spawn64_image(index, 0, spawn_image_capabilities[index],
                          "probe", 0) < 0)
            KERNEL_PANIC("probe spawn");
        break;
    }
#endif
#ifdef MICH_TEST_BUILD
    if (!bench_boot && !crash_boot &&
        !(init_module->flags & BOOT_MODULE_UNIT_TEST) &&
        driver_live_recovery_arm())
        KERNEL_PANIC("driver live recovery arm");
    if (!crash_boot && tests64_run_irq(&test_env, msi_test, msix_test))
        KERNEL_PANIC("independent IRQ tests");
    if (!bench_boot && !crash_boot &&
        !(init_module->flags & BOOT_MODULE_UNIT_TEST)) {
        // Keep the lifecycle probe out of the init1/init2 handshake. A bench
        // boot has no recovery lab to reach COMPLETE and unblock these, so it
        // must leave the init tasks runnable.
        task_state_set(&task_pool[1], TASK_BLOCKED_RECV);
        task_state_set(&task_pool[2], TASK_BLOCKED_RECV);
    }
#endif
    serial64_write("Mich x86_64: LAPIC controller pass\n");
    serial64_write("Mich x86_64: IOAPIC routing pass\n");
    serial64_write("Mich x86_64: legacy PIC disabled\n");
    serial64_write("Mich x86_64: APIC timer pass\n");
    highmem_probe_finish();
#ifdef MICH_TEST_BUILD
    if (init_module->flags & BOOT_MODULE_UNIT_TEST)
        test_report_finish();
#endif
    if (smp64_host_start()) KERNEL_PANIC("SMP AP host");
#ifdef MICH_TEST_BUILD
    if (!crash_boot && !(init_module->flags & BOOT_MODULE_UNIT_TEST)) {
        u32 live_slot = PID_SLOT((u32)driver_live_recovery.primary_pid);
        if (live_slot >= MAX_TASKS ||
            task_pool[live_slot].id != driver_live_recovery.primary_pid)
            KERNEL_PANIC("driver live recovery entry");
        scheduler64_set_running(live_slot);
        fpu64_load(&task_contexts[live_slot]);
        vm64_activate(task_pool[live_slot].page_dir);
        smp64_gs_user();
        user64_enter(task_contexts[live_slot].rip, task_contexts[live_slot].rsp,
                     task_contexts[live_slot].rdi, task_contexts[live_slot].rsi);
    }
#endif
    smp64_gs_user();
    user64_enter(task_contexts[1].rip, task_contexts[1].rsp,
                 task_contexts[1].rdi, task_contexts[1].rsi);
    for (;;) __asm__ volatile("cli; hlt");
}
