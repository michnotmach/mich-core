#include "tests64.h"
#include "test_report.h"
#include "types.h"
#include "object.h"
#include "resource.h"
#include "driver.h"
#include "driver_manager.h"
#include "driver_supervisor.h"
#include "bridge.h"
#include "event.h"
#include "firmware.h"
#include "pmm.h"
#include "vm64.h"
#include "pci64.h"
#include "vector64.h"
#include "serial64.h"

static const struct test64_env *test_env;

static u32 driver_test_starts;
static u32 driver_test_stops;
static u32 supervisor_test_quiesces;
static u32 supervisor_test_resets;
static u32 supervisor_test_revokes;
static int supervisor_test_quiesce_fail;
static u32 stress_irq_masks;
static u32 stress_irq_releases;

static int stress_irq_mask(u32 source, int masked) {
    if (source != 123 || (masked != 0 && masked != 1)) return -1;
    stress_irq_masks++;
    return 0;
}

static void stress_irq_release(u32 source) {
    if (source == 123) stress_irq_releases++;
}

static int supervisor_test_spawn(const struct driver_domain *d) {
    if (!test_env || !d || (d->image_id && d->image_id != 7)) return -1;
    return d->argument == 20 ? test_env->owner->id : test_env->target->id;
}

static int supervisor_test_quiesce(struct kernel_object *device) {
    if (!pci_resource_get(device)) return -1;
    supervisor_test_quiesces++;
    return supervisor_test_quiesce_fail ? -1 : 0;
}

static int supervisor_test_recovery_audit_clear(
    const struct driver_recovery_audit *audit) {
    if (!audit) return 0;
    const u8 *bytes = (const u8 *)audit;
    for (usize_t index = 0; index < sizeof(*audit); index++)
        if (bytes[index]) return 0;
    return 1;
}

static int supervisor_test_reset(struct kernel_object *device) {
    const struct pci_resource *pci = pci_resource_get(device);
    if (!pci) return -1;
    supervisor_test_resets++;
    return pci->device_id == 0xB201 ? 1 : 0;
}

static int supervisor_test_revoke(int pid, u32 domain_id,
    const struct driver_domain_resource *resources, u32 count) {
    if ((pid != test_env->owner->id && pid != test_env->target->id) ||
        !domain_id || !resources || !count)
        return -1;
    supervisor_test_revokes++;
    return test_env->revoke(pid, domain_id, resources, count);
}

static int supervisor_test_terminate(int pid) {
    return pid == test_env->owner->id || pid == test_env->target->id ? 0 : -1;
}

static struct driver_instance *driver_test_last;

static int driver_test_probe(struct kernel_object *device) {
    return !device || device->type != KOBJECT_PCI;
}

static int driver_test_start(struct driver_instance *instance) {
    struct kernel_object *resource =
        driver_get_resource(instance, 0, KRIGHT_READ | KRIGHT_MAP,
                            KOBJECT_MMIO);
    if (!resource || !mmio_resource_get(resource)) return -1;
    instance->private_data = (void *)(uptr_t)0x4D494348;
    driver_test_starts++;
    driver_test_last = instance;
    return 0;
}

static void driver_test_stop(struct driver_instance *instance) {
    if (instance->private_data == (void *)(uptr_t)0x4D494348)
        driver_test_stops++;
    instance->private_data = 0;
}

static int driver_manifest_start(struct driver_instance *instance) {
    if (!instance || !instance->device ||
        instance->device->type != KOBJECT_PCI)
        return -1;
    instance->private_data = (void *)(uptr_t)0x44525652;
    driver_test_starts++;
    driver_test_last = instance;
    return 0;
}

static void driver_manifest_stop(struct driver_instance *instance) {
    if (instance->private_data == (void *)(uptr_t)0x44525652)
        driver_test_stops++;
    instance->private_data = 0;
}

static int driver_core(const struct test64_env *env) {
    test_env = env;
    if (!pci64_count() || !(test_env && test_env->platform_mmio)) return -1;
    struct driver_descriptor descriptor;
    descriptor.name = "mich.test.module";
    descriptor.abi_version = DRIVER_ABI_VERSION;
    descriptor.flags = 0;
    descriptor.probe = driver_test_probe;
    descriptor.start = driver_test_start;
    descriptor.stop = driver_test_stop;
    int module = driver_register(&descriptor);
    if (module <= 0 || driver_register(&descriptor) >= 0 ||
        !driver_name(module))
        return -1;
    struct driver_instance *instance =
        driver_bind(module, pci64_object(0));
    if (!instance ||
        driver_add_resource(instance, test_env->platform_mmio,
                            KRIGHT_READ | KRIGHT_MAP) ||
        driver_get_resource(instance, 0, KRIGHT_WRITE, KOBJECT_MMIO) ||
        driver_start(instance)) {
        if (instance) driver_unbind(instance);
        driver_unregister(module);
        return -1;
    }
    driver_stop(instance);
    if (driver_test_starts != 1 || driver_test_stops != 1) {
        driver_unbind(instance);
        driver_unregister(module);
        return -1;
    }
    driver_unbind(instance);
    if (driver_unregister(module)) return -1;
    struct pci_resource first;
    struct pci_resource second;
    struct pci_resource *descriptions[2] = { &first, &second };
    for (u32 device = 0; device < 2; device++) {
        struct pci_resource *description = descriptions[device];
        description->segment = 0;
        description->bus = 0;
        description->device = (u8)(20 + device);
        description->function = 0;
        description->vendor_id = (u16)(0xA100 + device);
        description->device_id = (u16)(0xB100 + device);
        description->class_code = 0xFF;
        description->subclass = 0;
        description->programming_interface = 0;
        description->revision = 1;
        description->capability_flags = 0;
        description->msi_offset = 0;
        description->msix_offset = 0;
        description->pcie_offset = 0;
        description->active = 0;
        for (u32 bar = 0; bar < 6; bar++) {
            description->bars[bar].address = 0;
            description->bars[bar].length = 0;
            description->bars[bar].flags = 0;
        }
    }
    struct kernel_object *devices[2];
    devices[0] = pci_resource_create(&first);
    devices[1] = pci_resource_create(&second);
    if (!devices[0] || !devices[1]) {
        if (devices[0]) object_release(devices[0]);
        if (devices[1]) object_release(devices[1]);
        return -10;
    }
    struct driver_manifest base;
    struct driver_manifest dependent;
    base.driver.name = "mich.base";
    base.driver.abi_version = DRIVER_ABI_VERSION;
    base.driver.flags = 0;
    base.driver.probe = driver_test_probe;
    base.driver.start = driver_manifest_start;
    base.driver.stop = driver_manifest_stop;
    base.priority = 10;
    base.restart_policy = DRIVER_RESTART_NEVER;
    base.max_restarts = 0;
    base.dependency_count = 0;
    base.match_count = 1;
    base.matches[0].vendor_id = 0xA100;
    base.matches[0].device_id = 0xB100;
    base.matches[0].class_code = 0xFF;
    base.matches[0].subclass = 0xFF;
    base.matches[0].programming_interface = 0xFF;
    dependent = base;
    dependent.driver.name = "mich.dependent";
    dependent.priority = 20;
    dependent.restart_policy = DRIVER_RESTART_ON_FAILURE;
    dependent.max_restarts = 1;
    dependent.dependency_count = 1;
    dependent.dependencies[0] = "mich.base";
    dependent.matches[0].vendor_id = 0xA101;
    dependent.matches[0].device_id = 0xB101;
    int base_id = driver_register_manifest(&base);
    int dependent_id = driver_register_manifest(&dependent);
    driver_test_starts = 0;
    driver_test_stops = 0;
    driver_test_last = 0;
    int started = base_id > 0 && dependent_id > 0 ?
        driver_start_all(devices, 2) : -1;
    int restarted = driver_test_last ?
        driver_instance_failed(driver_test_last) : -1;
    driver_device_removed(devices[0]);
    driver_device_removed(devices[1]);
    int dependent_unregistered = driver_unregister(dependent_id);
    int base_unregistered = driver_unregister(base_id);
    int valid = started == 2 && restarted == 0 &&
                driver_test_starts == 3 && driver_test_stops == 3 &&
                dependent_unregistered == 0 && base_unregistered == 0;
    if (!valid) {
        serial64_write("Mich x86_64: driver values=");
        serial64_hex((u32)started);
        serial64_hex((u32)restarted);
        serial64_hex(driver_test_starts);
        serial64_hex(driver_test_stops);
        serial64_hex((u32)dependent_unregistered);
        serial64_hex((u32)base_unregistered);
        serial64_write("\n");
    }
    object_release(devices[0]);
    object_release(devices[1]);
    return valid ? 0 : -20;
}

static int driver_crash_stress_self_test(struct kernel_object *device) {
    if (!device || irq_resource_set_backend(IRQ_CONTROLLER_IOAPIC,
                                             stress_irq_mask,
                                             stress_irq_release))
        return -1;
    u32 free_pages = pmm_free_pages();
    u32 objects = object_active_count();
    u32 handles = handle_active_count();
    u32 mmio = resource_active_count(KOBJECT_MMIO);
    u32 irqs = resource_active_count(KOBJECT_IRQ);
    u32 dmas = resource_active_count(KOBJECT_DMA);
    u32 bridges = bridge_active_count();
    u32 mappings = vm64_object_mapping_count(test_env->target_space);
    u32 vectors = vector64_available();
    struct driver_user_manifest manifest;
    u8 *bytes = (u8 *)&manifest;
    for (usize_t index = 0; index < sizeof(manifest); index++) bytes[index] = 0;
    manifest.abi_version = DRIVER_USER_ABI_VERSION;
    manifest.size = sizeof(manifest);
    const char *name = "mich.stress.domain";
    for (u32 index = 0; name[index]; index++) manifest.name[index] = name[index];
    manifest.restart_policy = DRIVER_RESTART_ON_FAILURE;
    manifest.max_restarts = 16;
    manifest.backoff_ticks = 1;
    manifest.reset_policy = DRIVER_RESET_IF_SUPPORTED;
    manifest.argument = 19;
    manifest.match_count = 1;
    const struct pci_resource *pci = pci_resource_get(device);
    if (!pci) return -1;
    manifest.matches[0].vendor_id = pci->vendor_id;
    manifest.matches[0].device_id = pci->device_id;
    manifest.matches[0].class_code = pci->class_code;
    manifest.matches[0].subclass = pci->subclass;
    manifest.matches[0].programming_interface = pci->programming_interface;
    manifest.request_count = 4;
    manifest.requests[0].kind = DRIVER_RESOURCE_PCI;
    manifest.requests[0].rights = KRIGHT_READ | KRIGHT_CONTROL;
    manifest.requests[1].kind = DRIVER_RESOURCE_BAR;
    manifest.requests[1].rights = KRIGHT_READ | KRIGHT_WRITE | KRIGHT_MAP;
    manifest.requests[2].kind = DRIVER_RESOURCE_DMA;
    manifest.requests[2].rights = KRIGHT_READ | KRIGHT_WRITE | KRIGHT_MAP;
    manifest.requests[2].amount = 2;
    manifest.requests[2].limit = 0x3FFFFFFFULL;
    manifest.requests[3].kind = DRIVER_RESOURCE_BRIDGE;
    manifest.requests[3].rights = KRIGHT_READ | KRIGHT_WAIT;
    struct driver_domain *domain = driver_domain_create_user(&manifest, device);
    if (!domain || driver_domain_apply_manifest(domain, &manifest,
                                                 test_env->resource_provider)) {
        if (domain) driver_domain_destroy(domain);
        return -1;
    }
    struct kernel_object *irq = irq_resource_create_kind(
        IRQ_CONTROLLER_IOAPIC, 123, 0x3F, IRQ_TRIGGER_EDGE,
        IRQ_POLARITY_HIGH);
    if (!irq || driver_domain_add_resource_kind(
            domain, irq, KRIGHT_CONTROL | KRIGHT_WAIT,
            DRIVER_RESOURCE_IRQ, 0, 0)) {
        if (irq) object_release(irq);
        driver_domain_destroy(domain);
        return -1;
    }
    object_release(irq);
    if (driver_domain_start(domain)) {
        driver_domain_destroy(domain);
        return -1;
    }
    struct driver_bootstrap_info irq_boot;
    int source_ok = 0;
    int dma_address_ok = 0;
    if (!driver_domain_bootstrap(domain->pid, &irq_boot)) {
        for (u32 i = 0; i < irq_boot.resource_count; i++) {
            struct driver_bootstrap_resource *r = &irq_boot.resources[i];
            if (r->kind == DRIVER_RESOURCE_IRQ &&
                (r->flags & DRIVER_BOOTSTRAP_IRQ_SOURCE_MASK) == 123)
                source_ok = 1;
            if (r->kind == DRIVER_RESOURCE_DMA && r->address &&
                r->address + r->length - 1 <= 0x3FFFFFFFULL)
                dma_address_ok = 1;
        }
    }
    if (!source_ok || !dma_address_ok) {
        driver_domain_destroy(domain);
        return -1;
    }
    stress_irq_masks = 0;
    stress_irq_releases = 0;
    int valid = 1;
    for (u32 cycle = 0; cycle < 16 && valid; cycle++) {
        struct kernel_object *bar = 0;
        struct kernel_object *dma = 0;
        struct kernel_object *bridge = 0;
        struct kernel_object *irq_object = 0;
        for (u32 index = 0; index < domain->resource_count; index++) {
            struct driver_domain_resource *resource = &domain->resources[index];
            if (resource->kind == DRIVER_RESOURCE_BAR) bar = resource->object;
            if (resource->kind == DRIVER_RESOURCE_DMA) dma = resource->object;
            if (resource->kind == DRIVER_RESOURCE_BRIDGE) bridge = resource->object;
            if (resource->kind == DRIVER_RESOURCE_IRQ) irq_object = resource->object;
        }
        const struct mmio_resource *bar_info = mmio_resource_get(bar);
        const struct dma_resource *dma_info = dma_resource_get(dma);
        u32 firmware_size = 0;
        struct kernel_object *firmware_file =
            firmware_open("init64", &firmware_size);
        u32 firmware_handle = firmware_file ? handle_open(
            test_env->target, firmware_file, KRIGHT_READ) : 0;
        if (firmware_file) object_release(firmware_file);
        if (!bar_info || !dma_info || !bridge || !irq_object ||
            !firmware_handle || !firmware_size ||
            vm64_map_object(test_env->target_space, VM64_DRIVER_BASE,
                            bar, bar_info->physical, bar_info->length, 1,
                            bar_info->cache_mode) ||
            vm64_map_object(test_env->target_space,
                            VM64_DRIVER_BASE + 0x10000, dma,
                            dma_info->physical, (usize_t)dma_info->pages * 4096,
                            1, VM64_CACHE_WB) ||
            irq_resource_bind(irq_object, bridge) ||
            irq_resource_set_mask(irq_object, 0) ||
            irq_resource_signal(irq_object)) {
            valid = 0;
            break;
        }
        struct kernel_object *old_bridge = bridge;
        int pid = domain->pid;
        driver_supervisor_task_died(pid, 1, cycle * 32);
        struct bridge_notification notification;
        valid = domain->state == DRIVER_DOMAIN_BACKOFF &&
                domain->pid < 0 &&
                vm64_object_mapping_count(test_env->target_space) == mappings &&
                !irq_resource_get(irq_object)->binding &&
                irq_resource_get(irq_object)->masked &&
                domain->resources[domain->bridge_index].object != old_bridge &&
                bridge_endpoint_read(
                    domain->resources[domain->bridge_index].object,
                    &notification) < 0 &&
                handle_task_count(test_env->target) == 0;
        if (!valid) break;
        driver_supervisor_tick(domain->restart_deadline);
        valid = domain->state == DRIVER_DOMAIN_RUNNING &&
                domain->generation == cycle + 2 &&
                handle_task_count(test_env->target) == domain->resource_count;
    }
    if (domain->state == DRIVER_DOMAIN_RUNNING) {
        driver_supervisor_task_died(domain->pid, 0, 1024);
        if (domain->state != DRIVER_DOMAIN_STOPPED) valid = 0;
    }
    driver_domain_destroy(domain);
    valid = valid && pmm_free_pages() == free_pages &&
            object_active_count() == objects &&
            handle_active_count() == handles &&
            resource_active_count(KOBJECT_MMIO) == mmio &&
            resource_active_count(KOBJECT_IRQ) == irqs &&
            resource_active_count(KOBJECT_DMA) == dmas &&
            bridge_active_count() == bridges &&
            vm64_object_mapping_count(test_env->target_space) == mappings &&
            vector64_available() == vectors &&
            stress_irq_masks >= 32 && stress_irq_releases == 1;
    return valid ? 0 : -1;
}

static struct driver_domain *driver_passport_domain(
    struct kernel_object *device, const struct driver_user_manifest *source,
    const struct driver_recovery_profile *fallback,
    const struct driver_recovery_selector *selector, u32 triggers,
    const struct driver_crash_circuit_policy *policy, u32 max_restarts) {
    struct driver_user_manifest manifest = *source;
    manifest.max_restarts = max_restarts;
    manifest.backoff_ticks = 1;
    struct driver_domain *domain = driver_domain_create_user(&manifest, device);
    if (!domain || (fallback &&
                    (driver_domain_set_recovery_fallback(domain, fallback) ||
                     driver_domain_set_recovery_fallback_triggers(domain,
                                                                  triggers) ||
                     (selector && driver_domain_set_recovery_fallback_selector(
                         domain, selector)))) ||
        (policy && driver_domain_set_crash_circuit_policy(domain, policy)) ||
        driver_domain_apply_manifest(domain, &manifest,
                                     test_env->resource_provider) ||
        driver_domain_start(domain)) {
        if (domain) driver_domain_destroy(domain);
        return 0;
    }
    return domain;
}

static int driver_crash_passport_self_test(
    struct kernel_object *device, const struct driver_user_manifest *manifest) {
    struct driver_domain *domain = driver_passport_domain(device, manifest, 0, 0, 0, 0, 8);
    if (!domain) return -1;
    int pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 14, 7, 0x400100, 0xDEAD000,
                                        100);
    driver_supervisor_task_died(pid, 142, 100);
    struct driver_domain_status status;
    int passport_ok = !driver_domain_status(domain, &status) &&
        status.id == domain->id && status.state == DRIVER_DOMAIN_BACKOFF &&
        status.pid == -1 && status.generation == 1 &&
        status.image_id == manifest->image_id &&
        status.capabilities == manifest->capabilities &&
        status.argument == manifest->argument &&
        status.recovery_profile == DRIVER_RECOVERY_PRIMARY &&
        !status.fallback_enabled && !status.fallback_used &&
        status.restart_count == 1 &&
        status.restart_deadline == domain->restart_deadline &&
        status.crash_repeat_count == 1 &&
        status.crash_repeat_deadline == 100 + DRIVER_CRASH_REPEAT_WINDOW_TICKS &&
        status.crash_policy.repeat_limit == DRIVER_CRASH_REPEAT_LIMIT &&
        status.crash_policy.repeat_window_ticks ==
            DRIVER_CRASH_REPEAT_WINDOW_TICKS &&
        status.terminal_reason == DRIVER_TERMINAL_NONE &&
        status.last_decision == DRIVER_RECOVERY_DECISION_RESTART &&
        status.last_crash.kind == DRIVER_CRASH_USER_EXCEPTION &&
        status.last_crash.code == 142 && status.last_crash.generation == 1 &&
        status.last_crash.ticks == 100 && status.last_crash.vector == 14 &&
        status.last_crash.error == 7 && status.last_crash.rip == 0x400100 &&
        status.last_crash.address == 0xDEAD000;
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 14, 7, 0x400100, 0xDEAD000,
                                        102);
    driver_supervisor_task_died(pid, 142, 102);
    int circuit_ok = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_FAILED && status.pid == -1 &&
        status.generation == 2 && status.restart_count == 1 &&
        status.crash_repeat_count == DRIVER_CRASH_REPEAT_LIMIT &&
        !status.restart_deadline &&
        status.terminal_reason == DRIVER_TERMINAL_CRASH_CIRCUIT &&
        status.last_decision == DRIVER_RECOVERY_DECISION_CRASH_CIRCUIT;
    driver_supervisor_tick(1000);
    circuit_ok = circuit_ok && domain->state == DRIVER_DOMAIN_FAILED;
    driver_domain_destroy(domain);
    if (!passport_ok || !circuit_ok) return -1;

    domain = driver_passport_domain(device, manifest, 0, 0, 0, 0, 8);
    if (!domain) return -1;
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 13, 0, 0x400200, 0, 200);
    driver_supervisor_task_died(pid, 141, 200);
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(
        pid, 13, 0, 0x400200, 0, 200 + DRIVER_CRASH_REPEAT_WINDOW_TICKS);
    driver_supervisor_task_died(pid, 141,
                                200 + DRIVER_CRASH_REPEAT_WINDOW_TICKS);
    int window_ok = domain->state == DRIVER_DOMAIN_BACKOFF &&
        domain->crash_repeat_count == 1;
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 13, 0, 0x400201, 0, 267);
    driver_supervisor_task_died(pid, 141, 267);
    int exact_ok = domain->state == DRIVER_DOMAIN_BACKOFF &&
        domain->last_crash.rip == 0x400201 && domain->crash_repeat_count == 1;
    driver_domain_destroy(domain);
    if (!window_ok || !exact_ok) return -1;

    struct driver_recovery_profile iommu_fallback;
    iommu_fallback.image_id = 7;
    iommu_fallback.capabilities = 0;
    iommu_fallback.argument = 0xFA11BACULL;
    domain = driver_passport_domain(device, manifest, &iommu_fallback, 0,
                                     DRIVER_RECOVERY_TRIGGER_ALL, 0, 8);
    if (!domain) return -1;
    u32 id = domain->id;
    driver_supervisor_report_iommu_fault(id, 2, 0x1234, 5, 1,
                                         0x12345000, 300);
    int iommu_ok = !driver_domain_quarantine(id) &&
        !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_QUARANTINED && status.pid == -1 &&
        status.terminal_reason == DRIVER_TERMINAL_IOMMU_FAULT &&
        status.last_decision == DRIVER_RECOVERY_DECISION_IOMMU_QUARANTINE &&
        status.last_crash.kind == DRIVER_CRASH_IOMMU &&
        status.last_crash.generation == 1 && status.last_crash.ticks == 300 &&
        status.last_crash.segment == 2 && status.last_crash.source_id == 0x1234 &&
        status.last_crash.reason == 5 && status.last_crash.write == 1 &&
        status.last_crash.address == 0x12345000 &&
        status.fallback_enabled && !status.fallback_used &&
        status.fallback_triggers == DRIVER_RECOVERY_TRIGGER_ALL &&
        status.image_id == manifest->image_id &&
        status.recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_NONE &&
        !status.crash_repeat_count && !status.crash_repeat_deadline;
    int released = !driver_domain_admin_release(domain);
    domain = driver_passport_domain(device, manifest, 0, 0, 0, 0, 8);
    if (!domain) return -1;
    u32 manual_id = domain->id;
    int manual_ok = !driver_domain_quarantine(manual_id) &&
        !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_QUARANTINED && status.pid == -1 &&
        status.terminal_reason == DRIVER_TERMINAL_QUARANTINE &&
        status.last_decision == DRIVER_RECOVERY_DECISION_MANUAL_QUARANTINE;
    int manual_released = !driver_domain_admin_release(domain);
    return iommu_ok && released && manual_ok && manual_released ? 0 : -1;
}

static int driver_crash_policy_self_test(
    struct kernel_object *device, const struct driver_user_manifest *source) {
    struct driver_user_manifest manifest = *source;
    manifest.max_restarts = 8;
    manifest.backoff_ticks = 1;
    struct driver_crash_circuit_policy policy;
    policy.repeat_limit = 3;
    policy.repeat_window_ticks = 8;
    struct driver_crash_circuit_policy zero_limit = policy;
    struct driver_crash_circuit_policy large_limit = policy;
    struct driver_crash_circuit_policy zero_window = policy;
    zero_limit.repeat_limit = 0;
    large_limit.repeat_limit = DRIVER_CRASH_REPEAT_LIMIT_MAX + 1;
    zero_window.repeat_window_ticks = 0;
    struct driver_domain *domain = driver_domain_create_user(&manifest, device);
    if (!domain || driver_crash_circuit_policy_validate(&policy) ||
        !driver_crash_circuit_policy_validate(&zero_limit) ||
        !driver_crash_circuit_policy_validate(&large_limit) ||
        !driver_crash_circuit_policy_validate(&zero_window) ||
        driver_domain_set_crash_circuit_policy(domain, &zero_limit) >= 0 ||
        driver_domain_set_crash_circuit_policy(domain, &large_limit) >= 0 ||
        driver_domain_set_crash_circuit_policy(domain, &zero_window) >= 0 ||
        driver_domain_set_crash_circuit_policy(domain, &policy) ||
        driver_domain_apply_manifest(domain, &manifest,
                                     test_env->resource_provider) ||
        driver_domain_start(domain)) {
        if (domain) driver_domain_destroy(domain);
        return -1;
    }
    struct driver_domain_status status;
    int valid = !driver_domain_status(domain, &status) &&
        status.crash_policy.repeat_limit == policy.repeat_limit &&
        status.crash_policy.repeat_window_ticks == policy.repeat_window_ticks &&
        driver_domain_set_crash_circuit_policy(domain, &policy) < 0;
    int pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400500, 0, 100);
    driver_supervisor_task_died(pid, 134, 100);
    valid = valid && domain->state == DRIVER_DOMAIN_BACKOFF &&
            domain->crash_repeat_count == 1 &&
            domain->crash_repeat_deadline == 108;
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400500, 0, 102);
    driver_supervisor_task_died(pid, 134, 102);
    valid = valid && domain->state == DRIVER_DOMAIN_BACKOFF &&
            domain->generation == 2 && domain->crash_repeat_count == 2 &&
            domain->crash_repeat_deadline == 108;
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400500, 0, 105);
    driver_supervisor_task_died(pid, 134, 105);
    valid = valid && !driver_domain_status(domain, &status) &&
            status.state == DRIVER_DOMAIN_FAILED && status.pid == -1 &&
            status.generation == 3 && status.crash_repeat_count == 3 &&
            status.crash_repeat_deadline == 108 && !status.restart_deadline &&
            status.terminal_reason == DRIVER_TERMINAL_CRASH_CIRCUIT &&
            status.last_decision == DRIVER_RECOVERY_DECISION_CRASH_CIRCUIT &&
            status.crash_policy.repeat_limit == policy.repeat_limit &&
            status.crash_policy.repeat_window_ticks == policy.repeat_window_ticks;
    driver_supervisor_tick(1000);
    valid = valid && domain->state == DRIVER_DOMAIN_FAILED;
    driver_domain_destroy(domain);
    return valid ? 0 : -1;
}

static int driver_recovery_launch_decision_self_test(
    struct kernel_object *device, const struct driver_user_manifest *source) {
    struct driver_user_manifest manifest = *source;
    manifest.image_id = 15;
    struct driver_domain *domain = driver_domain_create_user(&manifest, device);
    if (!domain || driver_domain_apply_manifest(domain, &manifest,
                                                 test_env->resource_provider)) {
        if (domain) driver_domain_destroy(domain);
        return -1;
    }
    struct driver_domain_status status;
    int primary_failed = driver_domain_start(domain) < 0 &&
        !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_FAILED && status.pid == -1 &&
        status.terminal_reason == DRIVER_TERMINAL_LAUNCH_FAILURE &&
        status.last_decision == DRIVER_RECOVERY_DECISION_LAUNCH_FAILURE &&
        status.recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_NONE;
    driver_domain_destroy(domain);

    struct driver_recovery_profile fallback;
    fallback.image_id = 15;
    fallback.capabilities = 0;
    fallback.argument = 0x4C41554E4348ULL;
    domain = driver_passport_domain(
        device, source, &fallback, 0,
        DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT, 0, 8);
    if (!domain) return -1;
    int pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400600, 0, 600);
    driver_supervisor_task_died(pid, 134, 600);
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400600, 0, 602);
    driver_supervisor_task_died(pid, 134, 602);
    int fallback_pending = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_BACKOFF && status.pid == -1 &&
        status.generation == 2 && status.image_id == fallback.image_id &&
        status.fallback_used &&
        status.recovery_audit.trigger == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        status.recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_SELECTED &&
        status.recovery_audit.profile.image_id == fallback.image_id &&
        status.recovery_audit.profile.argument == fallback.argument &&
        status.recovery_audit.passport.generation == 2 &&
        status.recovery_audit.passport.ticks == 602 &&
        status.recovery_audit.passport.rip == 0x400600;
    driver_supervisor_tick(domain->restart_deadline);
    int fallback_failed = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_FAILED && status.pid == -1 &&
        status.generation == 2 && status.image_id == fallback.image_id &&
        status.fallback_used &&
        status.terminal_reason == DRIVER_TERMINAL_LAUNCH_FAILURE &&
        status.last_decision == DRIVER_RECOVERY_DECISION_LAUNCH_FAILURE &&
        status.recovery_audit.trigger == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        status.recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_SELECTED &&
        status.recovery_audit.profile.image_id == fallback.image_id &&
        status.recovery_audit.passport.generation == 2 &&
        status.recovery_audit.passport.ticks == 602 &&
        status.recovery_audit.passport.rip == 0x400600;
    driver_domain_destroy(domain);
    return primary_failed && fallback_pending && fallback_failed ? 0 : -1;
}

static int driver_recovery_teardown_audit_self_test(
    struct kernel_object *device, const struct driver_user_manifest *manifest) {
    struct driver_recovery_profile fallback;
    fallback.image_id = 7;
    fallback.capabilities = 0;
    fallback.argument = 0x54454152444F574EULL;
    struct driver_domain *domain = driver_passport_domain(
        device, manifest, &fallback, 0,
        DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT, 0, 8);
    if (!domain) return -1;
    struct driver_domain *slot = domain;
    int pid = domain->pid;
    supervisor_test_quiesce_fail = 1;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400610, 0, 610);
    driver_supervisor_task_died(pid, 134, 610);
    supervisor_test_quiesce_fail = 0;
    struct driver_domain_status status;
    int quarantined = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_QUARANTINED && status.pid == -1 &&
        status.generation == 1 && status.fallback_enabled &&
        !status.fallback_used &&
        status.terminal_reason == DRIVER_TERMINAL_TEARDOWN_FAILURE &&
        status.last_decision == DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE &&
        status.last_crash.kind == DRIVER_CRASH_USER_EXCEPTION &&
        status.last_crash.generation == 1 && status.last_crash.ticks == 610 &&
        status.last_crash.rip == 0x400610 &&
        status.recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_NONE;
    for (u32 index = 0; index < DRIVER_DOMAIN_RESOURCE_MAX; index++)
        if (domain->issued_handles[index]) quarantined = 0;
    int released = !driver_domain_admin_release(domain);

    struct driver_domain *reused = driver_passport_domain(
        device, manifest, 0, 0, 0, 0, 8);
    int clean_reuse = reused == slot && !driver_domain_status(reused, &status) &&
        status.state == DRIVER_DOMAIN_RUNNING && status.generation == 1 &&
        supervisor_test_recovery_audit_clear(&status.recovery_audit);
    if (reused) driver_domain_destroy(reused);
    return quarantined && released && clean_reuse ? 0 : -1;
}

static int driver_recovery_fallback_self_test(
    struct kernel_object *device, const struct driver_user_manifest *manifest) {
    struct driver_recovery_profile profile;
    profile.image_id = 7;
    profile.capabilities = 0;
    profile.argument = 0xFA11BACULL;
    struct driver_recovery_profile invalid_image = profile;
    invalid_image.image_id = DRIVER_USER_IMAGE_MAX;
    struct driver_recovery_profile invalid_capabilities = profile;
    invalid_capabilities.capabilities = 1;
    struct driver_domain *invalid_domain =
        driver_domain_create_user(manifest, device);
    int invalid_rejected = invalid_domain &&
        driver_recovery_fallback_triggers_validate(0) < 0 &&
        driver_recovery_fallback_triggers_validate(
            DRIVER_RECOVERY_TRIGGER_ALL + 1) < 0 &&
        driver_domain_set_recovery_fallback_triggers(
            invalid_domain, DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT) < 0 &&
        driver_domain_set_recovery_fallback(invalid_domain, &invalid_image) < 0 &&
        driver_domain_set_recovery_fallback(invalid_domain,
                                            &invalid_capabilities) < 0 &&
        !driver_domain_set_recovery_fallback(invalid_domain, &profile) &&
        driver_domain_set_recovery_fallback_triggers(invalid_domain, 0) < 0 &&
        driver_domain_set_recovery_fallback_triggers(
            invalid_domain, DRIVER_RECOVERY_TRIGGER_ALL + 1) < 0;
    if (invalid_domain) driver_domain_destroy(invalid_domain);
    if (!invalid_rejected) return -1;

    struct driver_domain *domain =
        driver_passport_domain(device, manifest, &profile, 0,
                                DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT, 0, 8);
    if (!domain) return -1;
    int pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400300, 0, 400);
    driver_supervisor_task_died(pid, 134, 400);
    driver_supervisor_tick(domain->restart_deadline);
    int primary_restart = domain->state == DRIVER_DOMAIN_RUNNING &&
        domain->generation == 2 && domain->image_id == manifest->image_id &&
        domain->recovery_profile == DRIVER_RECOVERY_PRIMARY &&
        !domain->fallback_used;
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400300, 0, 402);
    driver_supervisor_task_died(pid, 134, 402);
    int fallback_pending = domain->state == DRIVER_DOMAIN_BACKOFF &&
        domain->generation == 2 && domain->image_id == profile.image_id &&
        domain->capabilities == profile.capabilities &&
        domain->argument == profile.argument &&
        domain->recovery_profile == DRIVER_RECOVERY_FALLBACK &&
        domain->fallback_enabled && domain->fallback_used &&
        domain->fallback_triggers == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        domain->last_decision == DRIVER_RECOVERY_DECISION_FALLBACK &&
        domain->recovery_audit.trigger == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        domain->recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_SELECTED &&
        domain->recovery_audit.profile.image_id == profile.image_id &&
        domain->recovery_audit.profile.argument == profile.argument &&
        domain->recovery_audit.passport.generation == 2 &&
        domain->recovery_audit.passport.ticks == 402 &&
        domain->recovery_audit.passport.rip == 0x400300 &&
        !domain->crash_repeat_count && !domain->crash_repeat_deadline &&
        domain->restart_deadline == 403;
    driver_supervisor_tick(domain->restart_deadline);
    int fallback_started = domain->state == DRIVER_DOMAIN_RUNNING &&
        domain->generation == 3 && domain->image_id == profile.image_id &&
        driver_domain_set_recovery_fallback(domain, &profile) < 0 &&
        driver_domain_set_recovery_fallback_triggers(
            domain, DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT) < 0;
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400300, 0, 404);
    driver_supervisor_task_died(pid, 134, 404);
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400300, 0, 407);
    driver_supervisor_task_died(pid, 134, 407);
    struct driver_domain_status status;
    int fallback_exhausted = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_FAILED && status.pid == -1 &&
        status.generation == 4 && status.recovery_profile == DRIVER_RECOVERY_FALLBACK &&
        status.fallback_enabled && status.fallback_used &&
        status.crash_repeat_count == DRIVER_CRASH_REPEAT_LIMIT &&
        !status.restart_deadline &&
        status.terminal_reason == DRIVER_TERMINAL_CRASH_CIRCUIT &&
        status.last_decision == DRIVER_RECOVERY_DECISION_CRASH_CIRCUIT &&
        status.recovery_audit.trigger == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        status.recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_UNAVAILABLE &&
        status.recovery_audit.profile.image_id == profile.image_id &&
        status.recovery_audit.passport.generation == 4 &&
        status.recovery_audit.passport.ticks == 407;
    driver_domain_destroy(domain);

    struct driver_crash_circuit_policy circuit_policy;
    circuit_policy.repeat_limit = DRIVER_CRASH_REPEAT_LIMIT;
    circuit_policy.repeat_window_ticks = 8;
    domain = driver_passport_domain(
        device, manifest, &profile, 0, DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT,
        &circuit_policy, 8);
    if (!domain) return -1;
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400300, 0, 500);
    driver_supervisor_task_died(pid, 134, 500);
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400300, 0, 502);
    driver_supervisor_task_died(pid, 134, 502);
    int circuit_excluded = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_FAILED &&
        status.terminal_reason == DRIVER_TERMINAL_CRASH_CIRCUIT &&
        status.last_decision == DRIVER_RECOVERY_DECISION_CRASH_CIRCUIT &&
        status.fallback_triggers == DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT &&
        status.recovery_audit.trigger == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        status.recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_UNAVAILABLE &&
        status.recovery_audit.profile.image_id == profile.image_id &&
        status.recovery_audit.passport.generation == 2 &&
        status.recovery_audit.passport.ticks == 502 && !status.fallback_used;
    driver_domain_destroy(domain);

    struct driver_user_manifest never_manifest = *manifest;
    never_manifest.restart_policy = DRIVER_RESTART_NEVER;
    domain = driver_passport_domain(
        device, &never_manifest, &profile, 0,
        DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT, 0, 0);
    if (!domain) return -1;
    driver_supervisor_task_died(domain->pid, 1, 600);
    int restart_never = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_FAILED &&
        status.terminal_reason == DRIVER_TERMINAL_RESTART_LIMIT &&
        status.last_decision == DRIVER_RECOVERY_DECISION_RESTART_LIMIT &&
        !status.fallback_used;
    driver_domain_destroy(domain);
    return primary_restart && fallback_pending && fallback_started &&
           fallback_exhausted && circuit_excluded && restart_never ? 0 : -1;
}

static __attribute__((cold, noinline, optimize("Os"))) int
    driver_recovery_selector_self_test(
        struct kernel_object *device,
        const struct driver_user_manifest *manifest) {
    const struct pci_resource *pci = pci_resource_get(device);
    if (!pci) return -1;
    struct driver_recovery_profile profile;
    profile.image_id = 7;
    profile.capabilities = 0;
    profile.argument = 0x53414645ULL;
    struct driver_recovery_selector selector;
    selector.vendor_id = pci->vendor_id;
    selector.device_id = pci->device_id;
    selector.fingerprint.kind = DRIVER_CRASH_USER_EXCEPTION;
    selector.fingerprint.code = 134;
    selector.fingerprint.vector = 6;
    selector.fingerprint.error = 0;
    selector.fingerprint.rip = 0x400700;
    selector.fingerprint.address = 0;
    struct driver_recovery_selector invalid = selector;
    invalid.fingerprint.kind = DRIVER_CRASH_EXIT;
    struct driver_domain *invalid_domain =
        driver_domain_create_user(manifest, device);
    int invalid_rejected = invalid_domain &&
        driver_recovery_selector_validate(&invalid) < 0 &&
        !driver_domain_set_recovery_fallback(invalid_domain, &profile) &&
        driver_domain_set_recovery_fallback_selector(
            invalid_domain, &invalid) < 0 &&
        !driver_domain_set_recovery_fallback_selector(
            invalid_domain, &selector);
    if (invalid_domain) driver_domain_destroy(invalid_domain);
    if (!invalid_rejected) return -1;

    struct driver_domain *domain = driver_passport_domain(
        device, manifest, &profile, &selector,
        DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT, 0, 8);
    if (!domain) return -1;
    int pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400700, 0, 700);
    driver_supervisor_task_died(pid, 134, 700);
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400700, 0, 702);
    driver_supervisor_task_died(pid, 134, 702);
    struct driver_domain_status status;
    int selected = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_BACKOFF && status.generation == 2 &&
        status.image_id == profile.image_id &&
        status.recovery_profile == DRIVER_RECOVERY_FALLBACK &&
        status.fallback_selector_enabled &&
        status.fallback_selector.vendor_id == selector.vendor_id &&
        status.fallback_selector.device_id == selector.device_id &&
        status.fallback_selector.fingerprint.rip == selector.fingerprint.rip &&
        status.fallback_used &&
        status.last_decision == DRIVER_RECOVERY_DECISION_FALLBACK &&
        status.recovery_audit.trigger == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        status.recovery_audit.outcome == DRIVER_RECOVERY_AUDIT_SELECTED &&
        status.recovery_audit.profile.image_id == profile.image_id &&
        status.recovery_audit.profile.argument == profile.argument &&
        status.recovery_audit.passport.generation == 2 &&
        status.recovery_audit.passport.ticks == 702 &&
        status.recovery_audit.passport.rip == selector.fingerprint.rip;
    driver_supervisor_tick(domain->restart_deadline);
    selected = selected && domain->state == DRIVER_DOMAIN_RUNNING &&
        domain->generation == 3 && domain->image_id == profile.image_id &&
        driver_domain_set_recovery_fallback_selector(domain, &selector) < 0;
    driver_domain_destroy(domain);

    domain = driver_passport_domain(device, manifest, &profile, &selector,
                                    DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT,
                                    0, 8);
    if (!domain) return -1;
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400701, 0, 730);
    driver_supervisor_task_died(pid, 134, 730);
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400701, 0, 732);
    driver_supervisor_task_died(pid, 134, 732);
    int fingerprint_rejected = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_FAILED &&
        status.terminal_reason == DRIVER_TERMINAL_CRASH_CIRCUIT &&
        status.last_decision == DRIVER_RECOVERY_DECISION_CRASH_CIRCUIT &&
        status.recovery_audit.trigger == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        status.recovery_audit.outcome ==
            DRIVER_RECOVERY_AUDIT_SELECTOR_MISMATCH &&
        status.recovery_audit.profile.image_id == profile.image_id &&
        status.recovery_audit.passport.generation == 2 &&
        status.recovery_audit.passport.ticks == 732 &&
        status.recovery_audit.passport.rip == 0x400701 && !status.fallback_used;
    driver_domain_destroy(domain);

    selector.device_id ^= 1;
    domain = driver_passport_domain(device, manifest, &profile, &selector,
                                    DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT,
                                    0, 8);
    if (!domain) return -1;
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400700, 0, 760);
    driver_supervisor_task_died(pid, 134, 760);
    driver_supervisor_tick(domain->restart_deadline);
    pid = domain->pid;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400700, 0, 762);
    driver_supervisor_task_died(pid, 134, 762);
    int device_rejected = !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_FAILED &&
        status.terminal_reason == DRIVER_TERMINAL_CRASH_CIRCUIT &&
        status.recovery_audit.trigger == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        status.recovery_audit.outcome ==
            DRIVER_RECOVERY_AUDIT_SELECTOR_MISMATCH &&
        status.recovery_audit.profile.image_id == profile.image_id &&
        status.recovery_audit.passport.generation == 2 &&
        status.recovery_audit.passport.ticks == 762 &&
        status.recovery_audit.passport.rip == 0x400700 && !status.fallback_used;
    driver_domain_destroy(domain);
    return selected && fingerprint_rejected && device_rejected ? 0 : -1;
}

static __attribute__((cold, noinline, optimize("Os"))) int
    driver_manager_recovery_register_self_test(
        struct kernel_object *device,
        const struct driver_user_manifest *source) {
    const struct pci_resource *pci = pci_resource_get(device);
    if (!pci) return -1;
    struct driver_recovery_profile fallback;
    fallback.image_id = 7;
    fallback.capabilities = 0;
    fallback.argument = 0xFA11BACULL;
    struct driver_recovery_selector selector;
    selector.vendor_id = pci->vendor_id;
    selector.device_id = pci->device_id;
    selector.fingerprint.kind = DRIVER_CRASH_USER_EXCEPTION;
    selector.fingerprint.code = 134;
    selector.fingerprint.vector = 6;
    selector.fingerprint.error = 0;
    selector.fingerprint.rip = 0x400500;
    selector.fingerprint.address = 0;
    struct driver_crash_circuit_policy policy;
    policy.repeat_limit = DRIVER_CRASH_REPEAT_LIMIT + 1;
    policy.repeat_window_ticks = 8;
    struct driver_manager_recovery_config config;
    config.fallback = fallback;
    config.fallback_selector = selector;
    config.crash_policy = policy;
    config.fallback_enabled = 1;
    config.fallback_selector_enabled = 2;
    config.fallback_triggers = DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT;
    config.crash_policy_enabled = 1;
    struct kernel_object *devices[1];
    devices[0] = device;
    driver_manager_init(test_env->resource_provider);
    int inventory = driver_manager_set_devices(devices, 1);
    int invalid_rejected =
        driver_manager_register_recovery(source, &config) < 0 &&
        !driver_manager_manifest_count() && !driver_manager_binding_count() &&
        !driver_manager_domain(device);
    config.fallback_selector_enabled = 1;
    config.fallback_triggers = DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT;
    invalid_rejected = invalid_rejected &&
        driver_manager_register_recovery(source, &config) < 0 &&
        !driver_manager_manifest_count() && !driver_manager_binding_count() &&
        !driver_manager_domain(device);
    config.fallback_triggers = DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT;
    int id = inventory == 0 && invalid_rejected ?
        driver_manager_register_recovery(source, &config) : -1;
    struct driver_domain *domain = driver_manager_domain(device);
    struct driver_domain_status status;
    int locked = driver_manager_set_recovery_fallback_selector(
        id, &selector) < 0;
    int active = id > 0 && domain && !driver_domain_status(domain, &status) &&
        status.state == DRIVER_DOMAIN_RUNNING && status.generation == 1 &&
        status.fallback_enabled && status.fallback_selector_enabled &&
        !status.fallback_used &&
        status.fallback_triggers == DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT &&
        status.fallback_selector.vendor_id == selector.vendor_id &&
        status.fallback_selector.device_id == selector.device_id &&
        status.fallback_selector.fingerprint.rip == selector.fingerprint.rip &&
        status.crash_policy.repeat_limit == policy.repeat_limit &&
        status.crash_policy.repeat_window_ticks == policy.repeat_window_ticks &&
        locked && driver_manager_binding_count() == 1 &&
        driver_manager_manifest_count() == 1;
    int removed = driver_manager_device_removed(device);
    int unregistered = driver_manager_unregister(id);
    driver_manager_init(0);
    return active && !removed && !unregistered ? 0 : -1;
}

static int driver_manager_fallback_self_test(
    struct kernel_object *device, const struct driver_user_manifest *source) {
    struct driver_user_manifest manifest = *source;
    for (u32 index = 0; index < DRIVER_USER_NAME_MAX; index++)
        manifest.name[index] = 0;
    const char name[] = "mich.mgr";
    for (u32 index = 0; name[index]; index++) manifest.name[index] = name[index];
    manifest.max_restarts = 1;
    struct driver_recovery_profile fallback;
    fallback.image_id = 7;
    fallback.capabilities = 0;
    fallback.argument = 0xFA11BACULL;
    struct driver_recovery_profile invalid_image = fallback;
    invalid_image.image_id = DRIVER_USER_IMAGE_MAX;
    struct driver_recovery_profile invalid_capabilities = fallback;
    invalid_capabilities.capabilities = 1;
    struct driver_crash_circuit_policy policy;
    policy.repeat_limit = DRIVER_CRASH_REPEAT_LIMIT + 1;
    policy.repeat_window_ticks = 8;
    struct driver_crash_circuit_policy invalid_policy = policy;
    invalid_policy.repeat_limit = 0;
    driver_manager_init(test_env->resource_provider);
    int id = driver_manager_register(&manifest);
    struct kernel_object *devices[1];
    devices[0] = device;
    int configured = id > 0 &&
        !driver_manager_set_recovery_fallback(id, &fallback);
    int invalid_rejected = configured &&
        driver_manager_set_recovery_fallback(id, &invalid_image) < 0 &&
        driver_manager_set_recovery_fallback(id, &invalid_capabilities) < 0 &&
        driver_manager_set_recovery_fallback_triggers(id, 0) < 0 &&
        driver_manager_set_recovery_fallback_triggers(
            id, DRIVER_RECOVERY_TRIGGER_ALL + 1) < 0 &&
        driver_manager_set_crash_circuit_policy(id, &invalid_policy) < 0;
    configured = !configured || !invalid_rejected ||
        driver_manager_set_recovery_fallback_triggers(
            id, DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT) ||
        driver_manager_set_crash_circuit_policy(id, &policy);
    int started = configured ? -1 : driver_manager_set_devices(devices, 1);
    struct driver_domain *domain = driver_manager_domain(device);
    int locked = driver_manager_set_recovery_fallback(id, &fallback) < 0 &&
        driver_manager_set_recovery_fallback_triggers(
            id, DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT) < 0 &&
        driver_manager_set_crash_circuit_policy(id, &policy) < 0;
    int active = id > 0 && invalid_rejected && !configured && started == 1 &&
        domain && domain->recovery_profile == DRIVER_RECOVERY_PRIMARY &&
        domain->fallback_enabled && !domain->fallback_used &&
        domain->fallback_triggers == DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT &&
        domain->fallback.image_id == fallback.image_id &&
        domain->fallback.capabilities == fallback.capabilities &&
        domain->fallback.argument == fallback.argument &&
        domain->crash_policy.repeat_limit == policy.repeat_limit &&
        domain->crash_policy.repeat_window_ticks == policy.repeat_window_ticks &&
        locked;
    int pid = domain ? domain->pid : 0;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400400, 0, 500);
    driver_supervisor_task_died(pid, 134, 500);
    driver_supervisor_tick(domain ? domain->restart_deadline : 0);
    int primary_restart = domain && domain->state == DRIVER_DOMAIN_RUNNING &&
        domain->generation == 2 && domain->restart_count == 1 &&
        domain->recovery_profile == DRIVER_RECOVERY_PRIMARY &&
        domain->last_decision == DRIVER_RECOVERY_DECISION_RESTART &&
        !domain->fallback_used;
    pid = domain ? domain->pid : 0;
    driver_supervisor_report_user_fault(pid, 6, 0, 0x400400, 0, 504);
    driver_supervisor_task_died(pid, 134, 504);
    int fallback_pending = domain && domain->state == DRIVER_DOMAIN_BACKOFF &&
        domain->generation == 2 && domain->image_id == fallback.image_id &&
        domain->recovery_profile == DRIVER_RECOVERY_FALLBACK &&
        domain->fallback_used &&
        domain->fallback_triggers == DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT &&
        domain->last_decision == DRIVER_RECOVERY_DECISION_FALLBACK &&
        domain->crash_policy.repeat_limit == policy.repeat_limit &&
        domain->crash_policy.repeat_window_ticks == policy.repeat_window_ticks;
    driver_supervisor_tick(domain ? domain->restart_deadline : 0);
    int fallback_started = domain && domain->state == DRIVER_DOMAIN_RUNNING &&
        domain->generation == 3 && domain->image_id == fallback.image_id &&
        domain->last_decision == DRIVER_RECOVERY_DECISION_FALLBACK &&
        domain->crash_policy.repeat_limit == policy.repeat_limit &&
        domain->crash_policy.repeat_window_ticks == policy.repeat_window_ticks;
    int removed = driver_manager_device_removed(device);
    int unregistered = driver_manager_unregister(id);
    int result = active && primary_restart && fallback_pending && fallback_started &&
        !removed && !unregistered && !driver_manager_binding_count() &&
        !driver_manager_manifest_count();
    driver_manager_init(0);
    return result ? 0 : -1;
}

static int graceful_stop64_self_test(struct kernel_object *dev) {
    struct driver_user_manifest m;
    u8 *p = (u8 *)&m;
    for (usize_t i = 0; i < sizeof(m); i++) p[i] = 0;
    m.abi_version = DRIVER_USER_ABI_VERSION;
    m.size = sizeof(m);
    const char name[] = "mich.graceful";
    for (u32 i = 0; name[i]; i++) m.name[i] = name[i];
    m.flags = DRIVER_MANIFEST_GRACEFUL_STOP;
    m.request_count = 2;
    m.requests[0].kind = DRIVER_RESOURCE_PCI;
    m.requests[0].rights = KRIGHT_READ | KRIGHT_CONTROL;
    m.requests[1].kind = DRIVER_RESOURCE_BRIDGE;
    m.requests[1].rights = KRIGHT_READ | KRIGHT_WAIT;
    struct driver_domain *d = driver_domain_create_user(&m, dev);
    if (!d || driver_domain_apply_manifest(d, &m, test_env->resource_provider) ||
        driver_domain_start(d)) {
        if (d) driver_domain_destroy(d);
        return -1;
    }
    driver_supervisor_tick(100);
    if (d->last_decision != DRIVER_RECOVERY_DECISION_START ||
        driver_domain_request_stop(d) ||
        d->state != DRIVER_DOMAIN_STOPPING ||
        d->last_decision != DRIVER_RECOVERY_DECISION_STOP_REQUEST ||
        d->bridge_index >= d->resource_count) {
        driver_domain_stop(d);
        driver_domain_destroy(d);
        return -1;
    }
    struct bridge_notification note;
    struct kernel_object *bridge = d->resources[d->bridge_index].object;
    int pid = d->pid;
    int ok = !bridge_endpoint_read(bridge, &note) &&
        note.source == DRIVER_CONTROL_STOP &&
        !driver_domain_stop_ack(pid);
    driver_supervisor_task_died(pid, 0, 101);
    ok = ok && d->state == DRIVER_DOMAIN_STOPPED &&
         d->last_decision == DRIVER_RECOVERY_DECISION_STOP_ACK;
    driver_domain_destroy(d);
    if (!ok) return -1;
    d = driver_domain_create_user(&m, dev);
    if (!d || driver_domain_apply_manifest(d, &m, test_env->resource_provider) ||
        driver_domain_start(d)) {
        if (d) driver_domain_destroy(d);
        return -1;
    }
    driver_supervisor_tick(200);
    ok = d->last_decision == DRIVER_RECOVERY_DECISION_START &&
         !driver_domain_request_stop(d) &&
         d->last_decision == DRIVER_RECOVERY_DECISION_STOP_REQUEST &&
         d->stop_deadline == 200 + DRIVER_STOP_GRACE_TICKS;
    driver_supervisor_tick(d->stop_deadline - 1);
    ok = ok && d->state == DRIVER_DOMAIN_STOPPING;
    driver_supervisor_tick(d->stop_deadline);
    ok = ok && d->state == DRIVER_DOMAIN_STOPPED &&
         d->last_decision == DRIVER_RECOVERY_DECISION_STOP_TIMEOUT;
    driver_domain_destroy(d);
    return ok ? 0 : -1;
}

// Keep the test-only supervisor matrix within the fixed boot blob.
// The share travels manifest -> domain -> spawn, and this covers the first
// two hops plus the validation guarding the boundary. The spawn hop is not
// reached here because the supervisor runs against a stub spawn backend
// inside this function; the real backend is only installed once it returns.
static int driver_weight_self_test(struct kernel_object *device,
                                   const struct driver_user_manifest *source) {
    struct driver_user_manifest manifest = *source;
    manifest.weight = TASK_WEIGHT_DEFAULT * 4u;
    struct driver_domain *domain =
        driver_passport_domain(device, &manifest, 0, 0, 0, 0, 8);
    if (!domain) return -1;
    int scaled = domain->weight == TASK_WEIGHT_DEFAULT * 4u;
    driver_domain_destroy(domain);
    if (!scaled) return -2;

    // Zero has to mean the default, because every manifest written before
    // the field existed zeroes that word.
    manifest.weight = 0;
    domain = driver_passport_domain(device, &manifest, 0, 0, 0, 0, 8);
    if (!domain) return -3;
    int defaulted = domain->weight == 0;
    driver_domain_destroy(domain);
    if (!defaulted) return -4;

    // The bound is what stops one manifest from taking the whole machine,
    // and the still-reserved word keeps the ABI honest for the next field.
    manifest.weight = TASK_WEIGHT_MAX + 1u;
    if (!driver_user_manifest_validate(&manifest)) return -5;
    manifest.weight = 0;
    manifest.reserved3 = 1u;
    if (!driver_user_manifest_validate(&manifest)) return -6;
    return 0;
}

static __attribute__((cold, noinline, optimize("Os"))) int driver_supervisor(
    const struct test64_env *env) {
    test_env = env;
    struct pci_resource description;
    description.segment = 0;
    description.bus = 0;
    description.device = 1;
    description.function = 0;
    description.vendor_id = 0xA200;
    description.device_id = 0xB200;
    description.class_code = 2;
    description.subclass = 0;
    description.programming_interface = 0;
    description.revision = 1;
    description.capability_flags = 0;
    description.msi_offset = 0;
    description.msix_offset = 0;
    description.pcie_offset = 0;
    description.active = 0;
    for (u32 index = 0; index < 6; index++) {
        description.bars[index].address = 0;
        description.bars[index].length = 0;
        description.bars[index].flags = 0;
    }
    description.bars[0].address = 0xF1000000ULL;
    description.bars[0].length = 4096;
    struct kernel_object *device = pci_resource_create(&description);
    struct pci_resource dependent_description = description;
    dependent_description.device = 2;
    dependent_description.vendor_id = 0xA201;
    dependent_description.device_id = 0xB201;
    dependent_description.bars[0].address = 0xF1100000ULL;
    struct kernel_object *dependent_device =
        pci_resource_create(&dependent_description);
    if (!device || !dependent_device) {
        if (device) object_release(device);
        if (dependent_device) object_release(dependent_device);
        return -1;
    }
    struct driver_user_manifest manifest;
    u8 *manifest_bytes = (u8 *)&manifest;
    for (usize_t index = 0; index < sizeof(manifest); index++)
        manifest_bytes[index] = 0;
    manifest.abi_version = DRIVER_USER_ABI_VERSION;
    manifest.size = sizeof(manifest);
    const char *name = "mich.test.domain";
    for (u32 index = 0; name[index]; index++) manifest.name[index] = name[index];
    manifest.flags = 0x21;
    manifest.capabilities = 0;
    manifest.firmware_count = 1;
    const char *firmware = "test-firmware";
    for (u32 index = 0; firmware[index]; index++)
        manifest.firmware[0][index] = firmware[index];
    manifest.restart_policy = DRIVER_RESTART_ON_FAILURE;
    manifest.max_restarts = 2;
    manifest.backoff_ticks = 2;
    manifest.argument = 19;
    manifest.reset_policy = DRIVER_RESET_IF_SUPPORTED;
    manifest.match_count = 1;
    manifest.matches[0].vendor_id = 0xA200;
    manifest.matches[0].device_id = 0xB200;
    manifest.matches[0].class_code = 2;
    manifest.matches[0].subclass = 0;
    manifest.matches[0].programming_interface = 0;
    manifest.request_count = 3;
    manifest.requests[0].kind = DRIVER_RESOURCE_PCI;
    manifest.requests[0].rights = KRIGHT_READ | KRIGHT_CONTROL;
    manifest.requests[1].kind = DRIVER_RESOURCE_BAR;
    manifest.requests[1].index = 0;
    manifest.requests[1].rights = KRIGHT_READ | KRIGHT_WRITE | KRIGHT_MAP;
    manifest.requests[2].kind = DRIVER_RESOURCE_BRIDGE;
    manifest.requests[2].rights = KRIGHT_READ | KRIGHT_WAIT | KRIGHT_TRANSFER;
    struct driver_user_manifest invalid_manifest = manifest;
    invalid_manifest.size--;
    struct driver_user_manifest invalid_firmware = manifest;
    invalid_firmware.firmware[0][4] = '/';
    int manifest_valid = !driver_user_manifest_validate(&manifest) &&
                         driver_user_manifest_validate(&invalid_manifest) < 0 &&
                         driver_user_manifest_validate(&invalid_firmware) < 0 &&
                         driver_user_manifest_matches(&manifest, device);
    supervisor_test_quiesces = 0;
    supervisor_test_resets = 0;
    supervisor_test_revokes = 0;
    supervisor_test_quiesce_fail = 0;
    driver_supervisor_init(supervisor_test_spawn, supervisor_test_quiesce,
                           supervisor_test_reset, supervisor_test_revoke,
                           supervisor_test_terminate);
    driver_manager_init(test_env->resource_provider);
    struct driver_domain *rollback_domain =
        driver_domain_create_user(&manifest, device);
    struct driver_user_manifest rollback_manifest = manifest;
    rollback_manifest.request_count = 2;
    rollback_manifest.requests[1].kind = DRIVER_RESOURCE_DMA;
    rollback_manifest.requests[1].index = 0;
    rollback_manifest.requests[1].rights = KRIGHT_READ | KRIGHT_MAP;
    rollback_manifest.requests[1].amount = 1;
    rollback_manifest.requests[1].limit = 0xFFFFFFFFULL;
    int valid = manifest_valid && rollback_domain &&
        driver_domain_firmware_allowed(rollback_domain, "test-firmware") &&
        !driver_domain_firmware_allowed(rollback_domain, "other-firmware") &&
        driver_domain_apply_manifest(rollback_domain, &rollback_manifest, 0) < 0 &&
        rollback_domain->resource_count == 0;
    if (rollback_domain) driver_domain_destroy(rollback_domain);
    manifest.priority = 10;
    struct driver_user_manifest cycle_a = manifest;
    struct driver_user_manifest cycle_b = manifest;
    for (u32 index = 0; index < DRIVER_USER_NAME_MAX; index++) {
        cycle_a.name[index] = 0;
        cycle_b.name[index] = 0;
        cycle_a.dependencies[0][index] = 0;
        cycle_b.dependencies[0][index] = 0;
    }
    const char *cycle_a_name = "mich.cycle.a";
    const char *cycle_b_name = "mich.cycle.b";
    for (u32 index = 0; cycle_a_name[index]; index++) {
        cycle_a.name[index] = cycle_a_name[index];
        cycle_b.dependencies[0][index] = cycle_a_name[index];
    }
    for (u32 index = 0; cycle_b_name[index]; index++) {
        cycle_b.name[index] = cycle_b_name[index];
        cycle_a.dependencies[0][index] = cycle_b_name[index];
    }
    cycle_a.dependency_count = 1;
    cycle_b.dependency_count = 1;
    int cycle_a_id = driver_manager_register(&cycle_a);
    int cycle_rejected = driver_manager_register(&cycle_b);
    valid = valid && cycle_a_id > 0 && cycle_rejected < 0 &&
            !driver_manager_unregister(cycle_a_id);
    struct driver_user_manifest broken_manifest = manifest;
    struct driver_user_manifest dependent_manifest = manifest;
    for (u32 index = 0; index < DRIVER_USER_NAME_MAX; index++) {
        broken_manifest.name[index] = 0;
        dependent_manifest.name[index] = 0;
        dependent_manifest.dependencies[0][index] = manifest.name[index];
    }
    const char *broken_name = "mich.test.broken";
    const char *dependent_name = "mich.test.dependent";
    for (u32 index = 0; broken_name[index]; index++)
        broken_manifest.name[index] = broken_name[index];
    for (u32 index = 0; dependent_name[index]; index++)
        dependent_manifest.name[index] = dependent_name[index];
    broken_manifest.priority = 5;
    broken_manifest.image_id = 15;
    dependent_manifest.argument = 20;
    dependent_manifest.matches[0].vendor_id = 0xA201;
    dependent_manifest.matches[0].device_id = 0xB201;
    dependent_manifest.dependency_count = 1;
    struct kernel_object *manager_devices[2];
    manager_devices[0] = dependent_device;
    manager_devices[1] = device;
    valid = valid && driver_manager_set_devices(manager_devices, 2) == 0;
    int dependent_id = driver_manager_register(&dependent_manifest);
    int broken_id = driver_manager_register(&broken_manifest);
    int manifest_id = driver_manager_register(&manifest);
    struct driver_domain *domain = driver_manager_domain(device);
    struct driver_domain *dependent_domain =
        driver_manager_domain(dependent_device);
    valid = valid && dependent_id > 0 && broken_id > 0 && manifest_id > 0 &&
        driver_manager_binding_count() == 2 &&
        driver_manager_manifest_count() == 3 &&
        driver_manager_manifest(manifest_id) &&
        driver_manager_manifest(manifest_id)->priority == 10 && domain &&
        dependent_domain && dependent_domain->state == DRIVER_DOMAIN_RUNNING &&
        driver_manager_domain(device) == domain &&
        driver_manager_unregister(manifest_id) < 0 &&
        !driver_manager_start_device(device) &&
        domain->state == DRIVER_DOMAIN_RUNNING && domain->generation == 1;
    if (valid) {
        driver_manager_task_exiting(dependent_domain->pid, 0);
        driver_supervisor_task_died(dependent_domain->pid, 0, 1);
        driver_manager_tick();
        valid = dependent_domain->state == DRIVER_DOMAIN_STOPPED &&
                dependent_domain->last_decision == DRIVER_RECOVERY_DECISION_STOP &&
                dependent_domain->generation == 1 &&
                !driver_manager_restart_device(dependent_device) &&
                dependent_domain->state == DRIVER_DOMAIN_RUNNING &&
                dependent_domain->generation == 2;
    }
    if (valid) {
        valid = !driver_manager_stop_device(device);
        driver_manager_tick();
        valid = valid && domain->state == DRIVER_DOMAIN_STOPPED &&
                domain->last_decision == DRIVER_RECOVERY_DECISION_STOP &&
                dependent_domain->state == DRIVER_DOMAIN_STOPPED &&
                !driver_manager_restart_device(device);
        driver_manager_tick();
        valid = valid && domain->state == DRIVER_DOMAIN_RUNNING &&
                dependent_domain->state == DRIVER_DOMAIN_RUNNING &&
                domain->generation == 2 && dependent_domain->generation == 3;
    }
    if (dependent_domain) {
        struct kernel_object *reduced_inventory[1];
        reduced_inventory[0] = device;
        valid = valid && driver_manager_set_devices(reduced_inventory, 1) == 0 &&
                !driver_manager_domain(dependent_device) &&
                driver_manager_binding_count() == 1 &&
                !driver_manager_unregister(dependent_id);
        struct driver_user_manifest required_manifest = dependent_manifest;
        required_manifest.reset_policy = DRIVER_RESET_REQUIRED;
        struct driver_domain *required_domain =
            driver_domain_create_user(&required_manifest, dependent_device);
        valid = valid && required_domain &&
                !driver_domain_apply_manifest(required_domain,
                                              &required_manifest,
                                              test_env->resource_provider) &&
                !driver_domain_start(required_domain) &&
                driver_domain_stop(required_domain) < 0 &&
                required_domain->state == DRIVER_DOMAIN_QUARANTINED &&
                required_domain->last_decision ==
                    DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE &&
                driver_domain_for_device(dependent_device) == required_domain &&
                !driver_domain_admin_release(required_domain);
        if (required_domain && required_domain->active)
            driver_domain_admin_release(required_domain);
        supervisor_test_quiesces = 0;
        supervisor_test_resets = 0;
        supervisor_test_revokes = 0;
    }
    u32 bundle[DRIVER_DOMAIN_RESOURCE_MAX];
    u32 stale_bridge_handle = 0;
    struct kernel_object *stale_bridge = 0;
    struct driver_bootstrap_info bootstrap;
    valid = valid && driver_domain_bundle(
        domain, bundle, DRIVER_DOMAIN_RESOURCE_MAX) == 3 &&
        bundle[0] && bundle[1] && bundle[2] &&
        !driver_domain_bootstrap(domain->pid, &bootstrap) &&
        bootstrap.abi_version == DRIVER_USER_ABI_VERSION &&
        bootstrap.size == sizeof(bootstrap) &&
        bootstrap.domain_id == domain->id && bootstrap.generation == 2 &&
        bootstrap.manifest_flags == 0x21 && bootstrap.image_id == 0 &&
        bootstrap.reset_policy == DRIVER_RESET_IF_SUPPORTED &&
        bootstrap.name[10] == 'd' &&
        bootstrap.name[11] == 'o' &&
        bootstrap.name[12] == 'm' &&
        bootstrap.name[13] == 'a' &&
        bootstrap.name[14] == 'i' &&
        bootstrap.name[15] == 'n' &&
        bootstrap.vendor_id == 0xA200 && bootstrap.device_id == 0xB200 &&
        bootstrap.resource_count == 3 &&
        bootstrap.resources[0].kind == DRIVER_RESOURCE_PCI &&
        bootstrap.resources[0].handle == bundle[0] &&
        bootstrap.resources[1].kind == DRIVER_RESOURCE_BAR &&
        bootstrap.resources[1].handle == bundle[1] &&
        bootstrap.resources[1].length == 4096 &&
        bootstrap.resources[2].kind == DRIVER_RESOURCE_BRIDGE &&
        bootstrap.resources[2].handle == bundle[2];
    if (valid) {
        stale_bridge = handle_get(test_env->target, bundle[2],
                                  KRIGHT_READ | KRIGHT_WAIT, KOBJECT_ENDPOINT);
        stale_bridge_handle = stale_bridge ?
            handle_duplicate(test_env->target, test_env->owner, bundle[2],
                             KRIGHT_READ | KRIGHT_WAIT) : 0;
        valid = stale_bridge && stale_bridge_handle &&
                bridge_endpoint_wait(stale_bridge, test_env->owner_slot) == 1 &&
                test_env->owner->state == TASK_BLOCKED_EVENT;
    }
    if (valid) {
        struct bridge_notification notification;
        driver_supervisor_task_died(domain->pid, 1, 10);
        valid = domain->state == DRIVER_DOMAIN_BACKOFF &&
                domain->restart_deadline == 12 &&
                driver_domain_bundle(domain, bundle,
                                     DRIVER_DOMAIN_RESOURCE_MAX) < 0 &&
                !handle_get(test_env->owner, stale_bridge_handle,
                            KRIGHT_READ, KOBJECT_ENDPOINT) &&
                test_env->owner->state == TASK_RUNNING &&
                bridge_endpoint_read(stale_bridge, &notification) < 0;
    }
    if (valid) {
        driver_supervisor_tick(11);
        valid = domain->state == DRIVER_DOMAIN_BACKOFF;
        driver_supervisor_tick(12);
        struct driver_bootstrap_info restarted_bootstrap;
        valid = valid && domain->state == DRIVER_DOMAIN_RUNNING &&
                domain->generation == 3 &&
                !driver_domain_bootstrap(domain->pid, &restarted_bootstrap) &&
                restarted_bootstrap.generation == 3 &&
                restarted_bootstrap.resources[0].handle != bundle[0] &&
                restarted_bootstrap.resources[1].handle != bundle[1] &&
                restarted_bootstrap.resources[2].handle != bundle[2];
    }
    if (valid) {
        driver_supervisor_task_died(domain->pid, 1, 20);
        driver_supervisor_tick(24);
        valid = domain->state == DRIVER_DOMAIN_RUNNING &&
                domain->generation == 4 && domain->restart_count == 2;
    }
    if (valid) {
        driver_supervisor_task_died(domain->pid, 1, 30);
        valid = domain->state == DRIVER_DOMAIN_FAILED &&
                supervisor_test_quiesces == 3 &&
                supervisor_test_resets == 3 &&
                supervisor_test_revokes == 3;
    }
    if (domain)
        valid = valid && !driver_manager_device_removed(device) &&
                driver_manager_binding_count() == 0 &&
                supervisor_test_quiesces == 4 &&
                supervisor_test_resets == 3;
    valid = valid && !driver_manager_unregister(broken_id) &&
            !driver_manager_unregister(manifest_id) &&
            driver_manager_manifest_count() == 0;
    driver_manager_init(0);
    int manager_register_test =
        driver_manager_recovery_register_self_test(device, &manifest);
    int manager_fallback_test = driver_manager_fallback_self_test(device, &manifest);
    int passport_test = driver_crash_passport_self_test(device, &manifest);
    int policy_test = driver_crash_policy_self_test(device, &manifest);
    int launch_test = driver_recovery_launch_decision_self_test(device, &manifest);
    int teardown_audit_test =
        driver_recovery_teardown_audit_self_test(device, &manifest);
    int fallback_test = driver_recovery_fallback_self_test(device, &manifest);
    int selector_test = driver_recovery_selector_self_test(device, &manifest);
    int stress_test = driver_crash_stress_self_test(device);
    int graceful_test = graceful_stop64_self_test(device);
    int weight_test = driver_weight_self_test(device, &manifest);
    valid = valid && !manager_register_test && !manager_fallback_test &&
        !passport_test && !policy_test && !launch_test &&
        !teardown_audit_test && !fallback_test && !selector_test &&
        !stress_test && !graceful_test && !weight_test;
    object_release(dependent_device);
    object_release(device);
    driver_supervisor_init(test_env->spawn, test_env->quiesce,
                           test_env->reset, test_env->revoke,
                           test_env->terminate);
    driver_manager_init(test_env->resource_provider);
    return valid ? 0 : -1;
}
int tests64_run_driver(const struct test64_env *env) {
    if (!env || !env->platform_mmio || !env->resource_provider ||
        !env->spawn || !env->quiesce || !env->reset || !env->revoke ||
        !env->terminate)
        return -1;
    if (test_report_record(TEST_ID_DRIVER, driver_core(env))) return -1;
    serial64_write("Mich test64: driver module core pass\n");
    serial64_write("Mich test64: driver manifest pass\n");
    serial64_write("Mich test64: driver dependency order pass\n");
    serial64_write("Mich test64: driver restart policy pass\n");
    serial64_write("Mich test64: device removal pass\n");
    if (test_report_record(TEST_ID_SUPERVISOR, driver_supervisor(env)))
        return -1;
    serial64_write("Mich test64: driver supervisor pass\n");
    serial64_write("Mich test64: driver crash teardown pass\n");
    serial64_write("Mich test64: driver crash passport pass\n");
    serial64_write("Mich test64: driver crash circuit breaker pass\n");
    serial64_write("Mich test64: driver crash policy pass\n");
    serial64_write("Mich test64: driver recovery decision matrix pass\n");
    serial64_write("Mich test64: trigger policy pass\n");
    serial64_write("Mich test64: driver recovery fallback pass\n");
    serial64_write("Mich test64: driver recovery selector pass\n");
    serial64_write("Mich test64: driver recovery audit pass\n");
    serial64_write("Mich test64: driver IOMMU crash quarantine pass\n");
    serial64_write("Mich test64: atomic driver bundle pass\n");
    serial64_write("Mich test64: userspace driver manifest pass\n");
    serial64_write("Mich test64: firmware manifest allowlist pass\n");
    serial64_write("Mich test64: driver bootstrap ABI pass\n");
    serial64_write("Mich test64: IRQ bootstrap source pass\n");
    serial64_write("Mich test64: userspace driver manager pass\n");
    serial64_write("Mich test64: driver scheduler weight pass\n");
    serial64_write("Mich test64: driver manifest priority pass\n");
    serial64_write("Mich test64: driver manifest fallback pass\n");
    serial64_write("Mich test64: driver dependency graph pass\n");
    serial64_write("Mich test64: automatic PCI driver binding pass\n");
    serial64_write("Mich test64: PCI FLR abstraction pass\n");
    serial64_write("Mich test64: driver reset policy pass\n");
    serial64_write("Mich test64: driver crash stress pass\n");
    serial64_write("Mich test64: graceful driver stop pass\n");
    serial64_write("Mich test64: driver stop timeout fallback pass\n");
    serial64_write("Mich test64: firmware crash handle revoke pass\n");
    serial64_write("Mich test64: IRQ teardown race pass\n");
    serial64_write("Mich test64: driver resource accounting pass\n");
    return 0;
}
