#include "driver_supervisor.h"
#include "driver.h"
#include "klock.h"
#include "resource.h"
#include "bridge.h"
#include "endpoint.h"
#include "task.h"
#include "capability.h"

static struct driver_domain domains[DRIVER_DOMAIN_MAX];
static driver_domain_spawn_fn spawn_backend;
static driver_domain_quiesce_fn quiesce_backend;
static driver_domain_reset_fn reset_backend;
static driver_domain_revoke_fn revoke_backend;
static driver_domain_terminate_fn terminate_backend;
static driver_domain_release_fn release_backend;
static u32 next_domain_id;
static u32 now_ticks;

// Set while this layer is the one asking for a task to go. terminate64 calls
// back into the supervisor and the manager, and both would take a lock the
// caller already holds.
static u32 supervisor_terminating;

static struct klock driver_supervisor_klock =
    KLOCK_INIT(KLOCK_LEVEL_SUPERVISOR);

static int driver_domain_add_bridge_locked(struct driver_domain *domain,
                                           u32 rights);
static int driver_domain_add_resource_kind_locked(struct driver_domain *domain,
                                                  struct kernel_object *object,
                                                  u32 rights, u32 kind,
                                                  u32 index, u64 flags);
static struct driver_domain *driver_domain_for_device_locked(
    struct kernel_object *device);
static struct driver_domain *driver_domain_for_id_locked(u32 id);
static struct driver_domain *driver_domain_for_pid_locked(int pid);

static void passport_clear(struct driver_crash_passport *passport) {
    u8 *bytes = (u8 *)passport;
    for (usize_t byte = 0; byte < sizeof(*passport); byte++) bytes[byte] = 0;
}

static void crash_policy_default(struct driver_domain *domain) {
    domain->crash_policy.repeat_limit = DRIVER_CRASH_REPEAT_LIMIT;
    domain->crash_policy.repeat_window_ticks = DRIVER_CRASH_REPEAT_WINDOW_TICKS;
}

static void crash_state_clear(struct driver_domain *domain) {
    passport_clear(&domain->last_crash);
    passport_clear(&domain->pending_crash);
    domain->crash_repeat_count = 0;
    domain->crash_repeat_deadline = 0;
    domain->terminal_reason = DRIVER_TERMINAL_NONE;
    domain->last_decision = DRIVER_RECOVERY_DECISION_NONE;
}

static void recovery_selector_clear(struct driver_domain *domain) {
    u8 *bytes = (u8 *)&domain->fallback_selector;
    for (usize_t index = 0; index < sizeof(domain->fallback_selector); index++)
        bytes[index] = 0;
    domain->fallback_selector_enabled = 0;
}

static void recovery_audit_clear(struct driver_domain *domain) {
    u8 *bytes = (u8 *)&domain->recovery_audit;
    for (usize_t index = 0; index < sizeof(domain->recovery_audit); index++)
        bytes[index] = 0;
}

static void recovery_audit_record(
    struct driver_domain *domain, u32 trigger, u32 outcome,
    const struct driver_crash_passport *passport) {
    recovery_audit_clear(domain);
    domain->recovery_audit.trigger = trigger;
    domain->recovery_audit.outcome = outcome;
    if (domain->fallback_enabled)
        domain->recovery_audit.profile = domain->fallback;
    if (passport) domain->recovery_audit.passport = *passport;
}

static void recovery_fallback_clear(struct driver_domain *domain) {
    domain->fallback.image_id = 0;
    domain->fallback.capabilities = 0;
    domain->fallback.argument = 0;
    recovery_selector_clear(domain);
    recovery_audit_clear(domain);
    domain->recovery_profile = DRIVER_RECOVERY_PRIMARY;
    domain->fallback_enabled = 0;
    domain->fallback_used = 0;
    domain->fallback_triggers = DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT;
}

static int recovery_profile_valid(const struct driver_domain *domain,
                                  const struct driver_recovery_profile *profile) {
    return profile && profile->image_id < DRIVER_USER_IMAGE_MAX &&
           !(profile->capabilities & ~domain->capabilities) &&
           (profile->image_id != domain->image_id ||
            profile->capabilities != domain->capabilities ||
            profile->argument != domain->argument);
}

static int recovery_selector_matches(
    const struct driver_domain *domain,
    const struct driver_crash_passport *passport) {
    const struct pci_resource *pci = pci_resource_get(domain->device);
    const struct driver_recovery_fingerprint *fingerprint =
        &domain->fallback_selector.fingerprint;
    return pci && passport &&
        pci->vendor_id == domain->fallback_selector.vendor_id &&
        pci->device_id == domain->fallback_selector.device_id &&
        passport->kind == fingerprint->kind &&
        passport->code == fingerprint->code &&
        passport->vector == fingerprint->vector &&
        passport->error == fingerprint->error &&
        passport->rip == fingerprint->rip &&
        passport->address == fingerprint->address;
}

static int recovery_fallback_activate(struct driver_domain *domain, u32 ticks,
                                      u32 trigger,
                                      const struct driver_crash_passport *passport) {
    if (!domain->fallback_enabled || domain->fallback_used ||
        !(domain->fallback_triggers & trigger)) {
        recovery_audit_record(domain, trigger, DRIVER_RECOVERY_AUDIT_UNAVAILABLE,
                              passport);
        return 0;
    }
    if (domain->fallback_selector_enabled &&
        (trigger != DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT ||
         !recovery_selector_matches(domain, passport))) {
        recovery_audit_record(domain, trigger,
                              DRIVER_RECOVERY_AUDIT_SELECTOR_MISMATCH, passport);
        return 0;
    }
    recovery_audit_record(domain, trigger, DRIVER_RECOVERY_AUDIT_SELECTED,
                          passport);
    domain->image_id = domain->fallback.image_id;
    domain->capabilities = domain->fallback.capabilities;
    domain->argument = domain->fallback.argument;
    domain->recovery_profile = DRIVER_RECOVERY_FALLBACK;
    domain->fallback_used = 1;
    domain->terminal_reason = DRIVER_TERMINAL_NONE;
    domain->last_decision = DRIVER_RECOVERY_DECISION_FALLBACK;
    domain->crash_repeat_count = 0;
    domain->crash_repeat_deadline = 0;
    domain->restart_deadline = ticks + domain->backoff_ticks;
    domain->state = DRIVER_DOMAIN_BACKOFF;
    return 1;
}

static int passports_match(const struct driver_crash_passport *left,
                           const struct driver_crash_passport *right) {
    return left->kind == DRIVER_CRASH_USER_EXCEPTION &&
           right->kind == DRIVER_CRASH_USER_EXCEPTION && left->code == right->code &&
           left->vector == right->vector && left->error == right->error &&
           left->rip == right->rip && left->address == right->address;
}

static int crash_circuit_open(struct driver_domain *domain,
                              const struct driver_crash_passport *passport,
                              u32 ticks) {
    if (passport->kind != DRIVER_CRASH_USER_EXCEPTION) {
        domain->crash_repeat_count = 0;
        domain->crash_repeat_deadline = 0;
        return 0;
    }
    if (domain->crash_repeat_count &&
        (i32)(ticks - domain->crash_repeat_deadline) < 0 &&
        passports_match(&domain->last_crash, passport)) {
        domain->crash_repeat_count++;
    } else {
        domain->crash_repeat_count = 1;
        domain->crash_repeat_deadline =
            ticks + domain->crash_policy.repeat_window_ticks;
    }
    return domain->crash_repeat_count >= domain->crash_policy.repeat_limit;
}

static void crash_passport_for_death(struct driver_domain *domain, int code,
                                     u32 ticks,
                                     struct driver_crash_passport *passport) {
    passport_clear(passport);
    if (code && domain->pending_crash.kind &&
        domain->pending_crash.generation == domain->generation)
        *passport = domain->pending_crash;
    else if (code)
        passport->kind = DRIVER_CRASH_EXIT;
    passport->code = (u32)code;
    passport->generation = domain->generation;
    passport->ticks = ticks;
    passport_clear(&domain->pending_crash);
}

static u32 resource_kind(const struct kernel_object *object) {
    if (!object) return 0;
    if (object->type == KOBJECT_PCI) return DRIVER_RESOURCE_PCI;
    if (object->type == KOBJECT_MMIO) return DRIVER_RESOURCE_BAR;
    if (object->type == KOBJECT_DMA) return DRIVER_RESOURCE_DMA;
    if (object->type == KOBJECT_IRQ) return DRIVER_RESOURCE_IRQ;
    if (object->type == KOBJECT_MSIX_TABLE) return DRIVER_RESOURCE_MSIX_TABLE;
    if (object->type == KOBJECT_ENDPOINT) return DRIVER_RESOURCE_BRIDGE;
    return 0;
}

static int valid_name(const char *name) {
    if (!name || !name[0]) return 0;
    for (u32 index = 0; index < 32; index++)
        if (!name[index]) return 1;
    return 0;
}

static int abi_names_equal(const char *left, const char *right) {
    if (!left || !right) return 0;
    for (u32 index = 0; index < DRIVER_USER_NAME_MAX; index++) {
        if (left[index] != right[index]) return 0;
        if (!left[index]) return 1;
    }
    return 1;
}

static struct task *task_for_pid(int pid) {
    u32 slot = PID_SLOT((u32)pid);
    if (!pid || slot >= (u32)task_pool_count) return 0;
    struct task *task = &task_pool[slot];
    if (task->state == TASK_FREE || task->state == TASK_ZOMBIE ||
        task->id != pid)
        return 0;
    return task;
}

static int issue_bundle(struct driver_domain *domain) {
    struct task *task = task_for_pid(domain->pid);
    if (!task) return -1;
    u32 handles[DRIVER_DOMAIN_RESOURCE_MAX];
    u32 completed = 0;
    while (completed < domain->resource_count) {
        struct driver_domain_resource *resource = &domain->resources[completed];
        handles[completed] = handle_open(task, resource->object,
                                         resource->rights);
        if (!handles[completed]) break;
        completed++;
    }
    if (completed == domain->resource_count) {
        for (u32 index = 0; index < completed; index++)
            domain->issued_handles[index] = handles[index];
        return 0;
    }
    while (completed) handle_close(task, handles[--completed]);
    for (u32 index = 0; index < DRIVER_DOMAIN_RESOURCE_MAX; index++)
        domain->issued_handles[index] = 0;
    return -1;
}

static int mask_irqs(struct driver_domain *domain) {
    int result = 0;
    for (u32 index = 0; index < domain->resource_count; index++) {
        struct kernel_object *object = domain->resources[index].object;
        if (!object || object->type != KOBJECT_IRQ) continue;
        struct irq_resource *irq = irq_resource_get(object);
        if (!irq) {
            result = -1;
            continue;
        }
        if (!irq->masked && irq_resource_set_mask(object, 1)) result = -1;
        if (irq->binding && irq_resource_unbind(object)) result = -1;
    }
    return result;
}

static void revoke_handles(struct driver_domain *domain) {
    for (u32 index = 0; index < domain->resource_count; index++)
        handle_revoke_object(domain->resources[index].object);
}

static int recreate_bridge(struct driver_domain *domain) {
    if (domain->bridge_index >= domain->resource_count) return 0;
    struct driver_domain_resource *resource =
        &domain->resources[domain->bridge_index];
    struct kernel_object *replacement = bridge_endpoint_create();
    if (!replacement) return -1;
    object_release(resource->object);
    resource->object = replacement;
    return 0;
}

static int teardown(struct driver_domain *domain) {
    int result = mask_irqs(domain);
    if (quiesce_backend && quiesce_backend(domain->device)) result = -1;
    // The backend takes the domain id instead of looking the domain up by
    // pid: it runs inside teardown and must not walk the table again.
    if (revoke_backend && domain->pid > 0 &&
        revoke_backend(domain->pid, domain->id, domain->resources,
                       domain->resource_count))
        result = -1;
    struct task *task = task_for_pid(domain->pid);
    if (task) handle_close_all(task);
    revoke_handles(domain);
    for (u32 index = 0; index < DRIVER_DOMAIN_RESOURCE_MAX; index++)
        domain->issued_handles[index] = 0;
    if (domain->reset_policy != DRIVER_RESET_NONE) {
        int reset = reset_backend ? reset_backend(domain->device) : 1;
        if (reset < 0 ||
            (reset > 0 && domain->reset_policy == DRIVER_RESET_REQUIRED))
            result = -1;
    }
    if (recreate_bridge(domain)) result = -1;
    domain->pid = -1;
    return result;
}

static int terminate_task(int pid) {
    if (!terminate_backend || pid <= 0) return 0;
    supervisor_terminating = 1;
    int result = terminate_backend(pid);
    supervisor_terminating = 0;
    return result;
}

int driver_supervisor_terminating(void) {
    return supervisor_terminating != 0;
}

static int launch(struct driver_domain *domain) {
    if (!spawn_backend) return -1;
    int pid = spawn_backend(domain);
    if (pid <= 0) return -1;
    domain->pid = pid;
    passport_clear(&domain->pending_crash);
    domain->stop_deadline = 0;
    domain->stop_ack = 0;
    domain->generation++;
    if (!domain->generation) domain->generation = 1;
    if (issue_bundle(domain)) {
        revoke_handles(domain);
        terminate_task(pid);
        domain->pid = -1;
        return -1;
    }
    domain->state = DRIVER_DOMAIN_RUNNING;
    return 0;
}

void driver_supervisor_init(driver_domain_spawn_fn spawn,
                            driver_domain_quiesce_fn quiesce,
                            driver_domain_reset_fn reset,
                            driver_domain_revoke_fn revoke,
                            driver_domain_terminate_fn terminate) {
    spawn_backend = spawn;
    quiesce_backend = quiesce;
    reset_backend = reset;
    revoke_backend = revoke;
    terminate_backend = terminate;
    next_domain_id = 1;
    now_ticks = 0;
    for (u32 index = 0; index < DRIVER_DOMAIN_MAX; index++) {
        domains[index].id = 0;
        domains[index].state = DRIVER_DOMAIN_STOPPED;
        domains[index].pid = -1;
        domains[index].device = 0;
        for (u32 resource = 0; resource < DRIVER_DOMAIN_RESOURCE_MAX;
             resource++)
            domains[index].issued_handles[resource] = 0;
        domains[index].resource_count = 0;
        domains[index].bridge_index = DRIVER_DOMAIN_RESOURCE_MAX;
        domains[index].restart_count = 0;
        domains[index].restart_deadline = 0;
        crash_state_clear(&domains[index]);
        crash_policy_default(&domains[index]);
        recovery_fallback_clear(&domains[index]);
        domains[index].stop_deadline = 0;
        domains[index].stop_ack = 0;
        domains[index].generation = 0;
        for (u32 byte = 0; byte < sizeof(domains[index].name); byte++)
            domains[index].name[byte] = 0;
        domains[index].manifest_flags = 0;
        domains[index].firmware_count = 0;
        for (u32 firmware = 0; firmware < DRIVER_USER_FIRMWARE_MAX; firmware++)
            for (u32 byte = 0; byte < DRIVER_USER_NAME_MAX; byte++)
                domains[index].firmware[firmware][byte] = 0;
        domains[index].active = 0;
    }
}

int driver_supervisor_set_release_backend(driver_domain_release_fn release) {
    if (!release || release_backend) return -1;
    release_backend = release;
    return 0;
}

static struct driver_domain *driver_domain_create_locked(
    const struct driver_domain_manifest *manifest,
    struct kernel_object *device) {
    if (!manifest || !valid_name(manifest->name) || !device ||
        !device->active || device->type != KOBJECT_PCI ||
        manifest->restart_policy > DRIVER_RESTART_ON_FAILURE ||
        driver_domain_for_device_locked(device))
        return 0;
    for (u32 index = 0; index < DRIVER_DOMAIN_MAX; index++) {
        struct driver_domain *domain = &domains[index];
        if (domain->active) continue;
        if (object_retain(device)) return 0;
        domain->id = next_domain_id++;
        if (!next_domain_id) next_domain_id = 1;
        domain->state = DRIVER_DOMAIN_STOPPED;
        domain->pid = -1;
        domain->device = device;
        for (u32 resource = 0; resource < DRIVER_DOMAIN_RESOURCE_MAX;
             resource++)
            domain->issued_handles[resource] = 0;
        domain->resource_count = 0;
        domain->bridge_index = DRIVER_DOMAIN_RESOURCE_MAX;
        domain->restart_count = 0;
        domain->restart_deadline = 0;
        crash_state_clear(domain);
        crash_policy_default(domain);
        recovery_fallback_clear(domain);
        domain->stop_deadline = 0;
        domain->stop_ack = 0;
        domain->generation = 0;
        for (u32 byte = 0; byte < sizeof(domain->name); byte++)
            domain->name[byte] = 0;
        u32 length = 0;
        while (manifest->name[length]) {
            domain->name[length] = manifest->name[length];
            length++;
        }
        domain->name[length] = 0;
        domain->manifest_flags = 0;
        domain->capabilities = manifest->capabilities;
        domain->restart_policy = manifest->restart_policy;
        domain->max_restarts = manifest->max_restarts;
        domain->backoff_ticks = manifest->backoff_ticks;
        domain->image_id = manifest->image_id;
        domain->reset_policy = manifest->reset_policy;
        domain->weight = manifest->weight;
        domain->argument = manifest->argument;
        domain->firmware_count = 0;
        for (u32 firmware = 0; firmware < DRIVER_USER_FIRMWARE_MAX; firmware++)
            for (u32 byte = 0; byte < DRIVER_USER_NAME_MAX; byte++)
                domain->firmware[firmware][byte] = 0;
        domain->active = 1;
        return domain;
    }
    return 0;
}

struct driver_domain *driver_domain_create(
    const struct driver_domain_manifest *manifest,
    struct kernel_object *device) {
    klock_acquire(&driver_supervisor_klock);
    struct driver_domain *result = driver_domain_create_locked(manifest,
                                                               device);
    klock_release(&driver_supervisor_klock);
    return result;
}

int driver_user_manifest_validate(const struct driver_user_manifest *manifest) {
    if (!manifest || manifest->abi_version != DRIVER_USER_ABI_VERSION ||
        manifest->size != sizeof(*manifest) || !valid_name(manifest->name) ||
        manifest->restart_policy > DRIVER_RESTART_ON_FAILURE ||
        manifest->reset_policy > DRIVER_RESET_REQUIRED ||
        manifest->max_restarts > 1024 ||
        (manifest->max_restarts && manifest->backoff_ticks >
         0x7FFFFFFFu / manifest->max_restarts) ||
        (manifest->capabilities & ~CAP_BOOT_ALLOWED) ||
        manifest->match_count > DRIVER_USER_MATCH_MAX ||
        manifest->request_count > DRIVER_USER_REQUEST_MAX ||
        manifest->dependency_count > DRIVER_USER_DEPENDENCY_MAX ||
        manifest->firmware_count > DRIVER_USER_FIRMWARE_MAX ||
        manifest->image_id >= DRIVER_USER_IMAGE_MAX ||
        manifest->weight > TASK_WEIGHT_MAX || manifest->reserved3)
        return -1;
    for (u32 index = 0; index < manifest->dependency_count; index++) {
        const char *dependency = manifest->dependencies[index];
        if (!valid_name(dependency) ||
            abi_names_equal(dependency, manifest->name))
            return -1;
        for (u32 prior = 0; prior < index; prior++)
            if (abi_names_equal(dependency, manifest->dependencies[prior]))
                return -1;
    }
    for (u32 index = 0; index < manifest->firmware_count; index++) {
        const char *firmware = manifest->firmware[index];
        if (!valid_name(firmware)) return -1;
        for (u32 byte = 0; byte < DRIVER_USER_NAME_MAX && firmware[byte]; byte++)
            if (firmware[byte] == '/') return -1;
        for (u32 prior = 0; prior < index; prior++)
            if (abi_names_equal(firmware, manifest->firmware[prior]))
                return -1;
    }
    for (u32 index = 0; index < manifest->match_count; index++)
        if (manifest->matches[index].reserved) return -1;
    for (u32 index = 0; index < manifest->request_count; index++) {
        const struct driver_user_request *request = &manifest->requests[index];
        if (!request->kind || request->kind > DRIVER_RESOURCE_BRIDGE ||
            !request->rights || (request->rights & ~KRIGHT_ALL))
            return -1;
        if (request->kind == DRIVER_RESOURCE_BAR && request->index >= 6)
            return -1;
        if (request->kind == DRIVER_RESOURCE_DMA &&
            (!request->amount || request->amount > 256 ||
             request->limit < 0xFFFFF))
            return -1;
        if (request->kind == DRIVER_RESOURCE_MSI &&
            (!request->amount || request->amount > 32 ||
             (request->amount & (request->amount - 1))))
            return -1;
        if (request->kind == DRIVER_RESOURCE_MSIX_IRQ &&
            (!request->amount || request->amount > 32))
            return -1;
        if (request->kind == DRIVER_RESOURCE_BRIDGE && request->index)
            return -1;
        for (u32 prior = 0; prior < index; prior++)
            if (manifest->requests[prior].kind == request->kind &&
                manifest->requests[prior].index == request->index)
                return -1;
    }
    return 0;
}

int driver_user_manifest_matches(const struct driver_user_manifest *manifest,
                                 struct kernel_object *device) {
    if (driver_user_manifest_validate(manifest)) return 0;
    const struct pci_resource *pci = pci_resource_get(device);
    if (!pci) return 0;
    if (!manifest->match_count) return 1;
    for (u32 index = 0; index < manifest->match_count; index++) {
        const struct driver_user_match *match = &manifest->matches[index];
        if (match->vendor_id != 0xFFFF && match->vendor_id != pci->vendor_id)
            continue;
        if (match->device_id != 0xFFFF && match->device_id != pci->device_id)
            continue;
        if (match->class_code != 0xFF && match->class_code != pci->class_code)
            continue;
        if (match->subclass != 0xFF && match->subclass != pci->subclass)
            continue;
        if (match->programming_interface != 0xFF &&
            match->programming_interface != pci->programming_interface)
            continue;
        return 1;
    }
    return 0;
}

static struct driver_domain *driver_domain_create_user_locked(
    const struct driver_user_manifest *manifest, struct kernel_object *device) {
    if (!driver_user_manifest_matches(manifest, device)) return 0;
    struct driver_domain_manifest base;
    base.name = manifest->name;
    base.capabilities = manifest->capabilities;
    base.restart_policy = manifest->restart_policy;
    base.max_restarts = manifest->max_restarts;
    base.backoff_ticks = manifest->backoff_ticks;
    base.image_id = manifest->image_id;
    base.reset_policy = manifest->reset_policy;
    base.weight = manifest->weight;
    base.argument = manifest->argument;
    struct driver_domain *domain = driver_domain_create_locked(&base, device);
    if (domain) {
        domain->manifest_flags = manifest->flags;
        domain->firmware_count = manifest->firmware_count;
        for (u32 firmware = 0; firmware < manifest->firmware_count; firmware++)
            for (u32 byte = 0; byte < DRIVER_USER_NAME_MAX; byte++)
                domain->firmware[firmware][byte] =
                    manifest->firmware[firmware][byte];
    }
    return domain;
}

struct driver_domain *driver_domain_create_user(
    const struct driver_user_manifest *manifest, struct kernel_object *device) {
    klock_acquire(&driver_supervisor_klock);
    struct driver_domain *result = driver_domain_create_user_locked(manifest,
                                                                    device);
    klock_release(&driver_supervisor_klock);
    return result;
}

static void rollback_resources(struct driver_domain *domain, u32 count) {
    while (domain->resource_count > count) {
        struct driver_domain_resource *resource =
            &domain->resources[--domain->resource_count];
        object_release(resource->object);
        resource->object = 0;
        resource->rights = 0;
        resource->kind = 0;
        resource->index = 0;
        resource->flags = 0;
    }
    if (domain->bridge_index >= domain->resource_count)
        domain->bridge_index = DRIVER_DOMAIN_RESOURCE_MAX;
}

static int driver_domain_apply_manifest_locked(
    struct driver_domain *domain, const struct driver_user_manifest *manifest,
    driver_resource_provider_fn provider) {
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_STOPPED ||
        driver_user_manifest_validate(manifest) ||
        !driver_user_manifest_matches(manifest, domain->device))
        return -1;
    u32 original_count = domain->resource_count;
    for (u32 index = 0; index < manifest->request_count; index++) {
        const struct driver_user_request *request = &manifest->requests[index];
        int result;
        if (request->kind == DRIVER_RESOURCE_BRIDGE) {
            result = driver_domain_add_bridge_locked(domain, request->rights);
        } else if (request->kind == DRIVER_RESOURCE_PCI) {
            result = driver_domain_add_resource_kind_locked(
                domain, domain->device, request->rights, request->kind,
                request->index, request->flags);
        } else {
            struct kernel_object *objects[DRIVER_DOMAIN_RESOURCE_MAX];
            for (u32 item = 0; item < DRIVER_DOMAIN_RESOURCE_MAX; item++)
                objects[item] = 0;
            u32 capacity = DRIVER_DOMAIN_RESOURCE_MAX - domain->resource_count;
            int provided = provider ? provider(
                domain, request, objects, capacity) : -1;
            result = provided <= 0 || (u32)provided > capacity ? -1 : 0;
            u32 supplied = provided > 0 && (u32)provided <= capacity
                ? (u32)provided : 0;
            if (!supplied)
                for (u32 item = 0; item < capacity; item++)
                    if (objects[item]) object_release(objects[item]);
            for (u32 item = 0; item < supplied; item++) {
                if (!result && driver_domain_add_resource_kind_locked(
                        domain, objects[item], request->rights, request->kind,
                        request->index + (u32)item, request->flags))
                    result = -1;
                if (objects[item]) object_release(objects[item]);
            }
        }
        if (result) {
            rollback_resources(domain, original_count);
            return -1;
        }
    }
    return 0;
}

int driver_domain_apply_manifest(struct driver_domain *domain,
                                 const struct driver_user_manifest *manifest,
                                 driver_resource_provider_fn provider) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_apply_manifest_locked(domain, manifest,
                                                     provider);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_add_resource_kind_locked(struct driver_domain *domain,
                                                  struct kernel_object *object,
                                                  u32 rights, u32 kind,
                                                  u32 index, u64 flags) {
    u32 expected_type = kind == DRIVER_RESOURCE_PCI ? KOBJECT_PCI :
        kind == DRIVER_RESOURCE_BAR ? KOBJECT_MMIO :
        kind == DRIVER_RESOURCE_DMA ? KOBJECT_DMA :
        kind == DRIVER_RESOURCE_MSIX_TABLE ? KOBJECT_MSIX_TABLE :
        kind == DRIVER_RESOURCE_BRIDGE ? KOBJECT_ENDPOINT : KOBJECT_IRQ;
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_STOPPED ||
        !object || !object->active || object->type != expected_type ||
        !rights || (rights & ~KRIGHT_ALL) ||
        !kind || kind > DRIVER_RESOURCE_BRIDGE ||
        domain->resource_count >= DRIVER_DOMAIN_RESOURCE_MAX)
        return -1;
    for (u32 slot = 0; slot < domain->resource_count; slot++)
        if (domain->resources[slot].object == object ||
            (domain->resources[slot].kind == kind &&
             domain->resources[slot].index == index))
            return -1;
    if (object_retain(object)) return -1;
    struct driver_domain_resource *resource =
        &domain->resources[domain->resource_count++];
    resource->object = object;
    resource->rights = rights;
    resource->kind = kind;
    resource->index = index;
    resource->flags = flags;
    return 0;
}

int driver_domain_add_resource_kind(struct driver_domain *domain,
                                    struct kernel_object *object, u32 rights,
                                    u32 kind, u32 index, u64 flags) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_add_resource_kind_locked(domain, object, rights,
                                                        kind, index, flags);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_add_resource_locked(struct driver_domain *domain,
                                             struct kernel_object *object,
                                             u32 rights) {
    u32 kind = resource_kind(object);
    return kind ? driver_domain_add_resource_kind_locked(domain, object, rights,
                                                   kind, 0, 0) : -1;
}

int driver_domain_add_resource(struct driver_domain *domain,
                               struct kernel_object *object, u32 rights) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_add_resource_locked(domain, object, rights);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_add_bridge_locked(struct driver_domain *domain,
                                           u32 rights) {
    if (!domain || domain->bridge_index < DRIVER_DOMAIN_RESOURCE_MAX ||
        !(rights & KRIGHT_WAIT))
        return -1;
    struct kernel_object *bridge = bridge_endpoint_create();
    if (!bridge) return -1;
    u32 index = domain->resource_count;
    int result = driver_domain_add_resource_kind_locked(
        domain, bridge, rights, DRIVER_RESOURCE_BRIDGE, 0, 0);
    object_release(bridge);
    if (result) return -1;
    domain->bridge_index = index;
    return 0;
}

int driver_domain_add_bridge(struct driver_domain *domain, u32 rights) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_add_bridge_locked(domain, rights);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_set_recovery_fallback_locked(
    struct driver_domain *domain,
    const struct driver_recovery_profile *profile) {
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_STOPPED ||
        domain->generation || !recovery_profile_valid(domain, profile))
        return -1;
    domain->fallback = *profile;
    recovery_selector_clear(domain);
    domain->recovery_profile = DRIVER_RECOVERY_PRIMARY;
    domain->fallback_enabled = 1;
    domain->fallback_used = 0;
    domain->fallback_triggers = DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT;
    return 0;
}

int driver_domain_set_recovery_fallback(
    struct driver_domain *domain,
    const struct driver_recovery_profile *profile) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_set_recovery_fallback_locked(domain, profile);
    klock_release(&driver_supervisor_klock);
    return result;
}

int driver_recovery_selector_validate(
    const struct driver_recovery_selector *selector) {
    if (!selector || selector->vendor_id == 0xFFFF ||
        selector->device_id == 0xFFFF ||
        selector->fingerprint.kind != DRIVER_CRASH_USER_EXCEPTION ||
        !selector->fingerprint.code || selector->fingerprint.vector > 31 ||
        !selector->fingerprint.rip)
        return -1;
    return 0;
}

static int driver_domain_set_recovery_fallback_selector_locked(
    struct driver_domain *domain,
    const struct driver_recovery_selector *selector) {
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_STOPPED ||
        domain->generation || !domain->fallback_enabled ||
        !(domain->fallback_triggers & DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT) ||
        driver_recovery_selector_validate(selector))
        return -1;
    domain->fallback_selector = *selector;
    domain->fallback_selector_enabled = 1;
    return 0;
}

int driver_domain_set_recovery_fallback_selector(
    struct driver_domain *domain,
    const struct driver_recovery_selector *selector) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_set_recovery_fallback_selector_locked(domain,
                                                                     selector);
    klock_release(&driver_supervisor_klock);
    return result;
}

int driver_recovery_fallback_triggers_validate(u32 triggers) {
    return !triggers || (triggers & ~DRIVER_RECOVERY_TRIGGER_ALL) ? -1 : 0;
}

static int driver_domain_set_recovery_fallback_triggers_locked(
    struct driver_domain *domain, u32 triggers) {
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_STOPPED ||
        domain->generation || !domain->fallback_enabled ||
        driver_recovery_fallback_triggers_validate(triggers))
        return -1;
    domain->fallback_triggers = triggers;
    return 0;
}

int driver_domain_set_recovery_fallback_triggers(struct driver_domain *domain,
                                                 u32 triggers) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_set_recovery_fallback_triggers_locked(domain,
                                                                     triggers);
    klock_release(&driver_supervisor_klock);
    return result;
}

int driver_crash_circuit_policy_validate(
    const struct driver_crash_circuit_policy *policy) {
    return !policy || !policy->repeat_limit ||
           policy->repeat_limit > DRIVER_CRASH_REPEAT_LIMIT_MAX ||
           !policy->repeat_window_ticks ||
           policy->repeat_window_ticks > DRIVER_CRASH_REPEAT_WINDOW_TICKS_MAX ?
           -1 : 0;
}

static int driver_domain_set_crash_circuit_policy_locked(
    struct driver_domain *domain,
    const struct driver_crash_circuit_policy *policy) {
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_STOPPED ||
        domain->generation || driver_crash_circuit_policy_validate(policy))
        return -1;
    domain->crash_policy = *policy;
    return 0;
}

int driver_domain_set_crash_circuit_policy(
    struct driver_domain *domain,
    const struct driver_crash_circuit_policy *policy) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_set_crash_circuit_policy_locked(domain, policy);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_start_locked(struct driver_domain *domain) {
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_STOPPED)
        return -1;
    domain->terminal_reason = DRIVER_TERMINAL_NONE;
    if (launch(domain)) {
        domain->terminal_reason = DRIVER_TERMINAL_LAUNCH_FAILURE;
        domain->last_decision = DRIVER_RECOVERY_DECISION_LAUNCH_FAILURE;
        domain->state = DRIVER_DOMAIN_FAILED;
        return -1;
    }
    domain->last_decision = DRIVER_RECOVERY_DECISION_START;
    return 0;
}

int driver_domain_start(struct driver_domain *domain) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_start_locked(domain);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_bundle_locked(const struct driver_domain *domain,
                                       u32 *handles, u32 capacity) {
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_RUNNING ||
        (!handles && domain->resource_count) || capacity < domain->resource_count)
        return -1;
    for (u32 index = 0; index < domain->resource_count; index++) {
        if (!domain->issued_handles[index]) return -1;
        handles[index] = domain->issued_handles[index];
    }
    return (int)domain->resource_count;
}

int driver_domain_bundle(const struct driver_domain *domain, u32 *handles,
                         u32 capacity) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_bundle_locked(domain, handles, capacity);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_status_locked(const struct driver_domain *domain,
                                       struct driver_domain_status *status) {
    if (!domain || !domain->active || !status) return -1;
    status->id = domain->id;
    status->state = domain->state;
    status->pid = domain->pid;
    status->generation = domain->generation;
    status->image_id = domain->image_id;
    status->capabilities = domain->capabilities;
    status->argument = domain->argument;
    status->recovery_profile = domain->recovery_profile;
    status->fallback_enabled = domain->fallback_enabled;
    status->fallback_selector_enabled = domain->fallback_selector_enabled;
    status->fallback_selector = domain->fallback_selector;
    status->recovery_audit = domain->recovery_audit;
    status->fallback_used = domain->fallback_used;
    status->fallback_triggers = domain->fallback_triggers;
    status->restart_count = domain->restart_count;
    status->restart_deadline = domain->restart_deadline;
    status->stop_deadline = domain->stop_deadline;
    status->stop_ack = domain->stop_ack;
    status->crash_repeat_count = domain->crash_repeat_count;
    status->crash_repeat_deadline = domain->crash_repeat_deadline;
    status->crash_policy = domain->crash_policy;
    status->terminal_reason = domain->terminal_reason;
    status->last_decision = domain->last_decision;
    status->last_crash = domain->last_crash;
    return 0;
}

int driver_domain_status(const struct driver_domain *domain,
                         struct driver_domain_status *status) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_status_locked(domain, status);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_bootstrap_locked(int pid,
                                          struct driver_bootstrap_info *info) {
    if (!info) return -1;
    struct driver_domain *domain = 0;
    for (u32 index = 0; index < DRIVER_DOMAIN_MAX; index++)
        if (domains[index].active &&
            domains[index].state == DRIVER_DOMAIN_RUNNING &&
            domains[index].pid == pid)
            domain = &domains[index];
    if (!domain) return -1;
    const struct pci_resource *pci = pci_resource_get(domain->device);
    if (!pci) return -1;
    u8 *bytes = (u8 *)info;
    for (usize_t index = 0; index < sizeof(*info); index++) bytes[index] = 0;
    info->abi_version = DRIVER_USER_ABI_VERSION;
    info->size = sizeof(*info);
    info->domain_id = domain->id;
    info->generation = domain->generation;
    info->pid = (u32)domain->pid;
    info->state = domain->state;
    info->manifest_flags = domain->manifest_flags;
    info->restart_count = domain->restart_count;
    info->image_id = domain->image_id;
    info->segment = pci->segment;
    info->bus = pci->bus;
    info->device = pci->device;
    info->function = pci->function;
    info->class_code = pci->class_code;
    info->subclass = pci->subclass;
    info->programming_interface = pci->programming_interface;
    info->vendor_id = pci->vendor_id;
    info->device_id = pci->device_id;
    info->resource_count = domain->resource_count;
    info->reset_policy = domain->reset_policy;
    for (u32 index = 0; index < DRIVER_USER_NAME_MAX; index++)
        info->name[index] = domain->name[index];
    for (u32 index = 0; index < domain->resource_count; index++) {
        const struct driver_domain_resource *source = &domain->resources[index];
        struct driver_bootstrap_resource *target = &info->resources[index];
        target->kind = source->kind;
        target->index = source->index;
        target->handle = domain->issued_handles[index];
        target->rights = source->rights;
        target->flags = source->flags;
        if (source->object->type == KOBJECT_IRQ) {
            const struct irq_resource *irq = irq_resource_get(source->object);
            if (!irq) return -1;
            target->flags = (source->flags <<
                             DRIVER_BOOTSTRAP_REQUEST_FLAGS_SHIFT) |
                            irq->source;
        } else if (source->object->type == KOBJECT_MMIO) {
            const struct mmio_resource *resource =
                mmio_resource_get(source->object);
            if (resource) target->length = resource->length;
        } else if (source->object->type == KOBJECT_DMA) {
            const struct dma_resource *resource =
                dma_resource_get(source->object);
            if (resource) {
                target->length = (u64)resource->pages * 4096;
                target->address = resource->bus_address;
            }
        } else if (source->object->type == KOBJECT_MSIX_TABLE) {
            const struct msix_table_resource *resource =
                msix_table_resource_get(source->object);
            if (resource) target->length = (u64)resource->entries * 16;
        }
        if (!target->handle) return -1;
    }
    return 0;
}

int driver_domain_bootstrap(int pid, struct driver_bootstrap_info *info) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_bootstrap_locked(pid, info);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_request_stop_locked(struct driver_domain *domain) {
    if (!domain || !domain->active || domain->state != DRIVER_DOMAIN_RUNNING ||
        !(domain->manifest_flags & DRIVER_MANIFEST_GRACEFUL_STOP) ||
        domain->bridge_index >= domain->resource_count)
        return -1;
    struct kernel_object *bridge =
        domain->resources[domain->bridge_index].object;
    if (!bridge || bridge->type != KOBJECT_ENDPOINT ||
        endpoint_signal(bridge, DRIVER_CONTROL_STOP))
        return -1;
    domain->state = DRIVER_DOMAIN_STOPPING;
    domain->last_decision = DRIVER_RECOVERY_DECISION_STOP_REQUEST;
    domain->stop_deadline = now_ticks + DRIVER_STOP_GRACE_TICKS;
    domain->stop_ack = 0;
    return 0;
}

int driver_domain_request_stop(struct driver_domain *domain) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_request_stop_locked(domain);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_stop_ack_locked(int pid) {
    for (u32 i = 0; i < DRIVER_DOMAIN_MAX; i++) {
        struct driver_domain *d = &domains[i];
        if (!d->active || d->state != DRIVER_DOMAIN_STOPPING || d->pid != pid)
            continue;
        if (d->stop_ack) return -1;
        d->stop_ack = 1;
        return 0;
    }
    return -1;
}

int driver_domain_stop_ack(int pid) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_stop_ack_locked(pid);
    klock_release(&driver_supervisor_klock);
    return result;
}

static void driver_supervisor_report_user_fault_locked(int pid, u32 vector,
                                                       u64 error, u64 rip,
                                                       u64 address, u32 ticks) {
    struct driver_domain *domain = driver_domain_for_pid_locked(pid);
    if (!domain) return;
    passport_clear(&domain->pending_crash);
    domain->pending_crash.kind = DRIVER_CRASH_USER_EXCEPTION;
    domain->pending_crash.generation = domain->generation;
    domain->pending_crash.ticks = ticks;
    domain->pending_crash.vector = vector;
    domain->pending_crash.error = error;
    domain->pending_crash.rip = rip;
    domain->pending_crash.address = address;
}

void driver_supervisor_report_user_fault(
    int pid, u32 vector, u64 error, u64 rip, u64 address, u32 ticks) {
    klock_acquire(&driver_supervisor_klock);
    driver_supervisor_report_user_fault_locked(pid, vector, error, rip, address,
                                               ticks);
    klock_release(&driver_supervisor_klock);
}

static void driver_supervisor_report_iommu_fault_locked(
    u32 id, u16 segment, u16 source_id, u8 reason, u8 write, u64 address,
    u32 ticks) {
    struct driver_domain *domain = driver_domain_for_id_locked(id);
    if (!domain || (domain->state != DRIVER_DOMAIN_RUNNING &&
                    domain->state != DRIVER_DOMAIN_STOPPING))
        return;
    passport_clear(&domain->pending_crash);
    passport_clear(&domain->last_crash);
    domain->last_crash.kind = DRIVER_CRASH_IOMMU;
    domain->last_crash.generation = domain->generation;
    domain->last_crash.ticks = ticks;
    domain->last_crash.segment = segment;
    domain->last_crash.source_id = source_id;
    domain->last_crash.reason = reason;
    domain->last_crash.write = write;
    domain->last_crash.address = address;
    domain->terminal_reason = DRIVER_TERMINAL_IOMMU_FAULT;
    domain->last_decision = DRIVER_RECOVERY_DECISION_IOMMU_QUARANTINE;
    domain->crash_repeat_count = 0;
    domain->crash_repeat_deadline = 0;
}

void driver_supervisor_report_iommu_fault(u32 id, u16 segment, u16 source_id,
                                          u8 reason, u8 write, u64 address,
                                          u32 ticks) {
    klock_acquire(&driver_supervisor_klock);
    driver_supervisor_report_iommu_fault_locked(id, segment, source_id, reason,
                                                write, address, ticks);
    klock_release(&driver_supervisor_klock);
}

static void driver_supervisor_task_died_locked(int pid, int code, u32 ticks) {
    for (u32 i = 0; i < DRIVER_DOMAIN_MAX; i++) {
        struct driver_domain *d = &domains[i];
        if (!d->active ||
            (d->state != DRIVER_DOMAIN_RUNNING &&
             d->state != DRIVER_DOMAIN_STOPPING) || d->pid != pid)
            continue;
        int stopping = d->state == DRIVER_DOMAIN_STOPPING;
        int ack = d->stop_ack;
        struct driver_crash_passport passport;
        crash_passport_for_death(d, code, ticks, &passport);
        int circuit_open = code && crash_circuit_open(d, &passport, ticks);
        if (code) d->last_crash = passport;
        int rc = teardown(d);
        d->stop_deadline = 0;
        d->stop_ack = 0;
        if (rc) {
            d->terminal_reason = DRIVER_TERMINAL_TEARDOWN_FAILURE;
            d->last_decision = DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE;
            d->state = DRIVER_DOMAIN_QUARANTINED;
            continue;
        }
        if (stopping) {
            if (!code && ack) {
                d->terminal_reason = DRIVER_TERMINAL_NONE;
                d->last_decision = DRIVER_RECOVERY_DECISION_STOP_ACK;
                d->state = DRIVER_DOMAIN_STOPPED;
            } else {
                d->terminal_reason = DRIVER_TERMINAL_STOP_FAILURE;
                d->last_decision = DRIVER_RECOVERY_DECISION_STOP_FAILURE;
                d->state = DRIVER_DOMAIN_FAILED;
            }
            continue;
        }
        if (!code) {
            d->terminal_reason = DRIVER_TERMINAL_NONE;
            d->last_decision = DRIVER_RECOVERY_DECISION_STOP;
            d->crash_repeat_count = 0;
            d->crash_repeat_deadline = 0;
            d->state = DRIVER_DOMAIN_STOPPED;
            continue;
        }
        if (circuit_open) {
            if (recovery_fallback_activate(
                    d, ticks, DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT,
                    &passport))
                continue;
            d->terminal_reason = DRIVER_TERMINAL_CRASH_CIRCUIT;
            d->last_decision = DRIVER_RECOVERY_DECISION_CRASH_CIRCUIT;
            d->restart_deadline = 0;
            d->state = DRIVER_DOMAIN_FAILED;
            continue;
        }
        if (d->restart_policy != DRIVER_RESTART_ON_FAILURE) {
            d->terminal_reason = DRIVER_TERMINAL_RESTART_LIMIT;
            d->last_decision = DRIVER_RECOVERY_DECISION_RESTART_LIMIT;
            d->state = DRIVER_DOMAIN_FAILED;
            continue;
        }
        if (d->restart_count >= d->max_restarts) {
            if (recovery_fallback_activate(
                    d, ticks, DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT,
                    &passport))
                continue;
            d->terminal_reason = DRIVER_TERMINAL_RESTART_LIMIT;
            d->last_decision = DRIVER_RECOVERY_DECISION_RESTART_LIMIT;
            d->state = DRIVER_DOMAIN_FAILED;
            continue;
        }
        d->terminal_reason = DRIVER_TERMINAL_NONE;
        d->last_decision = DRIVER_RECOVERY_DECISION_RESTART;
        d->restart_count++;
        d->restart_deadline = ticks + d->backoff_ticks * d->restart_count;
        d->state = DRIVER_DOMAIN_BACKOFF;
    }
}

void driver_supervisor_task_died(int pid, int code, u32 ticks) {
    klock_acquire(&driver_supervisor_klock);
    driver_supervisor_task_died_locked(pid, code, ticks);
    klock_release(&driver_supervisor_klock);
}

static void driver_supervisor_tick_locked(u32 ticks) {
    now_ticks = ticks;
    for (u32 i = 0; i < DRIVER_DOMAIN_MAX; i++) {
        struct driver_domain *d = &domains[i];
        if (!d->active) continue;
        if (d->state == DRIVER_DOMAIN_STOPPING &&
            (i32)(ticks - d->stop_deadline) >= 0) {
            int pid = d->pid;
            int rc = teardown(d);
            d->stop_deadline = 0;
            d->stop_ack = 0;
            d->state = rc ? DRIVER_DOMAIN_QUARANTINED : DRIVER_DOMAIN_STOPPED;
            d->terminal_reason = rc ? DRIVER_TERMINAL_TEARDOWN_FAILURE :
                                      DRIVER_TERMINAL_NONE;
            d->last_decision = rc ?
                DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE :
                DRIVER_RECOVERY_DECISION_STOP_TIMEOUT;
            if (!rc && terminate_task(pid)) {
                d->terminal_reason = DRIVER_TERMINAL_STOP_FAILURE;
                d->last_decision = DRIVER_RECOVERY_DECISION_STOP_FAILURE;
                d->state = DRIVER_DOMAIN_QUARANTINED;
            }
            continue;
        }
        if (d->state != DRIVER_DOMAIN_BACKOFF ||
            (i32)(ticks - d->restart_deadline) < 0)
            continue;
        if (launch(d)) {
            d->terminal_reason = DRIVER_TERMINAL_LAUNCH_FAILURE;
            d->last_decision = DRIVER_RECOVERY_DECISION_LAUNCH_FAILURE;
            d->state = DRIVER_DOMAIN_FAILED;
        }
    }
}

void driver_supervisor_tick(u32 ticks) {
    klock_acquire(&driver_supervisor_klock);
    driver_supervisor_tick_locked(ticks);
    klock_release(&driver_supervisor_klock);
}

static int driver_domain_stop_locked(struct driver_domain *d) {
    if (!d || !d->active || d->state == DRIVER_DOMAIN_QUARANTINED)
        return -1;
    int rc = 0;
    if (d->state == DRIVER_DOMAIN_RUNNING || d->state == DRIVER_DOMAIN_STOPPING) {
        int pid = d->pid;
        rc = teardown(d);
        d->state = rc ? DRIVER_DOMAIN_QUARANTINED : DRIVER_DOMAIN_STOPPED;
        if (!rc && terminate_task(pid))
            rc = -1;
    }
    d->state = rc ? DRIVER_DOMAIN_QUARANTINED : DRIVER_DOMAIN_STOPPED;
    d->terminal_reason = rc ? DRIVER_TERMINAL_TEARDOWN_FAILURE :
                              DRIVER_TERMINAL_NONE;
    d->last_decision = rc ? DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE :
                            DRIVER_RECOVERY_DECISION_STOP;
    d->restart_deadline = 0;
    d->stop_deadline = 0;
    d->stop_ack = 0;
    return rc;
}

int driver_domain_stop(struct driver_domain *d) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_stop_locked(d);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_remove_locked(struct driver_domain *domain) {
    if (!domain || !domain->active) return -1;
    int result = driver_domain_stop_locked(domain);
    if (quiesce_backend && quiesce_backend(domain->device)) result = -1;
    domain->state = result ? DRIVER_DOMAIN_QUARANTINED
                           : DRIVER_DOMAIN_REMOVED;
    domain->terminal_reason = result ? DRIVER_TERMINAL_TEARDOWN_FAILURE :
                                       DRIVER_TERMINAL_NONE;
    domain->last_decision = result ?
        DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE :
        DRIVER_RECOVERY_DECISION_REMOVE;
    return result;
}

int driver_domain_remove(struct driver_domain *domain) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_remove_locked(domain);
    klock_release(&driver_supervisor_klock);
    return result;
}

static void driver_domain_destroy_locked(struct driver_domain *domain) {
    if (!domain || !domain->active ||
        domain->state == DRIVER_DOMAIN_QUARANTINED)
        return;
    if (driver_domain_stop_locked(domain) ||
        domain->state == DRIVER_DOMAIN_QUARANTINED)
        return;
    for (u32 index = 0; index < domain->resource_count; index++) {
        object_release(domain->resources[index].object);
        domain->resources[index].object = 0;
        domain->resources[index].rights = 0;
        domain->resources[index].kind = 0;
        domain->resources[index].index = 0;
        domain->resources[index].flags = 0;
    }
    if (release_backend && release_backend(domain)) {
        domain->terminal_reason = DRIVER_TERMINAL_TEARDOWN_FAILURE;
        domain->last_decision = DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE;
        domain->state = DRIVER_DOMAIN_QUARANTINED;
        return;
    }
    object_release(domain->device);
    domain->device = 0;
    domain->resource_count = 0;
    domain->bridge_index = DRIVER_DOMAIN_RESOURCE_MAX;
    crash_state_clear(domain);
    crash_policy_default(domain);
    recovery_fallback_clear(domain);
    domain->stop_deadline = 0;
    domain->stop_ack = 0;
    domain->id = 0;
    domain->pid = -1;
    domain->name[0] = 0;
    domain->firmware_count = 0;
    for (u32 firmware = 0; firmware < DRIVER_USER_FIRMWARE_MAX; firmware++)
        for (u32 byte = 0; byte < DRIVER_USER_NAME_MAX; byte++)
            domain->firmware[firmware][byte] = 0;
    domain->active = 0;
}

void driver_domain_destroy(struct driver_domain *domain) {
    klock_acquire(&driver_supervisor_klock);
    driver_domain_destroy_locked(domain);
    klock_release(&driver_supervisor_klock);
}

static int driver_domain_admin_release_locked(struct driver_domain *domain) {
    if (!domain || !domain->active ||
        domain->state != DRIVER_DOMAIN_QUARANTINED)
        return -1;
    domain->state = DRIVER_DOMAIN_STOPPED;
    driver_domain_destroy_locked(domain);
    return domain->active ? -1 : 0;
}

int driver_domain_admin_release(struct driver_domain *domain) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_admin_release_locked(domain);
    klock_release(&driver_supervisor_klock);
    return result;
}

static struct driver_domain *driver_domain_for_id_locked(u32 id) {
    if (!id) return 0;
    for (u32 i = 0; i < DRIVER_DOMAIN_MAX; i++)
        if (domains[i].active && domains[i].id == id) return &domains[i];
    return 0;
}

struct driver_domain *driver_domain_for_id(u32 id) {
    klock_acquire(&driver_supervisor_klock);
    struct driver_domain *result = driver_domain_for_id_locked(id);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_quarantine_locked(u32 id) {
    struct driver_domain *d = driver_domain_for_id_locked(id);
    if (!d || d->state == DRIVER_DOMAIN_QUARANTINED) return -1;
    int pid = d->pid;
    int rc = 0;
    if (d->state == DRIVER_DOMAIN_RUNNING || d->state == DRIVER_DOMAIN_STOPPING)
        rc = teardown(d);
    if (terminate_task(pid)) rc = -1;
    d->state = DRIVER_DOMAIN_QUARANTINED;
    if (d->terminal_reason == DRIVER_TERMINAL_NONE) {
        d->terminal_reason = DRIVER_TERMINAL_QUARANTINE;
        d->last_decision = rc ? DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE :
                                DRIVER_RECOVERY_DECISION_MANUAL_QUARANTINE;
    }
    d->restart_deadline = 0;
    d->stop_deadline = 0;
    d->stop_ack = 0;
    return rc;
}

int driver_domain_quarantine(u32 id) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_quarantine_locked(id);
    klock_release(&driver_supervisor_klock);
    return result;
}

static struct driver_domain *driver_domain_for_device_locked(
    struct kernel_object *device) {
    if (!device) return 0;
    for (u32 index = 0; index < DRIVER_DOMAIN_MAX; index++)
        if (domains[index].active && domains[index].device == device &&
            domains[index].state != DRIVER_DOMAIN_REMOVED)
            return &domains[index];
    return 0;
}

struct driver_domain *driver_domain_for_device(struct kernel_object *device) {
    klock_acquire(&driver_supervisor_klock);
    struct driver_domain *result = driver_domain_for_device_locked(device);
    klock_release(&driver_supervisor_klock);
    return result;
}

static struct driver_domain *driver_domain_for_pid_locked(int pid) {
    if (!pid) return 0;
    for (u32 index = 0; index < DRIVER_DOMAIN_MAX; index++)
        if (domains[index].active && domains[index].pid == pid &&
            domains[index].state == DRIVER_DOMAIN_RUNNING)
            return &domains[index];
    return 0;
}

struct driver_domain *driver_domain_for_pid(int pid) {
    klock_acquire(&driver_supervisor_klock);
    struct driver_domain *result = driver_domain_for_pid_locked(pid);
    klock_release(&driver_supervisor_klock);
    return result;
}

static int driver_domain_firmware_allowed_locked(
    const struct driver_domain *domain, const char *name) {
    if (!domain || !domain->active || !name) return 0;
    for (u32 index = 0; index < domain->firmware_count; index++)
        if (abi_names_equal(domain->firmware[index], name)) return 1;
    return 0;
}

int driver_domain_firmware_allowed(const struct driver_domain *domain,
                                   const char *name) {
    klock_acquire(&driver_supervisor_klock);
    int result = driver_domain_firmware_allowed_locked(domain, name);
    klock_release(&driver_supervisor_klock);
    return result;
}

static u32 driver_domain_count_locked(void) {
    u32 count = 0;
    for (u32 index = 0; index < DRIVER_DOMAIN_MAX; index++)
        if (domains[index].active) count++;
    return count;
}

u32 driver_domain_count(void) {
    klock_acquire(&driver_supervisor_klock);
    u32 result = driver_domain_count_locked();
    klock_release(&driver_supervisor_klock);
    return result;
}

u32 driver_domain_state(const struct driver_domain *domain) {
    if (!domain) return 0;
    klock_acquire(&driver_supervisor_klock);
    u32 state = domain->state;
    klock_release(&driver_supervisor_klock);
    return state;
}

int driver_domain_pid(const struct driver_domain *domain) {
    if (!domain) return -1;
    klock_acquire(&driver_supervisor_klock);
    int pid = domain->pid;
    klock_release(&driver_supervisor_klock);
    return pid;
}
