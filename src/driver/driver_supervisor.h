#ifndef DRIVER_SUPERVISOR_H
#define DRIVER_SUPERVISOR_H

#include "types.h"
#include "object.h"
#include "driver_abi.h"

#define DRIVER_DOMAIN_MAX 16
#define DRIVER_DOMAIN_RESOURCE_MAX 16

#define DRIVER_DOMAIN_STOPPED 0
#define DRIVER_DOMAIN_RUNNING 1
#define DRIVER_DOMAIN_BACKOFF 2
#define DRIVER_DOMAIN_FAILED 3
#define DRIVER_DOMAIN_REMOVED 4
#define DRIVER_DOMAIN_QUARANTINED 5
#define DRIVER_DOMAIN_STOPPING 6

#define DRIVER_CRASH_NONE 0
#define DRIVER_CRASH_EXIT 1
#define DRIVER_CRASH_USER_EXCEPTION 2
#define DRIVER_CRASH_IOMMU 3

#define DRIVER_CRASH_REPEAT_LIMIT 2
#define DRIVER_CRASH_REPEAT_WINDOW_TICKS 64
#define DRIVER_CRASH_REPEAT_LIMIT_MAX 1024
#define DRIVER_CRASH_REPEAT_WINDOW_TICKS_MAX 0x7FFFFFFFU

struct driver_crash_passport {
    u32 kind;
    u32 code;
    u32 generation;
    u32 ticks;
    u32 vector;
    u32 segment;
    u32 source_id;
    u32 reason;
    u32 write;
    u64 error;
    u64 rip;
    u64 address;
};

#define DRIVER_RECOVERY_PRIMARY 0
#define DRIVER_RECOVERY_FALLBACK 1

#define DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT (1u << 0)
#define DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT (1u << 1)
#define DRIVER_RECOVERY_TRIGGER_ALL (DRIVER_RECOVERY_TRIGGER_CRASH_CIRCUIT | \
                                     DRIVER_RECOVERY_TRIGGER_RESTART_LIMIT)

#define DRIVER_TERMINAL_NONE 0
#define DRIVER_TERMINAL_RESTART_LIMIT 1
#define DRIVER_TERMINAL_CRASH_CIRCUIT 2
#define DRIVER_TERMINAL_TEARDOWN_FAILURE 3
#define DRIVER_TERMINAL_LAUNCH_FAILURE 4
#define DRIVER_TERMINAL_IOMMU_FAULT 5
#define DRIVER_TERMINAL_QUARANTINE 6
#define DRIVER_TERMINAL_STOP_FAILURE 7

#define DRIVER_RECOVERY_DECISION_NONE 0
#define DRIVER_RECOVERY_DECISION_START 1
#define DRIVER_RECOVERY_DECISION_RESTART 2
#define DRIVER_RECOVERY_DECISION_FALLBACK 3
#define DRIVER_RECOVERY_DECISION_STOP 4
#define DRIVER_RECOVERY_DECISION_STOP_REQUEST 5
#define DRIVER_RECOVERY_DECISION_STOP_ACK 6
#define DRIVER_RECOVERY_DECISION_STOP_TIMEOUT 7
#define DRIVER_RECOVERY_DECISION_STOP_FAILURE 8
#define DRIVER_RECOVERY_DECISION_RESTART_LIMIT 9
#define DRIVER_RECOVERY_DECISION_CRASH_CIRCUIT 10
#define DRIVER_RECOVERY_DECISION_TEARDOWN_QUARANTINE 11
#define DRIVER_RECOVERY_DECISION_LAUNCH_FAILURE 12
#define DRIVER_RECOVERY_DECISION_IOMMU_QUARANTINE 13
#define DRIVER_RECOVERY_DECISION_MANUAL_QUARANTINE 14
#define DRIVER_RECOVERY_DECISION_REMOVE 15

#define DRIVER_RECOVERY_AUDIT_NONE 0
#define DRIVER_RECOVERY_AUDIT_SELECTED 1
#define DRIVER_RECOVERY_AUDIT_UNAVAILABLE 2
#define DRIVER_RECOVERY_AUDIT_SELECTOR_MISMATCH 3

struct driver_recovery_profile {
    u32 image_id;
    u32 capabilities;
    u64 argument;
};

struct driver_recovery_fingerprint {
    u32 kind;
    u32 code;
    u32 vector;
    u64 error;
    u64 rip;
    u64 address;
};

struct driver_recovery_selector {
    u16 vendor_id;
    u16 device_id;
    struct driver_recovery_fingerprint fingerprint;
};

struct driver_recovery_audit {
    u32 trigger;
    u32 outcome;
    struct driver_recovery_profile profile;
    struct driver_crash_passport passport;
};

struct driver_crash_circuit_policy {
    u32 repeat_limit;
    u32 repeat_window_ticks;
};

struct driver_domain_manifest {
    const char *name;
    // Scheduler share, or 0 for the default. Every caller builds this on the
    // stack field by field, so a new member has to be set at each site.
    u32 weight;
    u32 capabilities;
    u32 restart_policy;
    u32 max_restarts;
    u32 backoff_ticks;
    u32 image_id;
    u32 reset_policy;
    u64 argument;
};

struct driver_domain_resource {
    struct kernel_object *object;
    u32 rights;
    u32 kind;
    u32 index;
    u64 flags;
};

struct driver_domain {
    u32 id;
    u32 state;
    int pid;
    struct kernel_object *device;
    struct driver_domain_resource resources[DRIVER_DOMAIN_RESOURCE_MAX];
    u32 issued_handles[DRIVER_DOMAIN_RESOURCE_MAX];
    u32 resource_count;
    u32 bridge_index;
    u32 restart_count;
    u32 restart_deadline;
    struct driver_crash_passport last_crash;
    struct driver_crash_passport pending_crash;
    u32 crash_repeat_count;
    u32 crash_repeat_deadline;
    struct driver_crash_circuit_policy crash_policy;
    u32 stop_deadline;
    u32 stop_ack;
    u32 generation;
    char name[32];
    u32 manifest_flags;
    u32 capabilities;
    u32 restart_policy;
    u32 max_restarts;
    u32 backoff_ticks;
    u32 image_id;
    u32 reset_policy;
    u64 argument;
    u32 weight;
    struct driver_recovery_profile fallback;
    struct driver_recovery_selector fallback_selector;
    struct driver_recovery_audit recovery_audit;
    u32 recovery_profile;
    u32 fallback_enabled;
    u32 fallback_selector_enabled;
    u32 fallback_used;
    u32 fallback_triggers;
    u32 terminal_reason;
    u32 last_decision;
    u32 firmware_count;
    char firmware[DRIVER_USER_FIRMWARE_MAX][DRIVER_USER_NAME_MAX];
    u32 active;
};

struct driver_domain_status {
    u32 id;
    u32 state;
    int pid;
    u32 generation;
    u32 image_id;
    u32 capabilities;
    u64 argument;
    u32 recovery_profile;
    u32 fallback_enabled;
    u32 fallback_selector_enabled;
    struct driver_recovery_selector fallback_selector;
    struct driver_recovery_audit recovery_audit;
    u32 fallback_used;
    u32 fallback_triggers;
    u32 restart_count;
    u32 restart_deadline;
    u32 stop_deadline;
    u32 stop_ack;
    u32 crash_repeat_count;
    u32 crash_repeat_deadline;
    struct driver_crash_circuit_policy crash_policy;
    u32 terminal_reason;
    u32 last_decision;
    struct driver_crash_passport last_crash;
};

typedef int (*driver_domain_spawn_fn)(const struct driver_domain *domain);
typedef int (*driver_domain_quiesce_fn)(struct kernel_object *device);
typedef int (*driver_domain_reset_fn)(struct kernel_object *device);
typedef int (*driver_domain_revoke_fn)(int pid, u32 domain_id,
    const struct driver_domain_resource *resources, u32 count);
typedef int (*driver_domain_terminate_fn)(int pid);
typedef int (*driver_domain_release_fn)(struct driver_domain *domain);
typedef int (*driver_resource_provider_fn)(
    struct driver_domain *domain, const struct driver_user_request *request,
    struct kernel_object **objects, u32 capacity);

void driver_supervisor_init(driver_domain_spawn_fn spawn,
                            driver_domain_quiesce_fn quiesce,
                            driver_domain_reset_fn reset,
                            driver_domain_revoke_fn revoke,
                            driver_domain_terminate_fn terminate);
int driver_supervisor_set_release_backend(driver_domain_release_fn release);
struct driver_domain *driver_domain_create(
    const struct driver_domain_manifest *manifest,
    struct kernel_object *device);
int driver_user_manifest_validate(const struct driver_user_manifest *manifest);
int driver_user_manifest_matches(const struct driver_user_manifest *manifest,
                                 struct kernel_object *device);
struct driver_domain *driver_domain_create_user(
    const struct driver_user_manifest *manifest,
    struct kernel_object *device);
int driver_domain_apply_manifest(struct driver_domain *domain,
                                 const struct driver_user_manifest *manifest,
                                 driver_resource_provider_fn provider);
int driver_domain_add_resource(struct driver_domain *domain,
                               struct kernel_object *object, u32 rights);
int driver_domain_add_resource_kind(struct driver_domain *domain,
                                    struct kernel_object *object, u32 rights,
                                    u32 kind, u32 index, u64 flags);
int driver_domain_add_bridge(struct driver_domain *domain, u32 rights);
int driver_domain_set_recovery_fallback(
    struct driver_domain *domain, const struct driver_recovery_profile *profile);
int driver_recovery_selector_validate(
    const struct driver_recovery_selector *selector);
int driver_domain_set_recovery_fallback_selector(
    struct driver_domain *domain,
    const struct driver_recovery_selector *selector);
int driver_recovery_fallback_triggers_validate(u32 triggers);
int driver_domain_set_recovery_fallback_triggers(struct driver_domain *domain,
                                                  u32 triggers);
int driver_crash_circuit_policy_validate(
    const struct driver_crash_circuit_policy *policy);
int driver_domain_set_crash_circuit_policy(
    struct driver_domain *domain,
    const struct driver_crash_circuit_policy *policy);
int driver_domain_start(struct driver_domain *domain);
int driver_domain_bundle(const struct driver_domain *domain, u32 *handles,
                         u32 capacity);
int driver_domain_status(const struct driver_domain *domain,
                         struct driver_domain_status *status);
int driver_domain_bootstrap(int pid, struct driver_bootstrap_info *info);
void driver_supervisor_report_user_fault(int pid, u32 vector, u64 error,
                                         u64 rip, u64 address, u32 ticks);
void driver_supervisor_report_iommu_fault(u32 id, u16 segment, u16 source_id,
                                          u8 reason, u8 write, u64 address,
                                          u32 ticks);
void driver_supervisor_task_died(int pid, int code, u32 ticks);
void driver_supervisor_tick(u32 ticks);
int driver_domain_request_stop(struct driver_domain *domain);
int driver_domain_stop_ack(int pid);
int driver_domain_stop(struct driver_domain *domain);
int driver_domain_remove(struct driver_domain *domain);
void driver_domain_destroy(struct driver_domain *domain);
int driver_domain_admin_release(struct driver_domain *domain);
int driver_domain_quarantine(u32 id);
struct driver_domain *driver_domain_for_id(u32 id);
struct driver_domain *driver_domain_for_device(struct kernel_object *device);
struct driver_domain *driver_domain_for_pid(int pid);
u32 driver_domain_count(void);
u32 driver_domain_state(const struct driver_domain *domain);
int driver_domain_pid(const struct driver_domain *domain);
int driver_supervisor_terminating(void);
int driver_domain_firmware_allowed(const struct driver_domain *domain,
                                   const char *name);

#endif
