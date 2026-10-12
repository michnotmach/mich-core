#ifndef DRIVER_ABI_H
#define DRIVER_ABI_H

#include "types.h"

#define DRIVER_USER_ABI_VERSION 3
#define DRIVER_USER_NAME_MAX 32
#define DRIVER_USER_MATCH_MAX 8
#define DRIVER_USER_REQUEST_MAX 16
#define DRIVER_USER_DEPENDENCY_MAX 4
#define DRIVER_USER_FIRMWARE_MAX 4
#define DRIVER_USER_IMAGE_MAX 16
#define DRIVER_BOOTSTRAP_RESOURCE_MAX 16

#define DRIVER_RESOURCE_PCI 1
#define DRIVER_RESOURCE_BAR 2
#define DRIVER_RESOURCE_DMA 3
#define DRIVER_RESOURCE_IRQ 4
#define DRIVER_RESOURCE_MSI 5
#define DRIVER_RESOURCE_MSIX_TABLE 6
#define DRIVER_RESOURCE_MSIX_IRQ 7
#define DRIVER_RESOURCE_BRIDGE 8

#define DRIVER_RESET_NONE 0
#define DRIVER_RESET_IF_SUPPORTED 1
#define DRIVER_RESET_REQUIRED 2

#define DRIVER_MANIFEST_GRACEFUL_STOP (1u << 8)
#define DRIVER_CONTROL_STOP 0xFFFFFFF0u
#define DRIVER_STOP_GRACE_TICKS 32
#define DRIVER_BOOTSTRAP_IRQ_SOURCE_MASK 0xFFFFFFFFULL
#define DRIVER_BOOTSTRAP_REQUEST_FLAGS_SHIFT 32

struct driver_user_match {
    u16 vendor_id;
    u16 device_id;
    u8 class_code;
    u8 subclass;
    u8 programming_interface;
    u8 reserved;
};

struct driver_user_request {
    u32 kind;
    u32 index;
    u32 rights;
    u32 flags;
    u64 amount;
    u64 limit;
};

struct driver_user_manifest {
    u32 abi_version;
    u32 size;
    char name[DRIVER_USER_NAME_MAX];
    u32 flags;
    u32 capabilities;
    u32 restart_policy;
    u32 max_restarts;
    u32 backoff_ticks;
    u32 priority;
    u32 image_id;
    u32 reset_policy;
    u64 argument;
    u32 match_count;
    u32 request_count;
    u32 dependency_count;
    u32 firmware_count;
    // Scheduler share, or 0 for the default. Was reserved2[0]; the word
    // after it is still required to be zero.
    u32 weight;
    u32 reserved3;
    char dependencies[DRIVER_USER_DEPENDENCY_MAX][DRIVER_USER_NAME_MAX];
    char firmware[DRIVER_USER_FIRMWARE_MAX][DRIVER_USER_NAME_MAX];
    struct driver_user_match matches[DRIVER_USER_MATCH_MAX];
    struct driver_user_request requests[DRIVER_USER_REQUEST_MAX];
};

struct driver_bootstrap_resource {
    u32 kind;
    u32 index;
    u32 handle;
    u32 rights;
    u64 length;
    u64 address;
    u64 flags;
};

struct driver_bootstrap_info {
    u32 abi_version;
    u32 size;
    u32 domain_id;
    u32 generation;
    u32 pid;
    u32 state;
    u32 manifest_flags;
    u32 restart_count;
    u32 image_id;
    u16 segment;
    u8 bus;
    u8 device;
    u8 function;
    u8 class_code;
    u8 subclass;
    u8 programming_interface;
    u16 vendor_id;
    u16 device_id;
    u32 resource_count;
    u32 reset_policy;
    char name[DRIVER_USER_NAME_MAX];
    struct driver_bootstrap_resource resources[DRIVER_BOOTSTRAP_RESOURCE_MAX];
};

typedef char driver_user_match_size_check[
    sizeof(struct driver_user_match) == 8 ? 1 : -1];
typedef char driver_user_request_size_check[
    sizeof(struct driver_user_request) == 32 ? 1 : -1];
typedef char driver_user_manifest_size_check[
    sizeof(struct driver_user_manifest) == 936 ? 1 : -1];
typedef char driver_bootstrap_resource_size_check[
    sizeof(struct driver_bootstrap_resource) == 40 ? 1 : -1];
typedef char driver_bootstrap_info_size_check[
    sizeof(struct driver_bootstrap_info) == 728 ? 1 : -1];

#endif
