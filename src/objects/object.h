#ifndef OBJECT_H
#define OBJECT_H

#include "types.h"

// The object table grows a slab at a time out of the page allocator, so the
// bound is a ceiling on memory rather than a fixed table. An object's address
// is its identity for every holder, so a slab that has ever backed one can
// never move or be returned; the ceiling is what keeps a runaway create loop
// from taking the whole machine's pages.
#define OBJECT_SLAB_SLOTS 127u
#define OBJECT_SLAB_MAX 64u
#define KOBJECT_MAX (OBJECT_SLAB_MAX * OBJECT_SLAB_SLOTS)
#define KHANDLE_MAX 32

#define KOBJECT_NONE 0
#define KOBJECT_EVENT 1
#define KOBJECT_IRQ 2
#define KOBJECT_IOPORT 3
#define KOBJECT_MMIO 4
#define KOBJECT_DMA 5
#define KOBJECT_PCI 6
#define KOBJECT_FILE 7
#define KOBJECT_ENDPOINT 8
#define KOBJECT_MSIX_TABLE 9
#define KOBJECT_PAGE 10
#define KOBJECT_SHARED_MEMORY 11
#define KOBJECT_SG_LIST 12
#define KOBJECT_RING 13
#define KOBJECT_COMPLETION 14
#define KOBJECT_TIMER 15
#define KOBJECT_PACKET_POOL 16
#define KOBJECT_VNIC 17
#define KOBJECT_SOCKET 18
#define KOBJECT_NET_INTERFACE 19
#define KOBJECT_VNODE 22
#define KOBJECT_DIRECTORY 23
#define KOBJECT_MOUNT 24
#define KOBJECT_BLOCK 25
#define KOBJECT_NVME_DEVICE 26

#define KRIGHT_READ (1u << 0)
#define KRIGHT_WRITE (1u << 1)
#define KRIGHT_WAIT (1u << 2)
#define KRIGHT_SIGNAL (1u << 3)
#define KRIGHT_MAP (1u << 4)
#define KRIGHT_CONTROL (1u << 5)
#define KRIGHT_TRANSFER (1u << 6)
#define KRIGHT_ALL 0x7Fu

struct task;
struct kernel_object;

typedef void (*object_destroy_fn)(struct kernel_object *object);

struct kernel_object {
    u32 type;
    u32 references;
    u64 value;
    object_destroy_fn destroy;
    u32 active;
};

void object_init(void);
struct kernel_object *object_create(u32 type, u64 value,
                                    object_destroy_fn destroy);
int object_retain(struct kernel_object *object);
void object_release(struct kernel_object *object);
u32 handle_open(struct task *task, struct kernel_object *object, u32 rights);
struct kernel_object *handle_get(struct task *task, u32 handle,
                                 u32 required_rights, u32 required_type);
int handle_close(struct task *task, u32 handle);
u32 handle_duplicate(struct task *source, struct task *target,
                     u32 handle, u32 rights);
u32 handle_revoke_object(struct kernel_object *object);
void handle_close_all(struct task *task);
u32 object_active_count(void);
u32 handle_active_count(void);
u32 handle_task_count(struct task *task);

#endif
