#include "types.h"
#include "object.h"
#include "event.h"
#include "block.h"
#include "cache.h"
#include "adytumfs_format.h"
#include "adytumfs.h"
#include "vfs.h"

// A crash window commits a second generation through a fault the device
// injects at a chosen page of the inactive set, then reboots the volume by
// throwing the cache and the staging window. Whatever the fault did, the
// pair must mount and hold exactly one committed generation: the old one for
// every fault, the new one for a clean flip.

#define CRASH_VOLUME_BLOCKS 40
#define CRASH_DISK_SECTORS (CRASH_VOLUME_BLOCKS * ADYTUMFS_SECTORS_PER_BLOCK)

#define CRASH_FAULT_NONE 0
#define CRASH_FAULT_BITMAP 1
#define CRASH_FAULT_SUPER 2

// The image is 160 KiB and reused by every window, so it lives next to the
// probe buffers of the other adytumfs tests rather than on the stack.
static u8 crash_image[CRASH_DISK_SECTORS * BLOCK_SECTOR_SIZE];

// The plan aims at one 4 KiB page of the device. The first allow sectors of
// that page may reach the image; the rest either fail the write outright, a
// hard fault the commit sees, or report success without landing, the drive
// that acked the write and then lost power before the platter turned.
static struct {
    u32 page;
    u32 allow;
    u8 armed;
    u8 silent;
    u8 fired;
} crash_plan;

static struct {
    u32 lba;
    u8 ready;
} crash_slot_state[BLOCK_REQUEST_MAX];

static int crash_issue(struct kernel_object *queue, struct kernel_object *dma,
                       u32 slot, u32 op, u32 lba, const u8 *data,
                       u64 *token) {
    (void)queue;
    (void)dma;
    if (slot >= BLOCK_REQUEST_MAX || lba >= CRASH_DISK_SECTORS) return -1;
    if (op == BLOCK_OP_WRITE) {
        u32 page = lba - (lba % BLOCK_CACHE_SECTORS);
        u32 offset = lba - page;
        if (crash_plan.armed && crash_plan.page == page &&
            offset >= crash_plan.allow) {
            crash_plan.fired = 1;
            if (!crash_plan.silent) return -1;
        } else {
            for (u32 i = 0; i < BLOCK_SECTOR_SIZE; i++)
                crash_image[lba * BLOCK_SECTOR_SIZE + i] = data[i];
        }
    }
    crash_slot_state[slot].lba = lba;
    crash_slot_state[slot].ready = 1;
    *token = slot + 1;
    return 0;
}

static int crash_reap(struct kernel_object *queue, struct kernel_object *dma,
                      const u64 *tokens, u32 n, u32 *slot, i32 *status,
                      u8 *data) {
    (void)queue;
    (void)dma;
    (void)tokens;
    for (u32 scan = 0; scan < n && scan < BLOCK_REQUEST_MAX; scan++) {
        if (!crash_slot_state[scan].ready) continue;
        crash_slot_state[scan].ready = 0;
        *slot = scan;
        *status = 0;
        for (u32 i = 0; i < BLOCK_SECTOR_SIZE; i++)
            data[i] = crash_image[crash_slot_state[scan].lba *
                                      BLOCK_SECTOR_SIZE +
                                  i];
        return 1;
    }
    return 0;
}

static void crash_reset(void) {
    for (u32 i = 0; i < sizeof(crash_image); i++) crash_image[i] = 0;
    for (u32 slot = 0; slot < BLOCK_REQUEST_MAX; slot++) {
        crash_slot_state[slot].lba = 0;
        crash_slot_state[slot].ready = 0;
    }
    crash_plan.page = 0;
    crash_plan.allow = 0;
    crash_plan.armed = 0;
    crash_plan.silent = 0;
    crash_plan.fired = 0;
}

// The transport and queue objects are opaque to the callbacks above, so any
// retained object serves; the block device releases them when it goes.
static struct kernel_object *crash_device(void) {
    struct kernel_object *transport = event_create(EVENT_AUTO_RESET, 0);
    struct kernel_object *queue = transport ?
        event_create(EVENT_AUTO_RESET, 0) : 0;
    struct kernel_object *dma = queue ?
        event_create(EVENT_AUTO_RESET, 0) : 0;
    struct kernel_object *device = dma ?
        block_bind_transport(CRASH_DISK_SECTORS, 0, transport, queue, dma,
                             crash_issue, crash_reap, 0) : 0;
    if (dma) object_release(dma);
    if (queue) object_release(queue);
    if (transport) object_release(transport);
    return device;
}

// The inactive set of the pair, the one the next commit writes. These mirror
// the slot formulas of the format layer, which are private to it, so a layout
// change there has to move these three lines with it.
static u64 crash_inactive_super(const struct adytumfs_superblock *super) {
    return super->active_slot ? 0 : super->total_blocks - 1;
}

static u64 crash_inactive_bitmap(const struct adytumfs_superblock *super) {
    if (super->active_slot) return super->block_bitmap_start;
    return super->total_blocks - 1 - super->block_bitmap_blocks;
}

static const u8 crash_seed_payload[16] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
};

static const u8 crash_next_payload[16] = {
    0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
    0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
};

// Read one file of the rebooted volume back and compare it against the
// expected image of its content.
static int crash_file_matches(struct kernel_object *disk, const char *name,
                              const u8 *payload) {
    struct kernel_object *node = disk ? vfs_lookup(disk, name) : 0;
    struct kernel_object *file = node ? vfs_open(node) : 0;
    u8 buffer[16];
    u32 moved = 0;
    int valid = file &&
        !vfs_read(file, 0, buffer, sizeof(buffer), &moved) &&
        moved == sizeof(buffer);
    for (u32 i = 0; valid && i < sizeof(buffer); i++)
        if (buffer[i] != payload[i]) valid = 0;
    if (file) object_release(file);
    if (node) object_release(node);
    return valid ? 0 : -1;
}

// Throw the cached pages and the staging window, the state a fresh boot would
// start from, then require the pair to mount and hold exactly the expected
// generation: seed present with its content, next present only when the flip
// committed.
static int crash_reboot(struct kernel_object *root,
                        struct kernel_object *point,
                        struct kernel_object *dev, u64 generation,
                        int expect_next) {
    block_cache_drop_device((u32)dev->value);
    adytumfs_window_discard(dev);
    struct adytumfs_superblock super;
    if (adytumfs_super_read(dev, &super) || super.generation != generation)
        return -1;
    if (vfs_mount_adytumfs(point, dev)) return -1;
    struct kernel_object *disk = vfs_lookup(root, "crash");
    int valid = disk && !crash_file_matches(disk, "seed", crash_seed_payload);
    if (expect_next) {
        valid = valid &&
            !crash_file_matches(disk, "next", crash_next_payload);
    } else {
        struct kernel_object *stale = disk ? vfs_lookup(disk, "next") : 0;
        valid = valid && !stale;
        if (stale) object_release(stale);
    }
    if (disk) object_release(disk);
    // The reboot mount has to come down even when the content checks above
    // failed, or the window leaks the mount into the next one.
    int unmounted = !vfs_unmount(point);
    return valid && unmounted ? 0 : -1;
}

// Build the seed generation, commit a second one through the armed fault,
// then reboot and check which generation survived. kind selects the page the
// fault lives in; allow is the sector count of that page the device writes
// before the fault; silent turns the fault into an acknowledged tear.
static int crash_window(struct kernel_object *root, u32 kind, u32 allow,
                        u8 silent, u64 generation, int expect_next) {
    crash_reset();
    struct kernel_object *dev = crash_device();
    struct kernel_object *point = root ?
        vfs_create(root, "crash", VFS_NODE_DIRECTORY) : 0;
    int ok = dev && point && !adytumfs_format(dev) &&
        !vfs_mount_adytumfs(point, dev);
    struct kernel_object *disk = ok ? vfs_lookup(root, "crash") : 0;
    struct kernel_object *seed = disk ?
        vfs_create_mode(disk, "seed", VFS_NODE_REGULAR, 0600) : 0;
    struct kernel_object *seed_file = seed ? vfs_open(seed) : 0;
    u32 moved = 0;
    ok = ok && seed && seed_file &&
        !vfs_write(seed_file, 0, crash_seed_payload,
                   sizeof(crash_seed_payload), &moved) &&
        moved == sizeof(crash_seed_payload);
    if (seed_file) object_release(seed_file);
    if (seed) object_release(seed);
    if (disk) object_release(disk);
    ok = ok && !vfs_unmount(point);
    struct adytumfs_superblock super;
    ok = ok && !adytumfs_super_read(dev, &super) && super.generation == 2;
    if (ok && kind != CRASH_FAULT_NONE) {
        u64 block = kind == CRASH_FAULT_BITMAP ?
            crash_inactive_bitmap(&super) : crash_inactive_super(&super);
        crash_plan.page = (u32)(block * ADYTUMFS_SECTORS_PER_BLOCK);
        crash_plan.allow = allow;
        crash_plan.armed = 1;
        crash_plan.silent = silent;
    }
    ok = ok && !vfs_mount_adytumfs(point, dev);
    disk = ok ? vfs_lookup(root, "crash") : 0;
    struct kernel_object *next = disk ?
        vfs_create_mode(disk, "next", VFS_NODE_REGULAR, 0600) : 0;
    struct kernel_object *next_file = next ? vfs_open(next) : 0;
    moved = 0;
    ok = ok && next && next_file &&
        !vfs_write(next_file, 0, crash_next_payload,
                   sizeof(crash_next_payload), &moved) &&
        moved == sizeof(crash_next_payload);
    if (next_file) object_release(next_file);
    if (next) object_release(next);
    if (disk) object_release(disk);
    ok = ok && !vfs_unmount(point);
    if (ok && kind != CRASH_FAULT_NONE) ok = ok && crash_plan.fired;
    ok = ok && !crash_reboot(root, point, dev, generation, expect_next);
    if (point) object_release(point);
    if (root) vfs_unlink(root, "crash");
    if (dev) object_release(dev);
    return ok ? 0 : -1;
}

int test_adytumfs_crash64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    int valid = root != 0;

    // A clean flip commits the new generation.
    valid = valid && !crash_window(root, CRASH_FAULT_NONE, 0, 0, 3, 1);
    // A staged bitmap block that never lands fails the commit before the
    // flip, so the old generation survives.
    valid = valid && !crash_window(root, CRASH_FAULT_BITMAP, 0, 0, 2, 0);
    // A superblock torn after its first sector fails the flip itself.
    valid = valid && !crash_window(root, CRASH_FAULT_SUPER, 1, 0, 2, 0);
    // A tear the device acknowledges without writing is the same on the
    // platter, only the commit cannot tell.
    valid = valid && !crash_window(root, CRASH_FAULT_SUPER, 1, 1, 2, 0);

    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
