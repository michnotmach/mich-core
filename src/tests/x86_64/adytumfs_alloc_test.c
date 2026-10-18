#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"

static int bitmap_used(const u8 *bitmap, u64 block) {
    return (bitmap[block / 8] >> (block % 8)) & 1;
}

int test_adytumfs_alloc64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(512, 0);   // 64 filesystem blocks

    // A 4 KiB block is too big for a modest stack, and the test is single
    // threaded, so the scratch block is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    // The allocator under test never touches the tree, but a commit now
    // lands whatever inodes the store is holding, so it needs one to be
    // given even when it is empty.
    static struct adytumfs_cas store;
    struct adytumfs_superblock super;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    u64 free0 = super.free_blocks;
    u64 first = 0;
    u64 second = 0;
    u64 moved = 0;
    u64 reused = 0;

    // First fit starts past the reserved index region and past the one block
    // formatting took for the tree that holds the root inode, and the second
    // run lands immediately after the first. The edits stage in the open
    // window, so the counters move in memory while the device bitmap waits
    // for the commit.
    valid = valid && adytumfs_alloc_run(dev, &super, 3, &first) == 0 &&
        first == super.data_start + super.index_blocks + 1 &&
        adytumfs_alloc_run(dev, &super, 2, &second) == 0 &&
        second == first + 3 &&
        super.free_blocks == free0 - 5;

    // The commit lands the staged bitmap in the inactive set and flips the
    // generation, so the bits read back from the tail copy the flip named.
    valid = valid && adytumfs_commit(dev, &super, &store) == 0 &&
        super.active_slot == 1 && super.generation == 2 &&
        adytumfs_block_read(dev, super.total_blocks - 1 -
                            super.block_bitmap_blocks, block) == 0 &&
        bitmap_used(block, first) && bitmap_used(block, first + 2) &&
        bitmap_used(block, second) && bitmap_used(block, second + 1) &&
        !bitmap_used(block, second + 2);

    // A free inside the window does not hand the blocks back: the committed
    // generation still references their old images, so the next run moves
    // past the hole until the commit lands the free and the hole returns.
    valid = valid && adytumfs_free_run(dev, &super, first, 3) == 0 &&
        super.free_blocks == free0 - 2 &&
        adytumfs_alloc_run(dev, &super, 3, &moved) == 0 &&
        moved == second + 2 &&
        adytumfs_commit(dev, &super, &store) == 0 &&
        adytumfs_alloc_run(dev, &super, 3, &reused) == 0 &&
        reused == first && super.free_blocks == free0 - 8;

    // A run larger than the free space fails, and metadata blocks cannot be
    // freed.
    u64 overflow = 0;
    valid = valid &&
        adytumfs_alloc_run(dev, &super, super.total_blocks, &overflow) != 0 &&
        adytumfs_free_run(dev, &super, 0, 1) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
