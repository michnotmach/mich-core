#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"

static int bitmap_used(const u8 *bitmap, u64 block) {
    return (bitmap[block / 8] >> (block % 8)) & 1;
}

int test_adytumfs_extent64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(512, 0);   // 64 filesystem blocks

    // A 4 KiB block is too big for a modest stack, and the test is single
    // threaded, so the scratch block is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0;

    // The index region is reserved at the front of the data area, so the
    // first extent a grow can take starts past it.
    u64 data = super.data_start + super.index_blocks;
    u64 na = 0;
    u64 nb = 0;
    struct adytumfs_inode a;
    struct adytumfs_inode b;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u, &na) == 0 &&
        adytumfs_inode_read(dev, &super, na, &a) == 0;

    // Grow to five blocks: one contiguous extent at the start of the data area.
    u64 physical = 0;
    valid = valid && adytumfs_inode_grow(dev, &super, &a, 5) == 0 &&
        a.blocks == 5 && a.direct[0].start_block == data &&
        a.direct[0].length == 5 && a.direct[1].length == 0 &&
        adytumfs_inode_map(&a, 0, &physical) == 0 && physical == data &&
        adytumfs_inode_map(&a, 4, &physical) == 0 && physical == data + 4 &&
        adytumfs_inode_map(&a, 5, &physical) != 0;

    // Persist and read it back unchanged.
    struct adytumfs_inode again;
    valid = valid && adytumfs_inode_write(dev, &super, na, &a) == 0 &&
        adytumfs_inode_read(dev, &super, na, &again) == 0 &&
        again.blocks == 5 && again.direct[0].length == 5;

    // A second file takes the next block, so the next grow of A cannot coalesce
    // and lands in a fresh extent.
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u, &nb) == 0 &&
        adytumfs_inode_read(dev, &super, nb, &b) == 0 &&
        adytumfs_inode_grow(dev, &super, &b, 1) == 0 &&
        b.direct[0].start_block == data + 5;

    valid = valid && adytumfs_inode_grow(dev, &super, &a, 8) == 0 &&
        a.blocks == 8 && a.direct[1].start_block == data + 6 &&
        a.direct[1].length == 3 &&
        adytumfs_inode_map(&a, 5, &physical) == 0 && physical == data + 6 &&
        adytumfs_inode_map(&a, 7, &physical) == 0 && physical == data + 8 &&
        adytumfs_inode_map(&a, 8, &physical) != 0;

    // Truncate to six: the second extent keeps one block, two are reclaimed.
    // The commit lands the window before the bitmap is read back, and the
    // live generation's copy is the one the flip named.
    u64 free_before = super.free_blocks;
    valid = valid && adytumfs_inode_truncate(dev, &super, &a, 6) == 0 &&
        a.blocks == 6 && a.direct[1].length == 1 &&
        super.free_blocks == free_before + 2 &&
        adytumfs_inode_map(&a, 5, &physical) == 0 && physical == data + 6 &&
        adytumfs_inode_map(&a, 6, &physical) != 0 &&
        adytumfs_commit(dev, &super) == 0;
    // The live generation's bitmap is the copy the flip named.
    valid = valid && adytumfs_block_read(
                dev, adytumfs_bitmap_block(&super, 0), block) == 0 &&
        bitmap_used(block, data + 6) && !bitmap_used(block, data + 7) &&
        !bitmap_used(block, data + 8);

    // Truncate to zero frees everything the file still held. The commit
    // ping-pongs the active set back to the primary, so the live bitmap
    // location moves again.
    valid = valid && adytumfs_inode_truncate(dev, &super, &a, 0) == 0 &&
        a.blocks == 0 && a.direct[0].length == 0 &&
        adytumfs_commit(dev, &super) == 0;
    valid = valid && adytumfs_block_read(
                dev, adytumfs_bitmap_block(&super, 0), block) == 0 &&
        !bitmap_used(block, data) && !bitmap_used(block, data + 6);

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
