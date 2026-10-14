#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"

int test_adytumfs_volume64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(512, 0);   // 64 filesystem blocks
    int valid = dev && adytumfs_make(dev) == 0;

    // A 4 KiB block is too big for a modest stack, and the test is single
    // threaded, so the scratch block is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    valid = valid && adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0 &&
        adytumfs_super_valid(&super, 64) == 0 &&
        super.total_blocks == 64 &&
        super.block_size == ADYTUMFS_BLOCK_SIZE &&
        super.root_inode == ADYTUMFS_ROOT_INODE;

    // The backup superblock in the last block mirrors the primary.
    struct adytumfs_superblock backup;
    valid = valid &&
        adytumfs_block_read(dev, super.total_blocks - 1, block) == 0 &&
        adytumfs_super_unpack(&backup, block) == 0 &&
        backup.total_blocks == super.total_blocks &&
        backup.data_start == super.data_start;

    // The bitmap marks block 0, the backup block, and the reserved index
    // region used, and leaves the first block past the index free.
    u64 last = super.total_blocks - 1;
    u64 first_free = super.index_start + super.index_blocks;
    valid = valid &&
        adytumfs_block_read(dev, super.block_bitmap_start, block) == 0 &&
        (block[0] & 1u) &&
        (block[super.data_start / 8] & (u8)(1u << (super.data_start % 8))) &&
        (block[last / 8] & (u8)(1u << (last % 8))) &&
        (block[first_free / 8] & (u8)(1u << (first_free % 8))) == 0;

    // The reserved region is recorded, sits inside the data area, and is
    // excluded from the free count, so nothing can hand it out twice.
    valid = valid && super.index_blocks >= 2 &&
        super.index_start == super.data_start &&
        super.index_start + super.index_blocks <= super.data_checksum_region &&
        super.free_blocks + super.index_blocks ==
            super.data_checksum_region - super.data_start;

    // The root inode is a directory that owns no data yet.
    struct adytumfs_inode root;
    valid = valid &&
        adytumfs_block_read(dev, super.inode_table_start, block) == 0 &&
        adytumfs_inode_unpack(&root,
            block + ADYTUMFS_ROOT_INODE * ADYTUMFS_INODE_SIZE) == 0 &&
        (root.mode & ADYTUMFS_MODE_DIR) && root.size == 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
