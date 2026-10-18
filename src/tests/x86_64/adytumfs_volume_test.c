#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"

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
    // region used. Formatting also builds the tree that holds the root inode,
    // and first fit gives that leaf the first block past the index, so the
    // block after it is the first one nothing has taken.
    u64 last = super.total_blocks - 1;
    u64 root_leaf = super.index_start + super.index_blocks;
    u64 first_free = root_leaf + 1;
    valid = valid &&
        adytumfs_block_read(dev, super.block_bitmap_start, block) == 0 &&
        (block[0] & 1u) &&
        (block[super.data_start / 8] & (u8)(1u << (super.data_start % 8))) &&
        (block[last / 8] & (u8)(1u << (last % 8))) &&
        (block[root_leaf / 8] & (u8)(1u << (root_leaf % 8))) &&
        (block[first_free / 8] & (u8)(1u << (first_free % 8))) == 0;

    // The reserved region is recorded, sits inside the data area, and is
    // excluded from the free count, so nothing can hand it out twice. The one
    // block the root tree took is the only other thing the span has lost.
    valid = valid && super.index_blocks >= 2 &&
        super.index_start == super.data_start &&
        super.index_start + super.index_blocks <= super.data_end &&
        super.free_blocks + super.index_blocks + 1 ==
            super.data_end - super.data_start;

    // The root inode is a directory that owns no data yet. It is an item in
    // the metadata tree now, so reaching it goes through the root the
    // superblock names rather than a fixed offset in a table. The index cache
    // is 20 KiB, too large for a modest stack, and the test is single
    // threaded.
    static struct adytumfs_cas store;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);
    struct adytumfs_inode root;
    valid = valid &&
        adytumfs_inode_read(dev, &super, &store, ADYTUMFS_ROOT_INODE,
                            &root) == 0 &&
        (root.mode & ADYTUMFS_MODE_DIR) && root.size == 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
