#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"

int test_adytumfs_inode64(void) {
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

    // The root inode reads back through the inode-table path as a directory.
    struct adytumfs_inode root;
    valid = valid &&
        adytumfs_inode_read(dev, &super, ADYTUMFS_ROOT_INODE, &root) == 0 &&
        (root.mode & ADYTUMFS_MODE_DIR);

    u64 free0 = super.free_inodes;

    // Allocate a regular-file inode, then round-trip its fields.
    u64 number = 0;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u, &number) == 0 &&
        number >= 1 && number < super.inode_count &&
        super.free_inodes == free0 - 1;
    struct adytumfs_inode file;
    valid = valid && adytumfs_inode_read(dev, &super, number, &file) == 0 &&
        (file.mode & ADYTUMFS_MODE_REG) && file.links == 1 &&
        file.generation >= 1;
    u64 generation = file.generation;

    // The extent root is the whole of what an inode now records about a
    // file's blocks, so the round trip that used to cover the extent array
    // covers it. Every byte matters: a root that came back wrong would name a
    // different tree, and the checksum over the slot is what says it did not.
    file.size = 12345;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        file.extent_root[index] = (u8)(index * 3u + 1u);
    struct adytumfs_inode again;
    int root_same = 1;
    valid = valid && adytumfs_inode_write(dev, &super, number, &file) == 0 &&
        adytumfs_inode_read(dev, &super, number, &again) == 0 &&
        again.size == 12345;
    for (u32 index = 0; valid && index < ADYTUMFS_HASH_SIZE; index++)
        if (again.extent_root[index] != file.extent_root[index]) {
            root_same = 0;
            break;
        }
    valid = valid && root_same;

    // The nanosecond halves of the timestamps round-trip through the slot
    // copy the seconds always did.
    file.atime_nsec = 123456789u;
    file.mtime_nsec = 987654321u;
    file.ctime_nsec = 500000000u;
    struct adytumfs_inode timed;
    valid = valid && adytumfs_inode_write(dev, &super, number, &file) == 0 &&
        adytumfs_inode_read(dev, &super, number, &timed) == 0 &&
        timed.atime_nsec == 123456789u &&
        timed.mtime_nsec == 987654321u &&
        timed.ctime_nsec == 500000000u;

    // Freeing returns the slot; the next allocation reuses it with a higher
    // generation.
    u64 reused = 0;
    struct adytumfs_inode fresh;
    valid = valid && adytumfs_inode_free(dev, &super, number) == 0 &&
        super.free_inodes == free0 &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0600u, &reused) == 0 &&
        reused == number &&
        adytumfs_inode_read(dev, &super, reused, &fresh) == 0 &&
        fresh.generation == generation + 1;

    // A flipped byte in an in-use inode slot is caught by its checksum. The
    // commit lands the window's staged table first, so the flip targets the
    // live generation's copy instead of being masked by the staging.
    valid = valid && adytumfs_commit(dev, &super) == 0;
    u64 table = adytumfs_table_block(
        &super, (u32)(reused / ADYTUMFS_INODES_PER_BLOCK));
    u32 slot = (u32)(reused % ADYTUMFS_INODES_PER_BLOCK) * ADYTUMFS_INODE_SIZE;
    struct adytumfs_inode corrupt;
    valid = valid && adytumfs_block_read(dev, table, block) == 0;
    block[slot + 16] ^= 0x20u;
    valid = valid && adytumfs_block_write(dev, table, block) == 0 &&
        adytumfs_inode_read(dev, &super, reused, &corrupt) != 0;

    // Out-of-range inode numbers are rejected.
    valid = valid && adytumfs_inode_read(dev, &super, 0, &corrupt) != 0 &&
        adytumfs_inode_read(dev, &super, super.inode_count, &corrupt) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
