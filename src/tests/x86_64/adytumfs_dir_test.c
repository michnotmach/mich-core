#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"

int test_adytumfs_dir64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(512, 0);   // 64 filesystem blocks

    // A 4 KiB block is too big for a modest stack, and the test is single
    // threaded, so the scratch block is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    // The content store every extent tree resolves through. A test that
    // touches a file's blocks needs one, exactly as a mount does.
    static struct adytumfs_cas store;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    u64 root = ADYTUMFS_ROOT_INODE;
    u64 got = 0;

    // Add three names to the empty root directory and look them up; a missing
    // name is reported as not found.
    valid = valid &&
        adytumfs_dir_add(dev, &super, &store, root, "alpha", 5, 11, ADYTUMFS_DTYPE_REG) == 0 &&
        adytumfs_dir_add(dev, &super, &store, root, "beta", 4, 12, ADYTUMFS_DTYPE_REG) == 0 &&
        adytumfs_dir_add(dev, &super, &store, root, "gamma", 5, 13, ADYTUMFS_DTYPE_DIR) == 0 &&
        adytumfs_dir_lookup(dev, &super, &store, root, "alpha", 5, &got) == 0 && got == 11 &&
        adytumfs_dir_lookup(dev, &super, &store, root, "beta", 4, &got) == 0 && got == 12 &&
        adytumfs_dir_lookup(dev, &super, &store, root, "gamma", 5, &got) == 0 && got == 13 &&
        adytumfs_dir_lookup(dev, &super, &store, root, "delta", 5, &got) != 0;

    // Duplicate names are rejected.
    valid = valid &&
        adytumfs_dir_add(dev, &super, &store, root, "alpha", 5, 99, ADYTUMFS_DTYPE_REG) != 0;

    // Remove then re-add reuses the freed record.
    valid = valid &&
        adytumfs_dir_remove(dev, &super, &store, root, "beta", 4) == 0 &&
        adytumfs_dir_lookup(dev, &super, &store, root, "beta", 4, &got) != 0 &&
        adytumfs_dir_lookup(dev, &super, &store, root, "alpha", 5, &got) == 0 && got == 11 &&
        adytumfs_dir_add(dev, &super, &store, root, "beta", 4, 60, ADYTUMFS_DTYPE_REG) == 0 &&
        adytumfs_dir_lookup(dev, &super, &store, root, "beta", 4, &got) == 0 && got == 60;

    // A fresh directory grows into a second block once entries overflow one.
    u64 dirnum = 0;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_DIR | 0755u, &dirnum) == 0;
    u8 longname[100];
    for (u32 index = 0; index < sizeof(longname); index++) longname[index] = 'z';
    for (u32 index = 0; index < 40 && valid; index++) {
        longname[0] = (u8)('a' + index);
        valid = valid && adytumfs_dir_add(dev, &super, &store, dirnum,
            (const char *)longname, sizeof(longname), 1000 + index,
            ADYTUMFS_DTYPE_REG) == 0;
    }
    struct adytumfs_inode grown;
    longname[0] = (u8)('a' + 20);
    valid = valid && adytumfs_inode_read(dev, &super, dirnum, &grown) == 0 &&
        grown.blocks >= 2 &&
        adytumfs_dir_lookup(dev, &super, &store, dirnum, (const char *)longname,
                            sizeof(longname), &got) == 0 && got == 1020;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
