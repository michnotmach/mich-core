#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"

int test_adytumfs_diriter64(void) {
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

    // A directory with four entries, one of which is then removed.
    u64 dir = 0;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, &store, ADYTUMFS_MODE_DIR | 0755u, &dir) == 0 &&
        adytumfs_dir_add(dev, &super, &store, dir, "one", 3, 21, ADYTUMFS_DTYPE_REG) == 0 &&
        adytumfs_dir_add(dev, &super, &store, dir, "two", 3, 22, ADYTUMFS_DTYPE_DIR) == 0 &&
        adytumfs_dir_add(dev, &super, &store, dir, "three", 5, 23, ADYTUMFS_DTYPE_REG) == 0 &&
        adytumfs_dir_add(dev, &super, &store, dir, "four", 4, 24, ADYTUMFS_DTYPE_REG) == 0 &&
        adytumfs_dir_remove(dev, &super, &store, dir, "two", 3) == 0;

    char name[ADYTUMFS_NAME_MAX + 1];
    u32 name_len = 0;
    u64 inode = 0;
    u8 type = 0;
    u64 cursor = 0;
    u32 count = 0;
    int saw_one = 0;
    int saw_three = 0;
    int saw_four = 0;
    int saw_two = 0;
    int result;
    while (valid && (result = adytumfs_dir_iter(dev, &super, &store, dir, &cursor, name,
                                                &name_len, &inode, &type)) == 0) {
        count++;
        if (inode == 21) saw_one = 1;
        if (inode == 22) saw_two = 1;
        if (inode == 23 && type == ADYTUMFS_DTYPE_REG) saw_three = 1;
        if (inode == 24) saw_four = 1;
    }
    valid = valid && result == 1 && count == 3 &&
        saw_one && saw_three && saw_four && !saw_two;

    // Iteration walks across multiple directory blocks.
    u64 big = 0;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, &store, ADYTUMFS_MODE_DIR | 0755u, &big) == 0;
    u8 longname[100];
    for (u32 index = 0; index < sizeof(longname); index++) longname[index] = 'q';
    for (u32 index = 0; index < 40 && valid; index++) {
        longname[0] = (u8)('a' + index);
        valid = valid && adytumfs_dir_add(dev, &super, &store, big,
            (const char *)longname, sizeof(longname), 500 + index,
            ADYTUMFS_DTYPE_REG) == 0;
    }
    cursor = 0;
    count = 0;
    while (valid && (result = adytumfs_dir_iter(dev, &super, &store, big, &cursor, name,
                                                &name_len, &inode, &type)) == 0)
        count++;
    valid = valid && result == 1 && count == 40;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
