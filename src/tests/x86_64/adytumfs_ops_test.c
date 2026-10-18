#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"

int test_adytumfs_ops64(void) {
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

    u64 root = super.root_inode;
    u64 etc = 0;
    u64 readme = 0;
    u64 config = 0;
    u64 got = 0;

    // Create a directory and a file under the root, then resolve them by path.
    valid = valid &&
        adytumfs_create_at(dev, &super, &store, root, "etc", 3, ADYTUMFS_MODE_DIR | 0755u,
                           &etc) == 0 &&
        adytumfs_create_at(dev, &super, &store, root, "readme", 6,
                           ADYTUMFS_MODE_REG | 0644u, &readme) == 0 &&
        adytumfs_path_resolve(dev, &super, &store, "/etc", &got) == 0 && got == etc &&
        adytumfs_path_resolve(dev, &super, &store, "/readme", &got) == 0 &&
        got == readme &&
        adytumfs_path_resolve(dev, &super, &store, "/", &got) == 0 && got == root &&
        adytumfs_path_resolve(dev, &super, &store, "/nope", &got) != 0;

    // Ownership and times are stamped at birth: the fresh inodes carry the
    // alloc stamp, a directory reports its two names, and the root carries
    // the format stamp.
    struct adytumfs_inode born;
    struct adytumfs_inode dir_born;
    struct adytumfs_inode root_born;
    valid = valid &&
        adytumfs_inode_read(dev, &super, &store, root, &root_born) == 0 &&
        root_born.atime && root_born.atime == root_born.mtime &&
        root_born.mtime == root_born.ctime && root_born.links == 2 &&
        adytumfs_inode_read(dev, &super, &store, readme, &born) == 0 &&
        born.atime && born.atime == born.mtime && born.mtime == born.ctime &&
        born.links == 1 && born.uid == 0 && born.gid == 0 &&
        adytumfs_inode_read(dev, &super, &store, etc, &dir_born) == 0 &&
        dir_born.links == 2;

    // Duplicate names are refused.
    u64 duplicate = 0;
    valid = valid &&
        adytumfs_create_at(dev, &super, &store, root, "readme", 6,
                           ADYTUMFS_MODE_REG | 0644u, &duplicate) != 0;

    // A nested file resolves through its parent directory.
    valid = valid &&
        adytumfs_create_at(dev, &super, &store, etc, "config", 6,
                           ADYTUMFS_MODE_REG | 0644u, &config) == 0 &&
        adytumfs_path_resolve(dev, &super, &store, "/etc/config", &got) == 0 &&
        got == config;

    // Create, write, resolve, read back: the pieces work together.
    u64 moved = 0;
    u8 window[2];
    valid = valid &&
        adytumfs_file_write(dev, &super, &store, readme, 0, "hi", 2, &moved) == 0 &&
        moved == 2 &&
        adytumfs_path_resolve(dev, &super, &store, "/readme", &got) == 0 &&
        adytumfs_file_read(dev, &super, &store, got, 0, window, 2, &moved) == 0 &&
        moved == 2 && window[0] == 'h' && window[1] == 'i';

    // Unlink the file; the path stops resolving and the sibling survives.
    valid = valid &&
        adytumfs_unlink_at(dev, &super, &store, root, "readme", 6) == 0 &&
        adytumfs_path_resolve(dev, &super, &store, "/readme", &got) != 0 &&
        adytumfs_path_resolve(dev, &super, &store, "/etc/config", &got) == 0 &&
        // Unlinking a directory through this path is refused.
        adytumfs_unlink_at(dev, &super, &store, root, "etc", 3) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
