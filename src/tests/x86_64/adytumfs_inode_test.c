#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"
#include "adytumfs_item.h"

int test_adytumfs_inode64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(512, 0);   // 64 filesystem blocks

    // A 4 KiB block is too big for a modest stack, and the test is single
    // threaded, so the scratch block is static. The index cache is the same
    // story at 20 KiB.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    static struct adytumfs_cas store;
    struct adytumfs_superblock super;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    // The root inode reads back through the item tree as a directory.
    struct adytumfs_inode root;
    valid = valid &&
        adytumfs_inode_read(dev, &super, &store, ADYTUMFS_ROOT_INODE,
                            &root) == 0 &&
        (root.mode & ADYTUMFS_MODE_DIR);

    u64 live0 = super.live_inodes;
    u64 next0 = super.inode_next;

    // Allocate a regular-file inode, then round-trip its fields.
    u64 number = 0;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, &store, ADYTUMFS_MODE_REG | 0644u,
                             &number) == 0 &&
        number == next0 && super.inode_next == next0 + 1 &&
        super.live_inodes == live0 + 1;
    struct adytumfs_inode file;
    valid = valid &&
        adytumfs_inode_read(dev, &super, &store, number, &file) == 0 &&
        (file.mode & ADYTUMFS_MODE_REG) && file.links == 1 &&
        file.generation >= 1;

    // The extent root is the whole of what an inode now records about a
    // file's blocks, so the round trip that used to cover the extent array
    // covers it. Every byte matters: a root that came back wrong would name a
    // different tree, and the checksum over the slot is what says it did not.
    file.size = 12345;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        file.extent_root[index] = (u8)(index * 3u + 1u);
    struct adytumfs_inode again;
    int root_same = 1;
    valid = valid &&
        adytumfs_inode_write(dev, &super, &store, number, &file) == 0 &&
        adytumfs_inode_read(dev, &super, &store, number, &again) == 0 &&
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
    valid = valid &&
        adytumfs_inode_write(dev, &super, &store, number, &file) == 0 &&
        adytumfs_inode_read(dev, &super, &store, number, &timed) == 0 &&
        timed.atime_nsec == 123456789u &&
        timed.mtime_nsec == 987654321u &&
        timed.ctime_nsec == 500000000u;

    // Freeing takes the item out of the tree, so the number stops resolving
    // and the live count goes back. The next allocation gets a fresh number
    // rather than this one: a number is never reused, which is what keeps a
    // handle that outlived its file from resolving into a different one.
    u64 reused = 0;
    struct adytumfs_inode fresh;
    valid = valid &&
        adytumfs_inode_free(dev, &super, &store, number) == 0 &&
        super.live_inodes == live0 &&
        adytumfs_inode_read(dev, &super, &store, number, &fresh) != 0 &&
        adytumfs_inode_free(dev, &super, &store, number) != 0 &&
        adytumfs_inode_alloc(dev, &super, &store, ADYTUMFS_MODE_REG | 0600u,
                             &reused) == 0 &&
        reused == number + 1 &&
        adytumfs_inode_read(dev, &super, &store, reused, &fresh) == 0 &&
        fresh.generation == reused;

    // A flipped byte inside the item is caught by the hash the parent node
    // promises, which is the same check the read path makes. The commit lands
    // the metadata first, so the flip targets the live generation's copy
    // instead of being masked by the staging.
    valid = valid && adytumfs_commit(dev, &super, &store) == 0;
    struct adytumfs_item_key key = {0};
    key.objectid = reused;
    key.type = ADYTUMFS_ITEM_INODE;
    u64 node = 0;
    valid = valid &&
        adytumfs_cas_lookup(dev, &super, &store, super.inode_root,
                            &node) == 0 &&
        adytumfs_block_read(dev, node, block) == 0;
    const u8 *item = 0;
    struct adytumfs_item_key found = {0};
    u32 item_size = 0;
    int placed = adytumfs_item_node_search(block, &key);
    valid = valid && placed >= 0 &&
        adytumfs_item_leaf_get(block, (u32)placed, &found, &item,
                               &item_size) == 0;
    struct adytumfs_inode corrupt;
    if (valid) {
        u32 offset = (u32)(item - block);
        block[offset + 16] ^= 0x20u;
        valid = adytumfs_block_write(dev, node, block) == 0 &&
            adytumfs_inode_read(dev, &super, &store, reused, &corrupt) != 0;
    }

    // A number the volume never handed out is not an inode.
    valid = valid &&
        adytumfs_inode_read(dev, &super, &store, 0, &corrupt) != 0 &&
        adytumfs_inode_read(dev, &super, &store, super.inode_next,
                            &corrupt) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
