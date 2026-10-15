#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"
#include "adytumfs_tree.h"

// A file's blocks are reached through its extent tree, and the tree names
// content rather than locations, so what this covers is the mapping a reader
// gets and what the growth and truncation of a file costs. The interesting
// part is that the cost is not what a physical extent layout would suggest:
// every hole on the volume names one shared block of zeroes, so a sparse file
// costs nothing per hole and a second sparse file costs nothing at all.
int test_adytumfs_extent64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(512, 0);   // 64 filesystem blocks

    // A 4 KiB block is too big for a modest stack, and the test is single
    // threaded, so the scratch block is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    static struct adytumfs_cas store;
    struct adytumfs_superblock super;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    u64 na = 0;
    u64 nb = 0;
    struct adytumfs_inode a;
    struct adytumfs_inode b;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u, &na) == 0 &&
        adytumfs_inode_read(dev, &super, na, &a) == 0;

    // A fresh inode names the empty tree, and a mapping through it fails
    // rather than inventing a block.
    u64 physical = 0;
    valid = valid && a.blocks == 0 &&
        adytumfs_tree_root_empty(a.extent_root) &&
        adytumfs_inode_map(dev, &super, &store, &a, 0, &physical) != 0;

    // Growing to five blocks maps all five, and every one of them resolves to
    // the same block because they are all holes naming the same zeroes.
    u64 hole = 0;
    u64 last = 0;
    valid = valid &&
        adytumfs_inode_grow(dev, &super, &store, &a, na, 5) == 0 &&
        a.blocks == 5 && !adytumfs_tree_root_empty(a.extent_root) &&
        adytumfs_inode_map(dev, &super, &store, &a, 0, &hole) == 0 &&
        adytumfs_inode_map(dev, &super, &store, &a, 4, &last) == 0 &&
        last == hole &&
        adytumfs_inode_map(dev, &super, &store, &a, 5, &physical) != 0;

    // What a hole resolves to really is zeroes.
    valid = valid && adytumfs_block_read(dev, hole, block) == 0;
    for (u32 index = 0; valid && index < ADYTUMFS_BLOCK_SIZE; index++)
        if (block[index]) {
            valid = 0;
            break;
        }

    // The root survives a round trip through the slot, and the mapping with
    // it. Nothing about the physical layout is recorded in the inode, so
    // there is nothing else to survive.
    struct adytumfs_inode again;
    valid = valid && adytumfs_inode_write(dev, &super, na, &a) == 0 &&
        adytumfs_inode_read(dev, &super, na, &again) == 0 &&
        again.blocks == 5 &&
        adytumfs_inode_map(dev, &super, &store, &again, 3, &physical) == 0 &&
        physical == hole;

    // A second file's hole is the same block, so growing it allocates nothing
    // new. This is the property that makes a sparse file cheap and it is only
    // visible because the tree names content.
    u64 live_before = 0;
    u64 bhole = 0;
    valid = valid &&
        adytumfs_cas_count(dev, &super, &store, &live_before) == 0 &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u, &nb) == 0 &&
        adytumfs_inode_read(dev, &super, nb, &b) == 0 &&
        adytumfs_inode_grow(dev, &super, &store, &b, nb, 1) == 0 &&
        adytumfs_inode_map(dev, &super, &store, &b, 0, &bhole) == 0 &&
        bhole == hole;
    u64 live_after = 0;
    valid = valid &&
        adytumfs_cas_count(dev, &super, &store, &live_after) == 0 &&
        live_after < live_before + 3u;

    // Writing one block gives it a block of its own and leaves its neighbours
    // on the shared zeroes, which is the copy-on-write the sharing requires.
    static u8 content[ADYTUMFS_BLOCK_SIZE];
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        content[index] = (u8)(index + 7u);
    u64 own = 0;
    u64 side = 0;
    valid = valid &&
        adytumfs_inode_remap(dev, &super, &store, &a, na, 2, content) == 0 &&
        adytumfs_inode_map(dev, &super, &store, &a, 2, &own) == 0 &&
        own != hole &&
        adytumfs_inode_map(dev, &super, &store, &a, 1, &side) == 0 &&
        side == hole &&
        adytumfs_inode_map(dev, &super, &store, &a, 3, &side) == 0 &&
        side == hole &&
        adytumfs_block_read(dev, own, block) == 0 &&
        block[0] == 7u && block[ADYTUMFS_BLOCK_SIZE - 1] == 6u;

    // Truncating to three drops the tail and keeps the written block. The
    // shared zero block is not freed, because file B still names it.
    valid = valid &&
        adytumfs_inode_truncate(dev, &super, &store, &a, na, 3) == 0 &&
        a.blocks == 3 &&
        adytumfs_inode_map(dev, &super, &store, &a, 2, &physical) == 0 &&
        physical == own &&
        adytumfs_inode_map(dev, &super, &store, &a, 3, &physical) != 0 &&
        adytumfs_inode_map(dev, &super, &store, &b, 0, &side) == 0 &&
        side == hole;

    // Truncating to nothing leaves the empty tree, and a mapping through it
    // fails the way it did for a fresh inode.
    valid = valid &&
        adytumfs_inode_truncate(dev, &super, &store, &a, na, 0) == 0 &&
        a.blocks == 0 && adytumfs_tree_root_empty(a.extent_root) &&
        adytumfs_inode_map(dev, &super, &store, &a, 0, &physical) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
