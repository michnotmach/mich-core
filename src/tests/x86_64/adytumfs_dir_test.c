#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"
#include "adytumfs_item.h"

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
        adytumfs_inode_alloc(dev, &super, &store, ADYTUMFS_MODE_DIR | 0755u, &dirnum) == 0;
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
    valid = valid && adytumfs_inode_read(dev, &super, &store, dirnum, &grown) == 0 &&
        grown.blocks >= 2 &&
        adytumfs_dir_lookup(dev, &super, &store, dirnum, (const char *)longname,
                            sizeof(longname), &got) == 0 && got == 1020;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

// Directory entries as items in the item tree. The key is the directory and
// the hash of the name, and the key is fixed width, so the interesting cases
// are the ones about a bucket: two names keyed alike, a bucket that does not
// hold the name it was reached by, and a bucket that has reached the cap.
int test_adytumfs_diritem64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(512, 0);
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    static struct adytumfs_cas store;
    struct adytumfs_superblock super;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    // A bucket is a list that describes itself, so the walk has to stop where
    // the bytes say and not where a count says. Two entries, the second found
    // by name rather than by position.
    static u8 pair[2 * (ADYTUMFS_DIR_HEADER + 3u)];
    u32 at = 0;
    u64 inode = 0;
    u8 kind = 0;
    u32 length = 0;
    valid = valid &&
        adytumfs_dirent_pack(pair, (u32)sizeof pair, 21, ADYTUMFS_DTYPE_REG,
                             "one", 3) == 0 &&
        adytumfs_dirent_pack(pair + ADYTUMFS_DIR_HEADER + 3u,
                             (u32)sizeof pair - ADYTUMFS_DIR_HEADER - 3u, 22,
                             ADYTUMFS_DTYPE_DIR, "two", 3) == 0 &&
        adytumfs_dirent_find(pair, (u32)sizeof pair, "two", 3, &at) == 0 &&
        at == ADYTUMFS_DIR_HEADER + 3u &&
        adytumfs_dirent_read(pair, (u32)sizeof pair, at, &inode, &kind,
                             &length) == 0 &&
        inode == 22 && kind == ADYTUMFS_DTYPE_DIR && length == 3u &&
        adytumfs_dirent_find(pair, (u32)sizeof pair, "six", 3, &at) != 0;

    // A name a directory does not hold is not found, and the root starts
    // holding nothing.
    static u8 root[ADYTUMFS_HASH_SIZE];
    static u8 next[ADYTUMFS_HASH_SIZE];
    u64 dir = ADYTUMFS_ROOT_INODE;
    valid = valid &&
        adytumfs_dir_item_find(dev, &super, &store, root, dir, "alpha", 5,
                               &inode, &kind) != 0 &&
        adytumfs_dir_item_add(dev, &super, &store, root, dir, "alpha", 5, 11,
                              ADYTUMFS_DTYPE_REG, next) == 0 &&
        adytumfs_dir_item_find(dev, &super, &store, next, dir, "alpha", 5,
                               &inode, &kind) == 0 &&
        inode == 11 && kind == ADYTUMFS_DTYPE_REG;

    // The root moved, and the old one still resolves: copy on write leaves the
    // generation the superblock names readable until the flip.
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        root[index] = next[index];
    // Each add takes the root the one before it produced. Both taken from the
    // same root would leave only the second, because copy on write hands back a
    // new root rather than editing the one it was given.
    valid = valid &&
        adytumfs_dir_item_add(dev, &super, &store, root, dir, "beta", 4, 12,
                              ADYTUMFS_DTYPE_DIR, next) == 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        root[index] = next[index];
    valid = valid &&
        adytumfs_dir_item_add(dev, &super, &store, root, dir, "gamma", 5, 13,
                              ADYTUMFS_DTYPE_REG, next) == 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        root[index] = next[index];
    valid = valid &&
        adytumfs_dir_item_find(dev, &super, &store, root, dir, "beta", 4,
                               &inode, &kind) == 0 &&
        inode == 12 && kind == ADYTUMFS_DTYPE_DIR &&
        adytumfs_dir_item_find(dev, &super, &store, root, dir, "gamma", 5,
                               &inode, &kind) == 0 &&
        inode == 13;

    // A second name for one directory is refused here. Whether a repeated name
    // replaces or fails belongs to the layer above, and deciding it in the
    // bucket would leave that layer unable to express either.
    valid = valid &&
        adytumfs_dir_item_add(dev, &super, &store, root, dir, "alpha", 5, 99,
                              ADYTUMFS_DTYPE_REG, next) != 0;

    // Removing one name leaves the rest reachable, and removing the last name
    // in a directory leaves the bucket gone rather than stored empty.
    valid = valid &&
        adytumfs_dir_item_remove(dev, &super, &store, root, dir, "beta", 4,
                                 next) == 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        root[index] = next[index];
    valid = valid &&
        adytumfs_dir_item_find(dev, &super, &store, root, dir, "beta", 4,
                               &inode, &kind) != 0 &&
        adytumfs_dir_item_find(dev, &super, &store, root, dir, "alpha", 5,
                               &inode, &kind) == 0 &&
        adytumfs_dir_item_remove(dev, &super, &store, root, dir, "beta", 4,
                                 next) != 0;

    // A bucket reached by a key that does not name the wanted bytes is what a
    // hash collision looks like, and two names that hash alike cannot be made
    // to order. Taking "alpha" out and publishing a bucket under the key it
    // hashed to, holding a different name, is that situation arranged by hand.
    // Finding "alpha" has to fail on the name rather than answer from the key,
    // and adding it has to join the bucket rather than overwrite the name
    // already there.
    static u8 forged[2 * (ADYTUMFS_DIR_HEADER + 5u)];
    u64 hash = 0;
    struct adytumfs_item_key key = {0};
    valid = valid &&
        adytumfs_dir_item_remove(dev, &super, &store, root, dir, "alpha", 5,
                                 next) == 0 &&
        adytumfs_dir_name_hash("alpha", 5, &hash) == 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        root[index] = next[index];
    key.objectid = dir;
    key.offset = hash;
    key.type = ADYTUMFS_ITEM_DIR;
    valid = valid &&
        adytumfs_dirent_pack(forged, (u32)sizeof forged, 77,
                             ADYTUMFS_DTYPE_REG, "other", 5) == 0 &&
        adytumfs_item_insert(dev, &super, &store, root, &key, forged,
                             ADYTUMFS_DIR_HEADER + 5u, next) == 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        root[index] = next[index];
    valid = valid &&
        adytumfs_dir_item_find(dev, &super, &store, root, dir, "alpha", 5,
                               &inode, &kind) != 0 &&
        adytumfs_dir_item_add(dev, &super, &store, root, dir, "alpha", 5, 11,
                              ADYTUMFS_DTYPE_REG, next) == 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        root[index] = next[index];
    valid = valid &&
        adytumfs_dir_item_find(dev, &super, &store, root, dir, "alpha", 5,
                               &inode, &kind) == 0 &&
        inode == 11;
    // The name already in that bucket is unreachable by its own name, because
    // a bucket is addressed by the hash its entries agree on and this one was
    // filed under a hash no name here produces. Pinning that is what makes the
    // comparison inside the bucket load bearing rather than decorative.
    valid = valid &&
        adytumfs_dir_item_find(dev, &super, &store, root, dir, "other", 5,
                               &inode, &kind) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
