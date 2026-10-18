#include "adytumfs_format.h"
#include "crypto.h"
#include "adytumfs_item.h"
#include "adytumfs_tree.h"
#include "blake2b.h"
#include "crc32c.h"
#include "rtc64.h"

void adytumfs_inode_pack(u8 *slot, const struct adytumfs_inode *inode) {
    for (u32 index = 0; index < ADYTUMFS_INODE_SIZE; index++) slot[index] = 0;
    adytumfs_write_le16(slot + 0, inode->mode);
    adytumfs_write_le16(slot + 2, inode->links);
    adytumfs_write_le32(slot + 4, inode->uid);
    adytumfs_write_le32(slot + 8, inode->gid);
    adytumfs_write_le32(slot + 12, inode->flags);
    adytumfs_write_le64(slot + 16, inode->size);
    adytumfs_write_le64(slot + 24, inode->blocks);
    adytumfs_write_le64(slot + 32, inode->atime);
    adytumfs_write_le64(slot + 40, inode->mtime);
    adytumfs_write_le64(slot + 48, inode->ctime);
    adytumfs_write_le64(slot + 56, inode->generation);
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        slot[64 + index] = inode->extent_root[index];
    adytumfs_write_le32(slot + 240, inode->atime_nsec);
    adytumfs_write_le32(slot + 244, inode->mtime_nsec);
    adytumfs_write_le32(slot + 248, inode->ctime_nsec);
    adytumfs_write_le32(slot + ADYTUMFS_INODE_CHECKSUM_OFFSET,
                        crc32c(slot, ADYTUMFS_INODE_CHECKSUM_OFFSET));
}

int adytumfs_inode_unpack(struct adytumfs_inode *inode, const u8 *slot) {
    u16 mode = adytumfs_read_le16(slot + 0);
    // An all zero image carries no meaningful checksum, so only an image
    // with a mode set is checked.
    if (mode && adytumfs_read_le32(slot + ADYTUMFS_INODE_CHECKSUM_OFFSET) !=
        crc32c(slot, ADYTUMFS_INODE_CHECKSUM_OFFSET))
        return -1;
    inode->mode = mode;
    inode->links = adytumfs_read_le16(slot + 2);
    inode->uid = adytumfs_read_le32(slot + 4);
    inode->gid = adytumfs_read_le32(slot + 8);
    inode->flags = adytumfs_read_le32(slot + 12);
    inode->size = adytumfs_read_le64(slot + 16);
    inode->blocks = adytumfs_read_le64(slot + 24);
    inode->atime = adytumfs_read_le64(slot + 32);
    inode->mtime = adytumfs_read_le64(slot + 40);
    inode->ctime = adytumfs_read_le64(slot + 48);
    inode->generation = adytumfs_read_le64(slot + 56);
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        inode->extent_root[index] = slot[64 + index];
    inode->atime_nsec = adytumfs_read_le32(slot + 240);
    inode->mtime_nsec = adytumfs_read_le32(slot + 244);
    inode->ctime_nsec = adytumfs_read_le32(slot + 248);
    return 0;
}

static void root_copy(u8 *to, const u8 *from) {
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        to[index] = from[index];
}

// An inode is one item in the metadata tree, keyed by its own number. The key
// is assembled in one place because four callers need the same fields, and a
// spare left uninitialised would order the item away from its own lookups.
static void inode_key(struct adytumfs_item_key *key, u64 inode_num) {
    key->objectid = inode_num;
    key->offset = 0;
    key->type = ADYTUMFS_ITEM_INODE;
    key->spare = 0;
}

// Where an inode is being held, or -1 when it is not.
static int stage_find(struct adytumfs_cas *store, u64 inode_num) {
    for (u32 index = 0; index < ADYTUMFS_INODE_STAGE; index++)
        if (store->staged_num[index] == inode_num) return (int)index;
    return -1;
}

// Land one held image in the tree. The root it supersedes is left standing
// rather than dropped, for the reason the commit gives: the committed
// superblock still names it, and dropping it early would leave that
// superblock pointing at freed nodes.
static int stage_land(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store, u32 index) {
    struct adytumfs_item_key key;
    inode_key(&key, store->staged_num[index]);
    // Captured on the first landing rather than when the store is bound,
    // because a store belongs to an index run and not to a generation, and
    // this is the first moment the distinction decides anything.
    if (adytumfs_item_root_empty(store->txn_root))
        root_copy(store->txn_root, super->inode_root);
    u8 previous[ADYTUMFS_HASH_SIZE];
    root_copy(previous, super->inode_root);
    u8 next[ADYTUMFS_HASH_SIZE];
    if (adytumfs_item_insert(device, super, store, previous, &key,
                             store->staged_image[index], ADYTUMFS_INODE_SIZE,
                             next))
        return -1;
    root_copy(super->inode_root, next);
    store->staged_num[index] = 0;
    // Every root this transaction built before this one is named by nothing
    // any more, and leaving it mapped is what made a rebuilt index report a
    // leak on a volume that had merely been written to. The one the
    // committed generation names stays: dropping it here would leave the
    // superblock on the device pointing at freed nodes.
    if (!crypto_equal(previous, store->txn_root, ADYTUMFS_HASH_SIZE))
        return adytumfs_item_drop(device, super, store, previous);
    return 0;
}

// Land everything held. The commit calls this before it counts the window,
// both so the flip cannot name a tree these inodes never reached and so the
// blocks they allocate are part of the generation being written.
int adytumfs_inode_flush(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store) {
    if (!device || !super || !store) return -1;
    for (u32 index = 0; index < ADYTUMFS_INODE_STAGE; index++)
        if (store->staged_num[index] &&
            stage_land(device, super, store, index))
            return -1;
    return 0;
}

int adytumfs_inode_read(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 inode_num,
                        struct adytumfs_inode *out) {
    if (!device || !super || !store || !out || inode_num == 0) return -1;
    // A held image is the truth for this transaction even though the tree
    // still carries the one the committed generation named.
    int held = stage_find(store, inode_num);
    if (held >= 0)
        return adytumfs_inode_unpack(out, store->staged_image[held]);
    struct adytumfs_item_key key;
    inode_key(&key, inode_num);
    u8 slot[ADYTUMFS_INODE_SIZE];
    u32 size = 0;
    if (adytumfs_item_lookup(device, super, store, super->inode_root, &key,
                             slot, ADYTUMFS_INODE_SIZE, &size))
        return -1;
    if (size != ADYTUMFS_INODE_SIZE) return -1;
    return adytumfs_inode_unpack(out, slot);
}

int adytumfs_inode_write(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store, u64 inode_num,
                         const struct adytumfs_inode *in) {
    if (!device || !super || !store || !in || inode_num == 0) return -1;
    int at = stage_find(store, inode_num);
    if (at < 0) {
        // A full stage is a memory budget running out, not a volume limit:
        // the image held longest lands in the tree, costing the block this
        // write would have cost before staging existed, and the new one
        // takes the slot that frees.
        at = (int)store->staged_next;
        store->staged_next = (store->staged_next + 1u) % ADYTUMFS_INODE_STAGE;
        if (store->staged_num[at] && stage_land(device, super, store, (u32)at))
            return -1;
    }
    store->staged_num[at] = inode_num;
    adytumfs_inode_pack(store->staged_image[at], in);
    return 0;
}

int adytumfs_inode_alloc(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store, u16 mode,
                         u64 *inode_num) {
    if (!device || !super || !store || !inode_num || mode == 0) return -1;
    struct adytumfs_inode fresh = {0};
    fresh.mode = mode;
    // A directory is born holding the two names every POSIX directory has, its
    // entry in the parent plus the implicit self reference; counting
    // subdirectory parents arrives with hard links.
    fresh.links = (mode & ADYTUMFS_MODE_DIR) ? 2u : 1u;
    u64 candidate = super->inode_next;
    // The number is the generation. A mount slot is reused even though a
    // number never is, so a tag that restarted at one for every fresh inode
    // would let a handle outliving its file match the slot's next occupant.
    fresh.generation = candidate;
    u64 now = rtc64_wall_clock();
    u32 now_nsec = rtc64_wall_clock_nsec();
    fresh.atime = now;
    fresh.mtime = now;
    fresh.ctime = now;
    fresh.atime_nsec = now_nsec;
    fresh.mtime_nsec = now_nsec;
    fresh.ctime_nsec = now_nsec;
    if (adytumfs_inode_write(device, super, store, candidate, &fresh))
        return -1;
    super->inode_next = candidate + 1u;
    super->live_inodes++;
    *inode_num = candidate;
    return 0;
}

int adytumfs_inode_free(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 inode_num) {
    if (!device || !super || !store || inode_num == 0) return -1;
    // A held image is dropped either way: it is the truth for this
    // transaction, and keeping it would resurrect the inode on the next read.
    int held = stage_find(store, inode_num);
    if (held >= 0) store->staged_num[held] = 0;
    struct adytumfs_item_key key;
    inode_key(&key, inode_num);
    // An inode allocated in this transaction has no item yet, so there is
    // nothing to take out. One that landed in an earlier commit does, and
    // leaving it behind keeps an inode whose extent tree the caller has
    // already released, so the next audit walks a root nothing maps.
    u8 image[ADYTUMFS_INODE_SIZE];
    u32 size = 0;
    int present = !adytumfs_item_lookup(device, super, store, super->inode_root,
                                        &key, image, ADYTUMFS_INODE_SIZE, &size);
    // Neither a held image nor an item means the number names nothing, and
    // freeing it again would take a second inode out of the live count.
    if (held < 0 && !present) return -1;
    if (present) {
        u8 next[ADYTUMFS_HASH_SIZE];
        if (adytumfs_item_remove(device, super, store, super->inode_root, &key,
                                 next))
            return -1;
        root_copy(super->inode_root, next);
    }
    super->live_inodes--;
    return 0;
}

// Commit a new extent root into the inode and let go of the one it named
// before. The order is the whole of the crash argument: the inode reaches the
// disk first, so a crash before the drop leaves the old tree unreferenced and
// the garbage walk reclaims it, while the reverse order would leave an inode
// naming blocks that already went back to the pool.
static int root_commit(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, struct adytumfs_inode *inode,
                       u64 inode_num, const u8 *previous, u64 blocks) {
    u8 built[ADYTUMFS_HASH_SIZE];
    root_copy(built, inode->extent_root);
    int moved = !crypto_equal(previous, built, ADYTUMFS_HASH_SIZE);
    if (adytumfs_inode_write(device, super, store, inode_num, inode)) {
        // The on-disk inode still names the previous root, so the in-memory
        // copy goes back to it and the root just built is the garbage.
        root_copy(inode->extent_root, previous);
        inode->blocks = blocks;
        if (moved) adytumfs_tree_drop(device, super, store, built);
        return -1;
    }
    // A rewrite that stores identical bytes lands the same node hash, so the
    // root does not move and the previous root is still the live one.
    if (!moved) return 0;
    return adytumfs_tree_drop(device, super, store, previous);
}

// Every block an entry covers holds the same bytes, so the entry's single
// hash resolves to one block that serves all of them. A run of a thousand
// holes is one mapping, and the caller needs no offset arithmetic because
// there is nothing to add to the block number.
static int inode_span(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store,
                      const struct adytumfs_inode *inode, u64 logical_block,
                      struct adytumfs_tree_span *span) {
    return adytumfs_tree_find(device, super, store, inode->extent_root,
                              logical_block * ADYTUMFS_BLOCK_SIZE, span);
}

int adytumfs_inode_block_hash(struct kernel_object *device,
                              struct adytumfs_superblock *super,
                              struct adytumfs_cas *store,
                              const struct adytumfs_inode *inode,
                              u64 logical_block, u8 hash[ADYTUMFS_HASH_SIZE]) {
    if (!device || !super || !store || !inode || !hash) return -1;
    struct adytumfs_tree_span span;
    if (inode_span(device, super, store, inode, logical_block, &span))
        return -1;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        hash[index] = span.hash[index];
    return 0;
}

int adytumfs_inode_map(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const struct adytumfs_inode *inode, u64 logical_block,
                       u64 *physical_block) {
    if (!device || !super || !store || !inode || !physical_block) return -1;
    u8 hash[ADYTUMFS_HASH_SIZE];
    if (adytumfs_inode_block_hash(device, super, store, inode, logical_block,
                                  hash))
        return -1;
    return adytumfs_cas_lookup(device, super, store, hash, physical_block);
}

// Map a logical block and read it in one step. Every content reader wants the
// pair, and going through here is what makes the hash check the block is read
// under impossible to leave out by taking the mapping alone.
int adytumfs_inode_fetch(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const struct adytumfs_inode *inode, u64 logical_block,
                         u8 *buffer) {
    if (!device || !super || !store || !inode || !buffer) return -1;
    u8 hash[ADYTUMFS_HASH_SIZE];
    if (adytumfs_inode_block_hash(device, super, store, inode, logical_block,
                                  hash))
        return -1;
    return adytumfs_cas_read(device, super, store, hash, buffer);
}

// Land content in the store and hand back its hash. Placing rather than
// acquiring is deliberate: the tree takes the reference when it packs the
// entry that names this hash, so a reference taken here as well would be one
// nobody ever releases.
static int content_place(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store, const u8 *content,
                         u8 hash[ADYTUMFS_HASH_SIZE], u64 *number) {
    if (blake2b(hash, ADYTUMFS_HASH_SIZE, content, ADYTUMFS_BLOCK_SIZE))
        return -1;
    if (adytumfs_cas_place(device, super, store, hash, number)) return -1;
    return adytumfs_block_write(device, *number, content);
}

int adytumfs_inode_grow(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        struct adytumfs_inode *inode, u64 inode_num,
                        u64 new_blocks) {
    if (!device || !super || !store || !inode) return -1;
    if (new_blocks <= inode->blocks) return 0;
    u64 blocks = inode->blocks;
    struct adytumfs_tree_value value;
    u64 number = 0;
    if (adytumfs_zero_hash(value.hash)) return -1;
    // One entry covers the whole growth whatever its length, because a hole is
    // a run of identical blocks and the format says the hash repeats every
    // block of them.
    value.length = (new_blocks - blocks) * ADYTUMFS_BLOCK_SIZE;
    if (adytumfs_cas_place(device, super, store, value.hash, &number))
        return -1;
    if (adytumfs_block_zero(device, number)) return -1;
    struct adytumfs_tree_key key;
    u8 next[ADYTUMFS_HASH_SIZE];
    key.end = new_blocks * ADYTUMFS_BLOCK_SIZE;
    if (adytumfs_tree_insert(device, super, store, inode->extent_root, &key,
                             &value, next))
        return -1;
    u8 previous[ADYTUMFS_HASH_SIZE];
    root_copy(previous, inode->extent_root);
    root_copy(inode->extent_root, next);
    inode->blocks = new_blocks;
    return root_commit(device, super, store, inode, inode_num, previous,
                       blocks);
}

int adytumfs_inode_truncate(struct kernel_object *device,
                            struct adytumfs_superblock *super,
                            struct adytumfs_cas *store,
                            struct adytumfs_inode *inode, u64 inode_num,
                            u64 new_blocks) {
    if (!device || !super || !store || !inode) return -1;
    if (new_blocks >= inode->blocks) return 0;
    u64 blocks = inode->blocks;
    u8 next[ADYTUMFS_HASH_SIZE];
    if (adytumfs_tree_truncate(device, super, store, inode->extent_root,
                               new_blocks * ADYTUMFS_BLOCK_SIZE, next))
        return -1;
    u8 previous[ADYTUMFS_HASH_SIZE];
    root_copy(previous, inode->extent_root);
    root_copy(inode->extent_root, next);
    inode->blocks = new_blocks;
    return root_commit(device, super, store, inode, inode_num, previous,
                       blocks);
}

int adytumfs_inode_remap(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         struct adytumfs_inode *inode, u64 inode_num,
                         u64 logical, const u8 *content) {
    if (!device || !super || !store || !inode || !content) return -1;
    struct adytumfs_tree_value value;
    u64 number = 0;
    u64 blocks = inode->blocks;
    if (content_place(device, super, store, content, value.hash, &number))
        return -1;
    // One block, so the entry covers exactly the block being rewritten and
    // splits any run it sat inside without the caller saying so.
    value.length = ADYTUMFS_BLOCK_SIZE;
    struct adytumfs_tree_key key;
    u8 next[ADYTUMFS_HASH_SIZE];
    key.end = (logical + 1u) * ADYTUMFS_BLOCK_SIZE;
    if (adytumfs_tree_insert(device, super, store, inode->extent_root, &key,
                             &value, next))
        return -1;
    u8 previous[ADYTUMFS_HASH_SIZE];
    root_copy(previous, inode->extent_root);
    root_copy(inode->extent_root, next);
    return root_commit(device, super, store, inode, inode_num, previous,
                       blocks);
}
