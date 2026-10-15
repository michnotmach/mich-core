#include "adytumfs_format.h"
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
    // A free slot has no meaningful checksum, so only in-use inodes are checked.
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

// One staging block for the inode table read-modify-write; the single-CPU
// filesystem owns it for the duration of one call, and the block cache keeps
// repeats cheap.
static u8 adytumfs_inode_scratch[ADYTUMFS_BLOCK_SIZE];

int adytumfs_inode_read(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        u64 inode_num, struct adytumfs_inode *out) {
    if (!super || !out || inode_num == 0 || inode_num >= super->inode_count)
        return -1;
    u32 block = (u32)(inode_num / ADYTUMFS_INODES_PER_BLOCK);
    u32 slot = (u32)(inode_num % ADYTUMFS_INODES_PER_BLOCK) * ADYTUMFS_INODE_SIZE;
    if (adytumfs_table_read(device, super, block, adytumfs_inode_scratch))
        return -1;
    return adytumfs_inode_unpack(out, adytumfs_inode_scratch + slot);
}

int adytumfs_inode_write(struct kernel_object *device,
                         const struct adytumfs_superblock *super,
                         u64 inode_num, const struct adytumfs_inode *in) {
    if (!super || !in || inode_num == 0 || inode_num >= super->inode_count)
        return -1;
    u32 block = (u32)(inode_num / ADYTUMFS_INODES_PER_BLOCK);
    u32 slot = (u32)(inode_num % ADYTUMFS_INODES_PER_BLOCK) * ADYTUMFS_INODE_SIZE;
    // Read-modify-write: the other fifteen inodes in this block must survive,
    // and the merged image lands in the window staging rather than on the
    // device, so the committed table stays whole until the commit.
    if (adytumfs_table_read(device, super, block, adytumfs_inode_scratch))
        return -1;
    adytumfs_inode_pack(adytumfs_inode_scratch + slot, in);
    return adytumfs_table_stage(device, super, block, adytumfs_inode_scratch);
}

int adytumfs_inode_alloc(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         u16 mode, u64 *inode_num) {
    if (!super || !inode_num || mode == 0) return -1;
    for (u64 candidate = 1; candidate < super->inode_count; candidate++) {
        struct adytumfs_inode inode;
        if (adytumfs_inode_read(device, super, candidate, &inode)) return -1;
        if (inode.mode) continue;
        // Reusing a slot bumps its generation so a handle to the old inode that
        // outlives it fails the generation check rather than aliasing the new one.
        struct adytumfs_inode fresh = {0};
        fresh.mode = mode;
        // A directory is born holding the two names every POSIX directory
        // has, its entry in the parent plus the implicit self reference;
        // counting subdirectory parents arrives with hard links.
        fresh.links = (mode & ADYTUMFS_MODE_DIR) ? 2u : 1u;
        fresh.generation = inode.generation + 1;
        u64 now = rtc64_wall_clock();
        u32 now_nsec = rtc64_wall_clock_nsec();
        fresh.atime = now;
        fresh.mtime = now;
        fresh.ctime = now;
        fresh.atime_nsec = now_nsec;
        fresh.mtime_nsec = now_nsec;
        fresh.ctime_nsec = now_nsec;
        if (adytumfs_inode_write(device, super, candidate, &fresh)) return -1;
        super->free_inodes--;
        *inode_num = candidate;
        return 0;
    }
    return -1;
}

int adytumfs_inode_free(struct kernel_object *device,
                        struct adytumfs_superblock *super, u64 inode_num) {
    if (!super || inode_num == 0 || inode_num >= super->inode_count) return -1;
    struct adytumfs_inode inode;
    if (adytumfs_inode_read(device, super, inode_num, &inode)) return -1;
    if (inode.mode == 0) return -1;
    inode.mode = 0;
    if (adytumfs_inode_write(device, super, inode_num, &inode)) return -1;
    super->free_inodes++;
    return 0;
}

static void root_copy(u8 *to, const u8 *from) {
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        to[index] = from[index];
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
    if (adytumfs_inode_write(device, super, inode_num, inode)) {
        // The on-disk inode still names the previous root, so the in-memory
        // copy goes back to it and the root just built is the garbage.
        root_copy(inode->extent_root, previous);
        inode->blocks = blocks;
        return adytumfs_tree_drop(device, super, store, inode->extent_root) ?
            -1 : -1;
    }
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

int adytumfs_inode_hash(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        const struct adytumfs_inode *inode, u64 logical_block,
                        u8 hash[ADYTUMFS_HASH_SIZE]) {
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
    if (adytumfs_inode_hash(device, super, store, inode, logical_block, hash))
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
    if (adytumfs_inode_hash(device, super, store, inode, logical_block, hash))
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
    return root_commit(device, super, store, inode, inode_num, previous, blocks);
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
    return root_commit(device, super, store, inode, inode_num, previous, blocks);
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
    return root_commit(device, super, store, inode, inode_num, previous, blocks);
}
