#include "adytumfs_cas.h"
#include "adytumfs_format.h"
#include "crypto.h"
#include "adytumfs_index.h"
#include "adytumfs_item.h"
#include "blake2b.h"
#include "block.h"
#include "cache.h"
#include "rtc64.h"

int adytumfs_block_read(struct kernel_object *device, u64 block, u8 *buffer) {
    return block_cache_read(device, (u32)(block * ADYTUMFS_SECTORS_PER_BLOCK),
                            buffer, ADYTUMFS_SECTORS_PER_BLOCK);
}

int adytumfs_block_write(struct kernel_object *device, u64 block,
                         const u8 *buffer) {
    return block_cache_write(device, (u32)(block * ADYTUMFS_SECTORS_PER_BLOCK),
                             buffer, ADYTUMFS_SECTORS_PER_BLOCK);
}

// Zero source for newly allocated blocks; it is written to the device and
// never modified, so the bss zero it boots with is all it ever needs.
static u8 adytumfs_zero_block[ADYTUMFS_BLOCK_SIZE];

// One staging block for the checksum region's read-modify-write; the data
// paths are single-CPU, like the rest of the format layer.





// The hash of the sealed zero image, which is what every hole on the volume
// names. Computed once rather than per hole: it is the same 4096 zero bytes
// every time, and hashing them on every grow of every file is work with no
// output that changes.
int adytumfs_zero_hash(u8 hash[ADYTUMFS_HASH_SIZE]) {
    static u8 cached[ADYTUMFS_HASH_SIZE];
    static int ready;
    if (!hash) return -1;
    if (!ready) {
        if (blake2b(cached, ADYTUMFS_HASH_SIZE, adytumfs_zero_block,
                    ADYTUMFS_BLOCK_SIZE))
            return -1;
        ready = 1;
    }
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        hash[index] = cached[index];
    return 0;
}

int adytumfs_block_zero(struct kernel_object *device, u64 block) {
    u32 lba = (u32)(block * ADYTUMFS_SECTORS_PER_BLOCK);
    block_cache_invalidate(device, lba, ADYTUMFS_SECTORS_PER_BLOCK);
    for (u32 sector = 0; sector < ADYTUMFS_SECTORS_PER_BLOCK; sector++)
        if (block_io(device, BLOCK_OP_WRITE, lba + sector, 1,
                     adytumfs_zero_block + sector * BLOCK_SECTOR_SIZE,
                     BLOCK_SECTOR_SIZE))
            return -1;
    // No seal: a content block is vouched for by the hash its parent
    // records, and the zero image names itself through adytumfs_zero_hash.
    return 0;
}

int adytumfs_make(struct kernel_object *device) {
    struct block_info info;
    if (!device || block_info(device, &info) ||
        (info.flags & BLOCK_FLAG_READ_ONLY))
        return -1;

    u64 total_blocks = info.sector_count / ADYTUMFS_SECTORS_PER_BLOCK;
    const u64 bits_per_block = (u64)ADYTUMFS_BLOCK_SIZE * 8;
    u64 bitmap_blocks = (total_blocks + bits_per_block - 1) / bits_per_block;
    u64 data_start = 1 + bitmap_blocks;
    // The tail from the last block backwards (shadow superblock, then shadow
    // bitmap) must leave room past the prefix for at least one data block.
    u64 tail_base = total_blocks - 1 - bitmap_blocks;
    if (total_blocks < 1 || tail_base <= data_start) return -1;

    u64 data_blocks = tail_base - data_start;
    if (data_blocks == 0) return -1;
    // The location index is reserved out of the data region rather than put in
    // the metadata prefix, so the prefix stays the size it was and the index
    // grows with the volume instead of being a second fixed table. It carries
    // one entry per content block, and a hash table driven at full load
    // degenerates into a scan, so it is sized for roughly three quarters.
    u64 index_capacity = data_blocks + data_blocks / 3;
    u64 index_blocks = index_capacity / ADYTUMFS_INDEX_PER_BLOCK + 2u;
    if (index_blocks * 2u > data_blocks) return -1;
    u64 index_start = data_start;
    // The tail packs upward from the last block: the backup superblock in the
    // last block, then the shadow bitmap below it.
    u64 shadow_bitmap_start = tail_base;

    struct adytumfs_superblock super = {
        .format_version = ADYTUMFS_FORMAT_VERSION,
        .block_size = ADYTUMFS_BLOCK_SIZE,
        .total_blocks = total_blocks,
        .block_bitmap_start = 1,
        .block_bitmap_blocks = bitmap_blocks,
        // Numbering starts at 1 and the root takes that slot, so the next
        // number to hand out is one past it.
        .inode_next = ADYTUMFS_ROOT_INODE + 1,
        .root_inode = ADYTUMFS_ROOT_INODE,
        .data_start = data_start,
        .free_blocks = data_blocks - index_blocks,
        .live_inodes = 1,
        .generation = 1,
        .feature_compat = 0,
        .feature_incompat = ADYTUMFS_FEATURE_INCOMPAT_V3 |
                            ADYTUMFS_FEATURE_INCOMPAT_NO_CKSUM_REGION |
                            ADYTUMFS_FEATURE_INCOMPAT_ITEM_INODES,
        .feature_ro_compat = 0,
        .data_end = tail_base,
        .index_start = index_start,
        .index_blocks = index_blocks,
    };

    // A 4 KiB staging block is too big for a modest stack, and the format
    // path is single threaded, so it is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];

    // The metadata prefix [0, data_start) and the whole tail from the checksum
    // region on are allocated; an empty root directory owns no data blocks yet.
    // Both bitmap copies carry the same map, so the shadow side starts life as
    // an exact twin of the primary.
    for (u64 bitmap = 0; bitmap < bitmap_blocks; bitmap++) {
        for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
            block[index] = 0;
        u64 base = bitmap * bits_per_block;
        for (u64 used = 0; used < total_blocks; used++)
            if ((used < data_start || used >= tail_base ||
                 (used >= index_start && used < index_start + index_blocks)) &&
                used >= base && used - base < bits_per_block)
                block[(used - base) / 8] |= (u8)(1u << ((used - base) % 8));
        if (adytumfs_block_write(device, super.block_bitmap_start + bitmap,
                                 block) ||
            adytumfs_block_write(device, shadow_bitmap_start + bitmap, block))
            return -1;
    }

    // The index is formatted before the tree because the tree writes through
    // it: a node has nowhere to land until its hash has a location.
    struct adytumfs_index index;
    adytumfs_index_init(&index, index_start, index_blocks);
    if (adytumfs_index_format(device, &index)) return -1;

    // The root directory is the first item in the tree. Inserting it allocates
    // from the bitmap written above, so the counts the superblock carries are
    // only final once this has run.
    struct adytumfs_cas store;
    adytumfs_cas_open(&store, index_start, index_blocks);
    struct adytumfs_inode root = {0};
    root.mode = ADYTUMFS_MODE_DIR | 0755u;
    root.links = 2;
    root.generation = 1;
    u64 now = rtc64_wall_clock();
    root.atime = now;
    root.mtime = now;
    root.ctime = now;
    static u8 root_slot[ADYTUMFS_INODE_SIZE];
    adytumfs_inode_pack(root_slot, &root);
    struct adytumfs_item_key key = {0};
    key.objectid = ADYTUMFS_ROOT_INODE;
    key.type = ADYTUMFS_ITEM_INODE;
    // An empty tree is named by all zero bytes, which is what the insert
    // tests for. adytumfs_zero_hash means the hash of a zeroed block, not a
    // cleared buffer, and passing that here sends the first insert down a
    // tree that does not exist yet.
    u8 empty_root[ADYTUMFS_HASH_SIZE];
    for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++) empty_root[byte] = 0;
    if (adytumfs_item_insert(device, &super, &store, empty_root, &key,
                             root_slot, ADYTUMFS_INODE_SIZE,
                             super.inode_root))
        return -1;

    // The insert took a block from the allocator, which only moves the staged
    // bitmap: nothing commits during a format, so the map on the device still
    // shows that block free and the next allocation would hand it out and
    // overwrite the tree the superblock is about to name. Mark it in both
    // copies before the superblock exists to be interrupted.
    u64 root_block = 0;
    if (adytumfs_cas_lookup(device, &super, &store, super.inode_root,
                            &root_block))
        return -1;
    u64 map_block = root_block / bits_per_block;
    u64 map_bit = root_block % bits_per_block;
    if (adytumfs_block_read(device, super.block_bitmap_start + map_block,
                            block))
        return -1;
    block[map_bit / 8] |= (u8)(1u << (map_bit % 8));
    if (adytumfs_block_write(device, super.block_bitmap_start + map_block,
                             block) ||
        adytumfs_block_write(device, shadow_bitmap_start + map_block, block))
        return -1;

    // Both superblock copies are written last, so a format interrupted before
    // this leaves no superblock at all rather than one naming a tree that was
    // never built.
    adytumfs_super_pack(block, &super);
    if (adytumfs_block_write(device, 0, block) ||
        adytumfs_block_write(device, total_blocks - 1, block))
        return -1;

    return block_cache_flush(device);
}

// The bitmap block for a given data block is re-read on every bit access; the
// block cache absorbs the repeats, so it stays a read-modify-write against one
// staging block rather than holding the whole bitmap in memory.
static u8 adytumfs_bitmap_scratch[ADYTUMFS_BLOCK_SIZE];

// The staged image of a bitmap block the allocator compares against the
// committed image of the same block: a block the window freed reads free in
// the staging but allocated in the committed bitmap, and that difference is
// exactly the pending-free set the allocator must skip.
static u8 adytumfs_committed_scratch[ADYTUMFS_BLOCK_SIZE];

// One staged metadata block of an open window. Entries are keyed by device so
// several mounted volumes can hold windows side by side, and by block index
// within the set rather than by device location, because which set is active
// changes at every commit while the image content is what the window owns.
// The pool holds every bitmap block the window has touched; exhaustion means
// a window more fragmented than that, which the format layer refuses rather
// than half-staging.
#define ADYTUMFS_STAGING_POOL 32u

struct adytumfs_staged {
    struct kernel_object *device;
    u8 index;
    u8 image[ADYTUMFS_BLOCK_SIZE];
};

static struct adytumfs_staged adytumfs_staging[ADYTUMFS_STAGING_POOL];

// Both metadata sets are addressed slot-relative: the active slot names the
// set the window reads through, the inactive slot the set the commit writes.
static u64 superblock_slot(u64 total_blocks, u8 slot) {
    return slot ? total_blocks - 1 : 0;
}

static u64 bitmap_slot_base(const struct adytumfs_superblock *super, u8 slot) {
    if (!slot) return super->block_bitmap_start;
    return super->total_blocks - 1 - super->block_bitmap_blocks;
}

// The device location of one bitmap or table block of the ACTIVE set: the
// mount, the verify pass, and device-level tests all address the generation
// that currently won, never a fixed copy.
u64 adytumfs_superblock_block(const struct adytumfs_superblock *super) {
    return superblock_slot(super->total_blocks, super->active_slot);
}

u64 adytumfs_bitmap_block(const struct adytumfs_superblock *super, u32 index) {
    return bitmap_slot_base(super, super->active_slot) + index;
}

static struct adytumfs_staged *staging_find(struct kernel_object *device,
                                            u32 index) {
    for (u32 entry = 0; entry < ADYTUMFS_STAGING_POOL; entry++)
        if (adytumfs_staging[entry].device == device &&
            adytumfs_staging[entry].index == (u8)index)
            return &adytumfs_staging[entry];
    return 0;
}

// Claim a staging entry for a metadata block, seeding it with the committed
// image so the caller can read-modify-write it. Fails closed when the pool is
// full or the device read fails.
static struct adytumfs_staged *staging_claim(struct kernel_object *device,
                                             const struct adytumfs_superblock
                                                 *super, u32 index) {
    // The index travels in a byte; a bitmap block count beyond that belongs
    // to a volume larger than any device this kernel drives.
    if (index > 255u) return 0;
    struct adytumfs_staged *entry = staging_find(device, index);
    if (entry) return entry;
    for (u32 scan = 0; scan < ADYTUMFS_STAGING_POOL; scan++) {
        entry = &adytumfs_staging[scan];
        if (entry->device) continue;
        u64 block = bitmap_slot_base(super, super->active_slot) + index;
        if (adytumfs_block_read(device, block, entry->image)) return 0;
        entry->device = device;
        entry->index = (u8)index;
        return entry;
    }
    return 0;
}

void adytumfs_window_discard(struct kernel_object *device) {
    for (u32 entry = 0; entry < ADYTUMFS_STAGING_POOL; entry++)
        if (adytumfs_staging[entry].device == device)
            adytumfs_staging[entry].device = 0;
}

// Read one allocation bit through the staging.
static int adytumfs_bit_test(struct kernel_object *device,
                             const struct adytumfs_superblock *super,
                             u64 block) {
    const u64 bits_per_block = (u64)ADYTUMFS_BLOCK_SIZE * 8;
    u64 bitmap = block / bits_per_block;
    u64 offset = block % bits_per_block;
    if (bitmap >= super->block_bitmap_blocks) return -1;
    struct adytumfs_staged *entry = staging_find(device, (u32)bitmap);
    if (entry) {
        return (entry->image[offset / 8] >> (offset % 8)) & 1;
    }
    if (adytumfs_block_read(device, bitmap_slot_base(super,
                                                     super->active_slot) +
                                            bitmap,
                            adytumfs_bitmap_scratch))
        return -1;
    return (adytumfs_bitmap_scratch[offset / 8] >> (offset % 8)) & 1;
}

// Read one allocation bit from the committed bitmap on the device, ignoring
// the staging. The allocator uses this to tell a block freed by the open
// window (staged free, committed allocated) from one the last committed
// generation already released.
static int adytumfs_bit_committed(struct kernel_object *device,
                                  const struct adytumfs_superblock *super,
                                  u64 block) {
    const u64 bits_per_block = (u64)ADYTUMFS_BLOCK_SIZE * 8;
    u64 bitmap = block / bits_per_block;
    u64 offset = block % bits_per_block;
    if (bitmap >= super->block_bitmap_blocks) return -1;
    if (adytumfs_block_read(device, bitmap_slot_base(super,
                                                     super->active_slot) +
                                            bitmap,
                            adytumfs_committed_scratch))
        return -1;
    return (adytumfs_committed_scratch[offset / 8] >> (offset % 8)) & 1;
}

// Stage one allocation bit edit. Nothing touches the device: the committed
// bitmap is part of the generation the flip replaces wholesale.
static int adytumfs_bit_write(struct kernel_object *device,
                              const struct adytumfs_superblock *super,
                              u64 block, int used) {
    const u64 bits_per_block = (u64)ADYTUMFS_BLOCK_SIZE * 8;
    u64 bitmap = block / bits_per_block;
    u64 offset = block % bits_per_block;
    if (bitmap >= super->block_bitmap_blocks) return -1;
    struct adytumfs_staged *entry =
        staging_claim(device, super, (u32)bitmap);
    if (!entry) return -1;
    if (used)
        entry->image[offset / 8] |= (u8)(1u << (offset % 8));
    else
        entry->image[offset / 8] &= (u8)~(1u << (offset % 8));
    return 0;
}

int adytumfs_alloc_run(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       u64 length, u64 *start) {
    if (!super || !start || length == 0) return -1;
    // Everything from the checksum region on is metadata (the region, the
    // shadow table, the shadow bitmap, the backup superblock), so it is never
    // allocatable.
    u64 usable_end = super->data_end;
    u64 run_start = 0;
    u64 run = 0;
    for (u64 block = super->data_start; block < usable_end; block++) {
        int used = adytumfs_bit_test(device, super, block);
        if (used < 0) return -1;
        if (used) {
            run = 0;
            continue;
        }
        // The staging may have freed this block within the window while the
        // committed generation on the device still references its old image,
        // so only a block the committed bitmap released as well is reusable.
        if (staging_find(device,
                         (u32)(block / ((u64)ADYTUMFS_BLOCK_SIZE * 8)))) {
            int committed = adytumfs_bit_committed(device, super, block);
            if (committed < 0) return -1;
            if (committed) {
                run = 0;
                continue;
            }
        }
        if (run == 0) run_start = block;
        run++;
        if (run == length) {
            for (u64 mark = run_start; mark < run_start + length; mark++)
                if (adytumfs_bit_write(device, super, mark, 1)) return -1;
            super->free_blocks -= length;
            *start = run_start;
            return 0;
        }
    }
    return -1;
}

int adytumfs_free_run(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      u64 start, u64 length) {
    if (!super || length == 0) return -1;
    // Only data blocks are freeable; the metadata prefix and the tail from the
    // checksum region on must never be handed back to the allocator.
    if (start < super->data_start || start >= super->data_end ||
        length > super->data_end - start)
        return -1;
    for (u64 block = start; block < start + length; block++)
        if (adytumfs_bit_write(device, super, block, 0)) return -1;
    super->free_blocks += length;
    return 0;
}

int adytumfs_superblock_slot_root(struct kernel_object *device,
                                  const struct adytumfs_superblock *super,
                                  u8 slot, u8 root[ADYTUMFS_HASH_SIZE]) {
    if (!device || !super || !root || slot > 1u) return 0;
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++) root[index] = 0;
    if (adytumfs_block_read(device, superblock_slot(super->total_blocks, slot),
                            block))
        return 0;
    struct adytumfs_superblock held;
    if (adytumfs_super_unpack(&held, block)) return 0;
    if (adytumfs_super_valid(&held, super->total_blocks)) return 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        root[index] = held.inode_root[index];
    return 1;
}

int adytumfs_commit(struct kernel_object *device,
                    struct adytumfs_superblock *super,
                    struct adytumfs_cas *store) {
    if (!device || !super || !store) return -1;
    // Inodes written since the last commit are still images in the store.
    // They have to reach the tree before the window is counted, both so the
    // flip cannot name a tree they never reached and so the blocks landing
    // them are part of the generation being written. A transaction that
    // touched nothing but inodes would otherwise look empty and not commit.
    if (adytumfs_inode_flush(device, super, store)) return -1;
    u8 inactive = super->active_slot ? 0 : 1;
    // The root the overwritten slot names is a candidate for collection, but
    // only if no superblock left on the device still names it. The two slots
    // hold two generations, and a freshly formatted volume holds the same one
    // in both, so the root the slot being written names can still be the one
    // the other slot falls back to; dropping it there would break the copy a
    // torn flip is supposed to recover to. The surviving slot is read from
    // the device rather than taken from the in-memory superblock, which has
    // already moved on to the root this commit is about to land.
    //
    // Collecting here, before the window is counted, puts the blocks it frees
    // into this same commit: a crash before the flip leaves them staged and
    // both generations on the device still resolve.
    int staged = 0;
    for (u32 entry = 0; entry < ADYTUMFS_STAGING_POOL; entry++)
        if (adytumfs_staging[entry].device == device) staged = 1;
    // A window that staged nothing has nothing to land: skipping the flip
    // keeps read-only mounts from bumping the generation on their way out.
    // Collection has to wait for that verdict. Dropping the superseded root
    // first would destroy a generation in a commit that then decides not to
    // happen, and the device would keep naming blocks nothing accounts for.
    if (!staged) return 0;
    u8 prior_root[ADYTUMFS_HASH_SIZE];
    u8 kept_root[ADYTUMFS_HASH_SIZE];
    adytumfs_superblock_slot_root(device, super, super->active_slot, kept_root);
    // A prior root the index no longer maps was collected by an earlier
    // attempt at this same generation: a commit that fails after the drop
    // leaves it released, and the retry that follows finds nothing to let go
    // of. Treating that as an error would stop the flip on a volume that is
    // already consistent.
    u32 prior_refs = 0;
    if (adytumfs_superblock_slot_root(device, super, inactive, prior_root) &&
        !adytumfs_item_root_empty(prior_root) &&
        !crypto_equal(prior_root, super->inode_root, ADYTUMFS_HASH_SIZE) &&
        !crypto_equal(prior_root, kept_root, ADYTUMFS_HASH_SIZE) &&
        !adytumfs_cas_refs(device, super, store, prior_root, &prior_refs) &&
        adytumfs_item_drop(device, super, store, prior_root))
        return -1;
    // The staged blocks are the next generation's metadata set; the active
    // set on the device stays untouched so the current generation survives
    // every crash point below.
    for (u32 entry = 0; entry < ADYTUMFS_STAGING_POOL; entry++) {
        struct adytumfs_staged *slot = &adytumfs_staging[entry];
        if (slot->device != device) continue;
        u64 block = bitmap_slot_base(super, inactive) + slot->index;
        if (adytumfs_block_write(device, block, slot->image)) return -1;
    }
    // Land every dirty sector of this device before the flip exists on it.
    // The cache flushes entries in array order, so one flush could seat the
    // new superblock ahead of the metadata it names and a crash between the
    // two would leave the newest generation naming blocks the device never
    // wrote. Flushing here, then writing and flushing the superblock alone,
    // makes the flip the last write the commit can issue.
    if (block_cache_flush(device)) return -1;
    // The superblock write is the flip: it lands last, carries generation
    // plus one, and names the set just written. A torn write fails the
    // superblock checksum and the mount picker falls back to the old one.
    struct adytumfs_superblock next = *super;
    next.generation++;
    next.active_slot = inactive;
    // A 4 KiB staging block is too large for a modest stack, and the commit
    // path is single threaded like the rest of the format layer.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    adytumfs_super_pack(block, &next);
    u64 flip = superblock_slot(super->total_blocks, inactive);
    if (adytumfs_block_write(device, flip, block)) return -1;
    if (block_cache_flush(device)) {
        // A failed flip can leave a half written superblock resident in the
        // cache. A retry must not land it ahead of the metadata it names, so
        // the cached copy is dropped and rebuilt from the staging.
        block_cache_invalidate(device, (u32)(flip * ADYTUMFS_SECTORS_PER_BLOCK),
                               ADYTUMFS_SECTORS_PER_BLOCK);
        return -1;
    }
    *super = next;
    // The root this transaction started from has just become the one the
    // overwritten slot no longer names, so the next transaction captures its
    // own instead of protecting a generation that is gone.
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        store->txn_root[index] = 0;
    adytumfs_window_discard(device);
    return 0;
}
