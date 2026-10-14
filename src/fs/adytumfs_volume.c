#include "adytumfs_format.h"
#include "adytumfs_index.h"
#include "crc32c.h"
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
static u8 adytumfs_checksum_scratch[ADYTUMFS_BLOCK_SIZE];

int adytumfs_data_check(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        u64 block, const u8 *bytes) {
    if (block < super->data_start || block >= super->data_checksum_region)
        return -1;
    u64 index = block - super->data_start;
    u64 region_block =
        super->data_checksum_region + index / ADYTUMFS_CHECKSUMS_PER_BLOCK;
    if (adytumfs_block_read(device, region_block, adytumfs_checksum_scratch))
        return -1;
    const u8 *entry = adytumfs_checksum_scratch +
                      (index % ADYTUMFS_CHECKSUMS_PER_BLOCK) * 4u;
    return adytumfs_read_le32(entry) == crc32c(bytes, ADYTUMFS_BLOCK_SIZE)
               ? 0
               : -1;
}

int adytumfs_data_seal(struct kernel_object *device,
                       const struct adytumfs_superblock *super,
                       u64 block, const u8 *bytes) {
    if (block < super->data_start || block >= super->data_checksum_region)
        return -1;
    u64 index = block - super->data_start;
    u64 region_block =
        super->data_checksum_region + index / ADYTUMFS_CHECKSUMS_PER_BLOCK;
    if (adytumfs_block_read(device, region_block, adytumfs_checksum_scratch))
        return -1;
    adytumfs_write_le32(adytumfs_checksum_scratch +
                            (index % ADYTUMFS_CHECKSUMS_PER_BLOCK) * 4u,
                        crc32c(bytes, ADYTUMFS_BLOCK_SIZE));
    return adytumfs_block_write(device, region_block,
                                adytumfs_checksum_scratch);
}

int adytumfs_data_read(struct kernel_object *device,
                       const struct adytumfs_superblock *super,
                       u64 block, u8 *buffer) {
    if (adytumfs_block_read(device, block, buffer)) return -1;
    return adytumfs_data_check(device, super, block, buffer);
}

int adytumfs_data_write(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        u64 block, const u8 *buffer) {
    if (adytumfs_block_write(device, block, buffer)) return -1;
    return adytumfs_data_seal(device, super, block, buffer);
}

int adytumfs_block_zero(struct kernel_object *device,
                        const struct adytumfs_superblock *super, u64 block) {
    u32 lba = (u32)(block * ADYTUMFS_SECTORS_PER_BLOCK);
    block_cache_invalidate(device, lba, ADYTUMFS_SECTORS_PER_BLOCK);
    for (u32 sector = 0; sector < ADYTUMFS_SECTORS_PER_BLOCK; sector++)
        if (block_io(device, BLOCK_OP_WRITE, lba + sector, 1,
                     adytumfs_zero_block + sector * BLOCK_SECTOR_SIZE,
                     BLOCK_SECTOR_SIZE))
            return -1;
    // A freshly allocated block reads back as zeroes through the verified
    // path, so the zero image has to be sealed like any other write.
    return adytumfs_data_seal(device, super, block, adytumfs_zero_block);
}

int adytumfs_make(struct kernel_object *device) {
    struct block_info info;
    if (!device || block_info(device, &info) ||
        (info.flags & BLOCK_FLAG_READ_ONLY))
        return -1;

    u64 total_blocks = info.sector_count / ADYTUMFS_SECTORS_PER_BLOCK;
    const u64 bits_per_block = (u64)ADYTUMFS_BLOCK_SIZE * 8;
    u64 bitmap_blocks = (total_blocks + bits_per_block - 1) / bits_per_block;
    // The table is bounded: the VFS mounts at most sixteen files, so a table
    // for a few hundred inodes is generous headroom, and the cap keeps the
    // format cost proportional on large volumes instead of zeroing a full
    // thirty-second of the device through the block cache.
    u64 inode_table_blocks = total_blocks / 32;
    if (inode_table_blocks > ADYTUMFS_INODE_TABLE_BLOCKS_MAX)
        inode_table_blocks = ADYTUMFS_INODE_TABLE_BLOCKS_MAX;
    if (inode_table_blocks == 0) inode_table_blocks = 1;
    u64 inode_table_start = 1 + bitmap_blocks;
    u64 data_start = inode_table_start + inode_table_blocks;
    // The tail from the last block backwards (shadow superblock, shadow
    // bitmap, shadow table) must leave room past the prefix for at least one
    // data block beside the checksum region.
    u64 tail_base = total_blocks - 1 - bitmap_blocks - inode_table_blocks;
    if (total_blocks < 1 || tail_base <= data_start) return -1;

    u64 inode_count = inode_table_blocks * ADYTUMFS_INODES_PER_BLOCK;
    // The checksum region ends exactly where the data region ends; its size
    // holds one u32 per data block, so region and data spans are solved
    // together against the space the tail leaves.
    u64 data_span = tail_base - data_start;
    u64 region_blocks = 1;
    while ((data_span - region_blocks + ADYTUMFS_CHECKSUMS_PER_BLOCK - 1) /
               ADYTUMFS_CHECKSUMS_PER_BLOCK >
           region_blocks)
        region_blocks++;
    u64 data_blocks = data_span - region_blocks;
    if (data_blocks == 0) return -1;
    u64 region_start = data_start + data_blocks;
    // The location index is reserved out of the data region rather than put in
    // the metadata prefix, so the prefix stays the size it was and the index
    // grows with the volume instead of being a second fixed table. It carries
    // one entry per content block, and a hash table driven at full load
    // degenerates into a scan, so it is sized for roughly three quarters.
    u64 index_capacity = data_blocks + data_blocks / 3;
    u64 index_blocks = index_capacity / ADYTUMFS_INDEX_PER_BLOCK + 2u;
    if (index_blocks * 2u > data_blocks) return -1;
    u64 index_start = data_start;
    // The tail packs upward from where the checksum region ends: shadow
    // table, then shadow bitmap, then the backup superblock in the last
    // block. Starting the table at tail_base rather than below it keeps the
    // region's last block from doubling as the table's first; the overlap
    // was latent until the generation pair made the tail readable.
    u64 shadow_table_start = tail_base;
    u64 shadow_bitmap_start = tail_base + inode_table_blocks;

    struct adytumfs_superblock super = {
        .format_version = ADYTUMFS_FORMAT_VERSION,
        .block_size = ADYTUMFS_BLOCK_SIZE,
        .total_blocks = total_blocks,
        .block_bitmap_start = 1,
        .block_bitmap_blocks = bitmap_blocks,
        .inode_table_start = inode_table_start,
        .inode_table_blocks = inode_table_blocks,
        .inode_count = inode_count,
        .root_inode = ADYTUMFS_ROOT_INODE,
        .data_start = data_start,
        .free_blocks = data_blocks - index_blocks,
        // Slot 0 is the null inode and the root occupies slot 1, so the
        // free count starts two below the table size.
        .free_inodes = inode_count - 2,
        .generation = 1,
        .feature_compat = 0,
        .feature_incompat = ADYTUMFS_FEATURE_INCOMPAT_V3,
        .feature_ro_compat = 0,
        .data_checksum_region = region_start,
        .index_start = index_start,
        .index_blocks = index_blocks,
    };

    // A 4 KiB staging block is too big for a modest stack, and the format path is
    // single threaded, so it is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];

    adytumfs_super_pack(block, &super);
    if (adytumfs_block_write(device, 0, block) ||
        adytumfs_block_write(device, total_blocks - 1, block))
        return -1;

    // The metadata prefix [0, data_start) and the whole tail from the checksum
    // region on are allocated; an empty root directory owns no data blocks yet.
    // Both bitmap copies carry the same map, so the shadow side starts life as
    // an exact twin of the primary.
    for (u64 bitmap = 0; bitmap < bitmap_blocks; bitmap++) {
        for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++) block[index] = 0;
        u64 base = bitmap * bits_per_block;
        for (u64 used = 0; used < total_blocks; used++)
            if ((used < data_start || used >= region_start ||
                 (used >= index_start && used < index_start + index_blocks)) &&
                used >= base && used - base < bits_per_block)
                block[(used - base) / 8] |= (u8)(1u << ((used - base) % 8));
        if (adytumfs_block_write(device, super.block_bitmap_start + bitmap, block) ||
            adytumfs_block_write(device, shadow_bitmap_start + bitmap, block))
            return -1;
    }

    // Both table copies hold the root, so a future commit that flips the
    // active superblock starts from a complete shadow set.
    for (u64 table = 0; table < inode_table_blocks; table++) {
        for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++) block[index] = 0;
        if (table == 0) {
            struct adytumfs_inode root = {0};
            root.mode = ADYTUMFS_MODE_DIR | 0755u;
            root.links = 2;
            root.generation = 1;
            u64 now = rtc64_wall_clock();
            root.atime = now;
            root.mtime = now;
            root.ctime = now;
            adytumfs_inode_pack(
                block + ADYTUMFS_ROOT_INODE * ADYTUMFS_INODE_SIZE, &root);
        }
        if (adytumfs_block_write(device, inode_table_start + table, block) ||
            adytumfs_block_write(device, shadow_table_start + table, block))
            return -1;
    }

    // A block nobody owns carries checksum zero: the first zeroing or write on
    // allocation replaces it, and an unallocated block is never read.
    for (u64 region = 0; region < region_blocks; region++)
        if (adytumfs_block_write(device, region_start + region,
                                 adytumfs_zero_block))
            return -1;

    // The index is formatted last, once the checksum region exists, because it
    // is written through the verified data path like everything else the tree
    // will read.
    struct adytumfs_index index;
    adytumfs_index_init(&index, index_start, index_blocks);
    if (adytumfs_index_format(device, &super, &index)) return -1;

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
// The pool always holds a volume's complete inode table (the format caps it
// at sixteen blocks) plus every bitmap block the window has touched;
// exhaustion means a window more fragmented than that, which the format
// layer refuses rather than half-staging.
#define ADYTUMFS_STAGING_POOL 32u

struct adytumfs_staged {
    struct kernel_object *device;
    u8 is_table;
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

static u64 table_slot_base(const struct adytumfs_superblock *super, u8 slot) {
    if (!slot) return super->inode_table_start;
    return super->total_blocks - 1 - super->block_bitmap_blocks -
           super->inode_table_blocks;
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

u64 adytumfs_table_block(const struct adytumfs_superblock *super, u32 index) {
    return table_slot_base(super, super->active_slot) + index;
}

static struct adytumfs_staged *staging_find(struct kernel_object *device,
                                            int is_table, u32 index) {
    for (u32 entry = 0; entry < ADYTUMFS_STAGING_POOL; entry++)
        if (adytumfs_staging[entry].device == device &&
            adytumfs_staging[entry].is_table == (u8)is_table &&
            adytumfs_staging[entry].index == (u8)index)
            return &adytumfs_staging[entry];
    return 0;
}

// Claim a staging entry for a metadata block, seeding it with the committed
// image so the caller can read-modify-write it. Fails closed when the pool is
// full or the device read fails.
static struct adytumfs_staged *staging_claim(struct kernel_object *device,
                                             const struct adytumfs_superblock
                                                 *super,
                                             int is_table, u32 index) {
    // The index travels in a byte; a bitmap block count beyond that belongs
    // to a volume larger than any device this kernel drives.
    if (index > 255u) return 0;
    struct adytumfs_staged *entry = staging_find(device, is_table, index);
    if (entry) return entry;
    for (u32 scan = 0; scan < ADYTUMFS_STAGING_POOL; scan++) {
        entry = &adytumfs_staging[scan];
        if (entry->device) continue;
        u64 block = is_table
                        ? table_slot_base(super, super->active_slot) + index
                        : bitmap_slot_base(super, super->active_slot) + index;
        if (adytumfs_block_read(device, block, entry->image)) return 0;
        entry->device = device;
        entry->is_table = (u8)is_table;
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

// Read one metadata block of the active set through the staging: a staged
// block answers from the window's image, anything else from the device.
int adytumfs_table_read(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        u32 index, u8 *buffer) {
    struct adytumfs_staged *entry = staging_find(device, 1, index);
    if (entry) {
        for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
            buffer[byte] = entry->image[byte];
        return 0;
    }
    return adytumfs_block_read(device, table_slot_base(super,
                                                       super->active_slot) +
                                          index,
                               buffer);
}

// Write one inode table block into the staging. The device copy belongs to
// the committed generation and is only replaced whole, by the commit.
int adytumfs_table_stage(struct kernel_object *device,
                         const struct adytumfs_superblock *super,
                         u32 index, const u8 *buffer) {
    struct adytumfs_staged *entry = staging_claim(device, super, 1, index);
    if (!entry) return -1;
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        entry->image[byte] = buffer[byte];
    return 0;
}

// Read one allocation bit through the staging (see adytumfs_table_read).
static int adytumfs_bit_test(struct kernel_object *device,
                             const struct adytumfs_superblock *super,
                             u64 block) {
    const u64 bits_per_block = (u64)ADYTUMFS_BLOCK_SIZE * 8;
    u64 bitmap = block / bits_per_block;
    u64 offset = block % bits_per_block;
    if (bitmap >= super->block_bitmap_blocks) return -1;
    struct adytumfs_staged *entry = staging_find(device, 0, (u32)bitmap);
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
        staging_claim(device, super, 0, (u32)bitmap);
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
    u64 usable_end = super->data_checksum_region;
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
        if (staging_find(device, 0,
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
    if (start < super->data_start || start >= super->data_checksum_region ||
        length > super->data_checksum_region - start)
        return -1;
    for (u64 block = start; block < start + length; block++)
        if (adytumfs_bit_write(device, super, block, 0)) return -1;
    super->free_blocks += length;
    return 0;
}

int adytumfs_commit(struct kernel_object *device,
                    struct adytumfs_superblock *super) {
    if (!device || !super) return -1;
    u8 inactive = super->active_slot ? 0 : 1;
    int staged = 0;
    for (u32 entry = 0; entry < ADYTUMFS_STAGING_POOL; entry++)
        if (adytumfs_staging[entry].device == device) staged = 1;
    // A window that staged nothing has nothing to land: skipping the flip
    // keeps read-only mounts from bumping the generation on their way out.
    if (!staged) return 0;
    // The staged blocks are the next generation's metadata set; the active
    // set on the device stays untouched so the current generation survives
    // every crash point below.
    for (u32 entry = 0; entry < ADYTUMFS_STAGING_POOL; entry++) {
        struct adytumfs_staged *slot = &adytumfs_staging[entry];
        if (slot->device != device) continue;
        u64 block = slot->is_table
                        ? table_slot_base(super, inactive) + slot->index
                        : bitmap_slot_base(super, inactive) + slot->index;
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
    adytumfs_window_discard(device);
    return 0;
}
