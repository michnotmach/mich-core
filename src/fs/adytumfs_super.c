#include "adytumfs_format.h"
#include "crc32c.h"
#include "block.h"

void adytumfs_super_pack(u8 *block, const struct adytumfs_superblock *super) {
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++) block[index] = 0;
    static const char signature[] = ADYTUMFS_SIGNATURE;
    for (u32 index = 0; index < ADYTUMFS_SIGNATURE_SIZE; index++)
        block[index] = (u8)signature[index];
    adytumfs_write_le32(block + 8, super->format_version);
    adytumfs_write_le32(block + 12, super->block_size);
    adytumfs_write_le64(block + 16, super->total_blocks);
    adytumfs_write_le64(block + 24, super->block_bitmap_start);
    adytumfs_write_le64(block + 32, super->block_bitmap_blocks);
    // Slots 40 and 48 held the fixed inode table and are reserved now. The
    // block is zeroed above, so leaving them unwritten is what marks a volume
    // as one this format wrote.
    adytumfs_write_le64(block + 56, super->inode_next);
    adytumfs_write_le64(block + 64, super->root_inode);
    adytumfs_write_le64(block + 72, super->data_start);
    adytumfs_write_le64(block + 80, super->free_blocks);
    adytumfs_write_le64(block + 88, super->live_inodes);
    adytumfs_write_le64(block + 96, super->generation);
    adytumfs_write_le64(block + 104, super->feature_compat);
    adytumfs_write_le64(block + 112, super->feature_incompat);
    adytumfs_write_le64(block + 120, super->feature_ro_compat);
    adytumfs_write_le64(block + 128, super->data_end);
    adytumfs_write_le64(block + 136, super->index_start);
    adytumfs_write_le64(block + 144, super->index_blocks);
    for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
        block[160 + byte] = super->inode_root[byte];
    adytumfs_write_le32(block + ADYTUMFS_SUPER_CHECKSUM_OFFSET,
                        crc32c(block, ADYTUMFS_SUPER_CHECKSUM_OFFSET));
}

int adytumfs_super_unpack(struct adytumfs_superblock *super, const u8 *block) {
    static const char signature[] = ADYTUMFS_SIGNATURE;
    for (u32 index = 0; index < ADYTUMFS_SIGNATURE_SIZE; index++)
        if (block[index] != (u8)signature[index]) return -1;
    if (adytumfs_read_le32(block + ADYTUMFS_SUPER_CHECKSUM_OFFSET) !=
        crc32c(block, ADYTUMFS_SUPER_CHECKSUM_OFFSET))
        return -1;
    super->format_version = adytumfs_read_le32(block + 8);
    super->block_size = adytumfs_read_le32(block + 12);
    if (super->format_version != ADYTUMFS_FORMAT_VERSION ||
        super->block_size != ADYTUMFS_BLOCK_SIZE)
        return -1;
    super->total_blocks = adytumfs_read_le64(block + 16);
    super->block_bitmap_start = adytumfs_read_le64(block + 24);
    super->block_bitmap_blocks = adytumfs_read_le64(block + 32);
    // The two slots the fixed table occupied are reserved, so a nonzero value
    // in either is a volume from before inodes moved into the tree. Rejecting
    // it here is the clean break: there is no reader for that layout left.
    if (adytumfs_read_le64(block + 40) || adytumfs_read_le64(block + 48))
        return -1;
    super->inode_next = adytumfs_read_le64(block + 56);
    super->root_inode = adytumfs_read_le64(block + 64);
    super->data_start = adytumfs_read_le64(block + 72);
    super->free_blocks = adytumfs_read_le64(block + 80);
    super->live_inodes = adytumfs_read_le64(block + 88);
    super->generation = adytumfs_read_le64(block + 96);
    super->feature_compat = adytumfs_read_le64(block + 104);
    super->feature_incompat = adytumfs_read_le64(block + 112);
    super->feature_ro_compat = adytumfs_read_le64(block + 120);
    super->data_end = adytumfs_read_le64(block + 128);
    super->index_start = adytumfs_read_le64(block + 136);
    super->index_blocks = adytumfs_read_le64(block + 144);
    for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
        super->inode_root[byte] = block[160 + byte];
    // The slot is runtime state, not on-disk state: the primary superblock is
    // the default guess, and the mount picker overrides it when the tail copy
    // wins on generation.
    super->active_slot = 0;
    return 0;
}

int adytumfs_super_valid(const struct adytumfs_superblock *super,
                         u64 device_blocks) {
    // The layout is one incompatible package, so the mask must match exactly:
    // a missing bit is a volume this build cannot interpret, and an extra bit
    // is one a future build wrote and this one must not guess at. A v2 mask is
    // a missing bit, which is the clean break: there is no migration path.
    if (super->feature_incompat !=
        (ADYTUMFS_FEATURE_INCOMPAT_V3 |
         ADYTUMFS_FEATURE_INCOMPAT_NO_CKSUM_REGION |
         ADYTUMFS_FEATURE_INCOMPAT_ITEM_INODES))
        return -1;
    if (super->block_size != ADYTUMFS_BLOCK_SIZE) return -1;
    if (super->total_blocks > device_blocks) return -1;

    // Regions sit in the fixed order block 0 (super), bitmap, then data, up to
    // total_blocks. The inode table is gone: inodes are items in a tree that
    // grows inside the data region like anything else it holds. Each bound is
    // checked with subtraction so a crafted size cannot overflow the addition.
    if (super->block_bitmap_start != 1) return -1;
    // The bitmap covers exactly one bit per block of the volume; a spare
    // window would be state this format never writes.
    if (super->block_bitmap_blocks !=
        (super->total_blocks + (u64)ADYTUMFS_BLOCK_SIZE * 8u - 1u) /
            ((u64)ADYTUMFS_BLOCK_SIZE * 8u))
        return -1;
    if (super->data_start !=
        super->block_bitmap_start + super->block_bitmap_blocks)
        return -1;
    if (super->data_start >= super->total_blocks) return -1;

    // Slot 0 is the null inode and numbering starts at 1, so a formatted
    // volume has handed out at least the root. There is no upper bound to
    // check against: the tree grows and the number is only a high-water mark.
    if (super->inode_next < 2) return -1;
    if (super->root_inode == 0 || super->root_inode >= super->inode_next)
        return -1;
    if (super->live_inodes == 0 || super->live_inodes >= super->inode_next)
        return -1;
    // The tail grows backwards from the last block: shadow superblock, then
    // shadow bitmap. Every bound is derived with the prefix checks above
    // already in place, so the subtraction cannot underflow.
    u64 tail_base = super->total_blocks - 1 - super->block_bitmap_blocks;
    if (super->data_end < super->data_start + 1 ||
        super->data_end > tail_base)
        return -1;
    // The index sits inside the data region, reserved at format time and
    // marked allocated in the bitmap. Block zero of the region is its header,
    // so a region of one block would hold no entries at all, and a region
    // reaching past the data end would send the first tree lookup somewhere
    // the volume never wrote.
    if (super->index_blocks < 2u) return -1;
    if (super->index_start < super->data_start ||
        super->index_blocks >
            super->data_end - super->index_start)
        return -1;
    return 0;
}


// Read the newest sound superblock of the generation pair: the primary in
// block 0 and the backup in the last block of the volume. The backup
// position is only known from a readable primary when the volume is smaller
// than its device, so an unreadable primary falls back to the last device
// block. Sound means the checksum verified, so the generation field can be
// trusted: a torn flip fails the checksum here and the older generation is
// the one picked. A sound copy that still fails structural validation is
// different: the volume was committed past that point, so falling back to
// the older generation would roll the mount back over the damage. The mount
// fails instead, leaving both generations for an explicit repair pass.
int adytumfs_super_read(struct kernel_object *device,
                        struct adytumfs_superblock *super) {
    if (!device || !super) return -1;
    struct block_info info;
    if (block_info(device, &info)) return -1;
    u64 device_blocks = info.sector_count / ADYTUMFS_SECTORS_PER_BLOCK;
    if (device_blocks < 1) return -1;
    // A 4 KiB staging block is too large for a modest stack, and the read
    // path is single threaded.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock pair[2];
    u8 sound[2] = {0, 0};
    u8 valid[2] = {0, 0};
    if (!adytumfs_block_read(device, 0, block) &&
        !adytumfs_super_unpack(&pair[0], block)) {
        sound[0] = 1;
        valid[0] = !adytumfs_super_valid(&pair[0], device_blocks);
    }
    u64 backup = valid[0] ? pair[0].total_blocks - 1 : device_blocks - 1;
    if (backup > 0 &&
        !adytumfs_block_read(device, backup, block) &&
        !adytumfs_super_unpack(&pair[1], block)) {
        sound[1] = 1;
        valid[1] = !adytumfs_super_valid(&pair[1], device_blocks);
    }
    // A tie means format time twins; the primary wins so a fresh volume has
    // one deterministic answer.
    u8 pick = 0;
    if (sound[1] && (!sound[0] || pair[1].generation > pair[0].generation))
        pick = 1;
    if (!sound[pick] || !valid[pick]) return -1;
    *super = pair[pick];
    super->active_slot = pick;
    return 0;
}
