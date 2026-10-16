#include "types.h"
#include "adytumfs_format.h"

int test_adytumfs_super64(void) {
    // A 4 KiB block is too big for a modest stack, and this test is single
    // threaded, so the scratch block is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    // The tail grows backwards from block 1023: shadow superblock, shadow
    // bitmap (1), shadow table (4), so the checksum region starts at 1017 and
    // covers the 1011 data blocks [6, 1017).
    struct adytumfs_superblock super = {
        .format_version = ADYTUMFS_FORMAT_VERSION,
        .block_size = ADYTUMFS_BLOCK_SIZE,
        .total_blocks = 1024,
        .block_bitmap_start = 1,
        .block_bitmap_blocks = 1,
        .inode_table_start = 2,
        .inode_table_blocks = 4,
        .inode_count = 64,
        .root_inode = ADYTUMFS_ROOT_INODE,
        .data_start = 6,
        .free_blocks = 1011,
        .free_inodes = 63,
        .generation = 1,
        .feature_compat = 0,
        .feature_incompat = ADYTUMFS_FEATURE_INCOMPAT_V3 |
                            ADYTUMFS_FEATURE_INCOMPAT_NO_CKSUM_REGION,
        .feature_ro_compat = 0,
        .data_end = 1017,
        .index_start = 6,
        .index_blocks = 21,
    };

    adytumfs_super_pack(block, &super);

    // The signature lands raw at the front so a foreign tool can spot the volume.
    int valid = block[0] == 'A' && block[7] == 'S' &&
        adytumfs_super_valid(&super, 1024) == 0 &&
        adytumfs_super_valid(&super, 512) != 0;

    struct adytumfs_superblock decoded;
    valid = valid && adytumfs_super_unpack(&decoded, block) == 0 &&
        decoded.format_version == super.format_version &&
        decoded.block_size == super.block_size &&
        decoded.total_blocks == super.total_blocks &&
        decoded.block_bitmap_start == super.block_bitmap_start &&
        decoded.block_bitmap_blocks == super.block_bitmap_blocks &&
        decoded.inode_table_start == super.inode_table_start &&
        decoded.inode_table_blocks == super.inode_table_blocks &&
        decoded.inode_count == super.inode_count &&
        decoded.root_inode == super.root_inode &&
        decoded.data_start == super.data_start &&
        decoded.free_blocks == super.free_blocks &&
        decoded.free_inodes == super.free_inodes &&
        decoded.generation == super.generation &&
        decoded.feature_incompat == super.feature_incompat &&
        decoded.data_end == super.data_end &&
        decoded.index_start == super.index_start &&
        decoded.index_blocks == super.index_blocks;

    // The checksum must catch a single flipped byte, and a broken signature
    // must be rejected before anything else.
    block[200] ^= 0x40u;
    valid = valid && adytumfs_super_unpack(&decoded, block) != 0;
    adytumfs_super_pack(block, &super);
    block[0] = 'X';
    valid = valid && adytumfs_super_unpack(&decoded, block) != 0;

    // Bounds validation rejects an out-of-range root inode, a table that is
    // not where the fixed order demands, a checksum region that does not fit
    // its data span, and an unknown incompatible feature bit.
    struct adytumfs_superblock bad = super;
    bad.root_inode = super.inode_count;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.inode_table_start = 3;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.data_end = 1020;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.data_end = super.data_start;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.feature_incompat = ADYTUMFS_FEATURE_INCOMPAT_V3 |
                           ADYTUMFS_FEATURE_INCOMPAT_NO_CKSUM_REGION |
                           0x8u;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;

    // The clean break: the v2 mask is not a smaller v3, it is a volume this
    // build refuses to interpret at all.
    bad = super;
    bad.feature_incompat = ADYTUMFS_FEATURE_INCOMPAT_V2;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;

    // The index region is part of the layout, so a header with no entries, one
    // that starts above the data region, and one that runs into the checksum
    // region are all volumes the formatter never wrote.
    bad = super;
    bad.index_blocks = 1;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.index_start = super.inode_table_start;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.index_start = super.data_end - 1;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.index_blocks = super.data_end - super.data_start + 1;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;

    return valid ? 0 : -1;
}
