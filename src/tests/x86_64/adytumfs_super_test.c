#include "types.h"
#include "adytumfs_format.h"

int test_adytumfs_super64(void) {
    // A 4 KiB block is too big for a modest stack, and this test is single
    // threaded, so the scratch block is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    // The tail grows backwards from block 1023: shadow superblock, then shadow
    // bitmap (1), so the data region is [2, 1022). There is no inode table in
    // the layout: inodes are items in a tree that grows inside the data region.
    struct adytumfs_superblock super = {
        .format_version = ADYTUMFS_FORMAT_VERSION,
        .block_size = ADYTUMFS_BLOCK_SIZE,
        .total_blocks = 1024,
        .block_bitmap_start = 1,
        .block_bitmap_blocks = 1,
        .inode_next = 2,
        .root_inode = ADYTUMFS_ROOT_INODE,
        .data_start = 2,
        .free_blocks = 999,
        .live_inodes = 1,
        .generation = 1,
        .feature_compat = 0,
        .feature_incompat = ADYTUMFS_FEATURE_INCOMPAT_V3 |
                            ADYTUMFS_FEATURE_INCOMPAT_NO_CKSUM_REGION |
                            ADYTUMFS_FEATURE_INCOMPAT_ITEM_INODES,
        .feature_ro_compat = 0,
        .data_end = 1022,
        .index_start = 2,
        .index_blocks = 21,
        .inode_root = {0xa5, 0x5a, 0x11, 0xee},
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
        decoded.inode_next == super.inode_next &&
        decoded.root_inode == super.root_inode &&
        decoded.data_start == super.data_start &&
        decoded.free_blocks == super.free_blocks &&
        decoded.live_inodes == super.live_inodes &&
        decoded.generation == super.generation &&
        decoded.feature_incompat == super.feature_incompat &&
        decoded.data_end == super.data_end &&
        decoded.index_start == super.index_start &&
        decoded.index_blocks == super.index_blocks;
    // The tree root is the one field with no numeric bound to catch a field
    // that silently stopped being written, so it is compared byte for byte.
    for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
        valid = valid && decoded.inode_root[byte] == super.inode_root[byte];

    // The checksum must catch a single flipped byte, and a broken signature
    // must be rejected before anything else.
    block[200] ^= 0x40u;
    valid = valid && adytumfs_super_unpack(&decoded, block) != 0;
    adytumfs_super_pack(block, &super);
    block[0] = 'X';
    valid = valid && adytumfs_super_unpack(&decoded, block) != 0;

    // Bounds validation rejects a root the volume never handed out, an
    // allocator that has issued no numbers at all, a live count that is zero
    // or larger than everything ever allocated, a data span that runs into the
    // tail or collapses to nothing, and an unknown incompatible feature bit.
    struct adytumfs_superblock bad = super;
    bad.root_inode = super.inode_next;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.inode_next = 1;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.live_inodes = 0;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.live_inodes = super.inode_next;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.data_end = 1023;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.data_end = super.data_start;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.feature_incompat = ADYTUMFS_FEATURE_INCOMPAT_V3 |
                           ADYTUMFS_FEATURE_INCOMPAT_NO_CKSUM_REGION |
                           ADYTUMFS_FEATURE_INCOMPAT_ITEM_INODES | 0x10u;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;

    // The clean break: the v2 mask is not a smaller v3, it is a volume this
    // build refuses to interpret at all.
    bad = super;
    bad.feature_incompat = ADYTUMFS_FEATURE_INCOMPAT_V2;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;

    // The index region is part of the layout, so a header with no entries, one
    // that starts below the data region, one that starts so high the region
    // cannot fit, and one that runs past the data end are all volumes the
    // formatter never wrote.
    bad = super;
    bad.index_blocks = 1;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.index_start = super.data_start - 1;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.index_start = super.data_end - 1;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;
    bad = super;
    bad.index_blocks = super.data_end - super.data_start + 1;
    valid = valid && adytumfs_super_valid(&bad, 1024) != 0;

    return valid ? 0 : -1;
}
