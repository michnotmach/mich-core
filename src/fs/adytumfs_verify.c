#include "types.h"
#include "adytumfs_format.h"

// Mount time audit of the on-disk allocation state. The superblock and the
// inode table are checksummed, but the bitmap is not, and the allocation
// truth is stored three times: bitmap bits, inode extents, and the superblock
// counters. A volume is only mountable when the views agree, so a forged or
// corrupted extent cannot reach the metadata prefix, the checksum region and
// the shadow tail, or another file's blocks.

#define ADYTUMFS_VERIFY_CLAIMS_MAX \
    ((u32)ADYTUMFS_INODE_TABLE_BLOCKS_MAX * ADYTUMFS_INODES_PER_BLOCK * \
     ADYTUMFS_DIRECT_EXTENTS)

struct verify_claim {
    u64 start;
    u32 length;
};

// One claim per live extent of every used inode. The table cap bounds this at
// 2560 entries (40 KiB), well past a modest stack, and the mount path is
// single threaded, so the ledger is static.
static struct verify_claim verify_claims[ADYTUMFS_VERIFY_CLAIMS_MAX];
static u32 verify_claim_count;

// One 4 KiB bitmap window serves every bit test of a scan that moves in
// volume order, so a window is re-read only when an address jumps.
static u8 verify_bitmap[ADYTUMFS_BLOCK_SIZE];
static u64 verify_bitmap_window;

static int verify_bit(struct kernel_object *device,
                      const struct adytumfs_superblock *super, u64 block) {
    u64 window = block / ((u64)ADYTUMFS_BLOCK_SIZE * 8u);
    if (window >= super->block_bitmap_blocks) return -1;
    if (window != verify_bitmap_window) {
        if (adytumfs_block_read(device,
                                adytumfs_bitmap_block(super, (u32)window),
                                verify_bitmap))
            return -1;
        verify_bitmap_window = window;
    }
    u64 offset = block % ((u64)ADYTUMFS_BLOCK_SIZE * 8u);
    return (verify_bitmap[offset / 8] >> (offset % 8)) & 1u;
}

int adytumfs_verify(struct kernel_object *device,
                    const struct adytumfs_superblock *super) {
    if (!device || !super) return -1;
    verify_claim_count = 0;
    verify_bitmap_window = ~(u64)0;
    u64 free_inodes = 0;
    u64 claimed = 0;
    // The index region is reserved metadata that happens to sit inside the
    // data span. It is allocated at format time and no inode owns it, so it
    // stays out of both sides of the allocation ledger.
    u64 index_end = super->index_start + super->index_blocks;

    // An unreachable inode still owns its blocks, and a used slot with a
    // broken body means the table itself is lying, so every used slot is
    // audited, not only the tree the mount will walk.
    for (u64 inode = 1; inode < super->inode_count; inode++) {
        struct adytumfs_inode in;
        if (adytumfs_inode_read(device, super, inode, &in)) return -1;
        if (!in.mode) {
            free_inodes++;
            continue;
        }
        u32 bits = in.mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG |
                              ADYTUMFS_MODE_LNK);
        if (bits != ADYTUMFS_MODE_DIR && bits != ADYTUMFS_MODE_REG &&
            bits != ADYTUMFS_MODE_LNK)
            return -1;
        u32 terminated = 0;
        u64 mapped = 0;
        for (u32 index = 0; index < ADYTUMFS_DIRECT_EXTENTS; index++) {
            u32 length = in.direct[index].length;
            // Extents are packed from the front and a zero length ends the
            // list, so an entry behind the terminator is a layout this format
            // never writes.
            if (!length) {
                terminated = 1;
                continue;
            }
            if (terminated) return -1;
            u64 start = in.direct[index].start_block;
            // The metadata prefix and the whole tail from the checksum region
            // on are never handed out by the allocator, so an extent reaching
            // either is forged. The bound is written as a subtraction so a
            // crafted start cannot overflow the addition.
            if (start < super->data_start ||
                start >= super->data_checksum_region ||
                length > super->data_checksum_region - start)
                return -1;
            // An extent reaching the index would let a file overwrite the
            // structure every hash lookup resolves through.
            if (start < index_end && start + length > super->index_start)
                return -1;
            if (verify_claim_count >= ADYTUMFS_VERIFY_CLAIMS_MAX) return -1;
            verify_claims[verify_claim_count].start = start;
            verify_claims[verify_claim_count].length = length;
            verify_claim_count++;
            mapped += length;
        }
        if (in.blocks != mapped) return -1;
        // Size is deliberately not audited: the write path persists a grown
        // size before the matching block count lands, and reads clamp to the
        // mapped blocks anyway.
    }

    // The metadata prefix, the reserved index region, and the tail from the
    // checksum region on must stay allocated, and every allocated data block
    // must belong to an extent.
    u64 allocated = 0;
    for (u64 block = 0; block < super->total_blocks; block++) {
        int bit = verify_bit(device, super, block);
        if (bit < 0) return -1;
        if (block < super->data_start ||
            block >= super->data_checksum_region ||
            (block >= super->index_start && block < index_end)) {
            if (!bit) return -1;
            continue;
        }
        if (bit) allocated++;
    }
    for (u32 index = 0; index < verify_claim_count; index++) {
        u64 start = verify_claims[index].start;
        for (u64 block = start; block < start + verify_claims[index].length;
             block++)
            if (verify_bit(device, super, block) != 1) return -1;
        claimed += verify_claims[index].length;
    }
    // No two extents may share a block, or two files would write through one
    // allocation behind each other's backs.
    for (u32 outer = 0; outer < verify_claim_count; outer++)
        for (u32 inner = outer + 1; inner < verify_claim_count; inner++)
            if (verify_claims[outer].start <
                    verify_claims[inner].start + verify_claims[inner].length &&
                verify_claims[inner].start <
                    verify_claims[outer].start + verify_claims[outer].length)
                return -1;
    // With no overlap and every claim on an allocated bit, equal totals make
    // the claims and the allocated data blocks the same set, so no block is
    // leaked and none is claimed while free.
    if (claimed != allocated) return -1;
    if (super->free_inodes != free_inodes) return -1;
    // The allocatable span ends at the checksum region, not at the backup
    // superblock, and the reserved index is not allocatable either, so the
    // free count is taken against the span the allocator can actually reach.
    if (super->free_blocks !=
        super->data_checksum_region - super->data_start - super->index_blocks -
            allocated)
        return -1;
    return 0;
}
