#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"

// The mount audit is the last thing standing between a damaged volume and a
// mount that trusts it. It keeps three copies of the allocation truth in
// agreement: bitmap bits, inode extents, and the superblock counters. Each
// corruption below breaks exactly one of the three and has to be refused,
// because a mount that accepts it goes on to write through the disagreement.

static int bitmap_flip(struct kernel_object *dev,
                       const struct adytumfs_superblock *super, u64 at,
                       u8 *scratch) {
    u32 which = adytumfs_bitmap_block(super, 0);
    if (adytumfs_block_read(dev, which, scratch)) return -1;
    scratch[at / 8] ^= (u8)(1u << (at % 8));
    return adytumfs_block_write(dev, which, scratch);
}

static int super_rewrite(struct kernel_object *dev,
                         const struct adytumfs_superblock *super, u8 *scratch) {
    adytumfs_super_pack(scratch, super);
    return adytumfs_block_write(dev, adytumfs_superblock_block(super), scratch);
}

// Rewrite one slot straight onto the device, past the window, so the audit
// reads the forgery rather than a staged copy of it.
static int inode_rewrite(struct kernel_object *dev,
                         const struct adytumfs_superblock *super, u64 number,
                         const struct adytumfs_inode *in, u8 *scratch) {
    u32 which = adytumfs_table_block(super,
                                     (u32)(number / ADYTUMFS_INODES_PER_BLOCK));
    if (adytumfs_block_read(dev, which, scratch)) return -1;
    adytumfs_inode_pack(
        scratch + (number % ADYTUMFS_INODES_PER_BLOCK) * ADYTUMFS_INODE_SIZE,
        in);
    return adytumfs_block_write(dev, which, scratch);
}

int test_adytumfs_verify64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(4096, 0);
    // A 4 KiB block is too big for a modest stack, and this test is single
    // threaded, so the scratch block is static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_super_read(dev, &super) == 0;

    // A formatted volume balances at zero: the reserved index is allocated and
    // owned by nobody, and the audit has to know that or it would report the
    // reservation as a leak on every mount.
    valid = valid && adytumfs_verify(dev, &super) == 0;

    // Claim three blocks with an extent on a properly allocated inode, then
    // commit, so the bitmap, the table, and the counters all reach the device
    // the audit reads.
    u64 run = 0;
    u64 first_free = super.index_start + super.index_blocks;
    u64 number = 0;
    u64 second = 0;
    struct adytumfs_inode file;
    valid = valid &&
        adytumfs_alloc_run(dev, &super, 3, &run) == 0 && run == first_free &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u,
                             &number) == 0 &&
        adytumfs_inode_read(dev, &super, number, &file) == 0 &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u,
                             &second) == 0;
    file.size = 3 * ADYTUMFS_BLOCK_SIZE;
    file.blocks = 3;
    file.direct[0].start_block = run;
    file.direct[0].length = 3;
    valid = valid && adytumfs_inode_write(dev, &super, number, &file) == 0 &&
        adytumfs_commit(dev, &super) == 0 &&
        // The commit flips the active slot, and unpack always guesses slot
        // zero, so the generation has to be picked the way the mount picks it
        // or the audit reads one generation's numbers against another's data.
        adytumfs_super_read(dev, &super) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // The ledger is live, not a formality: clearing one claimed bit leaves an
    // extent pointing at a free block.
    valid = valid && bitmap_flip(dev, &super, run + 1, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        bitmap_flip(dev, &super, run + 1, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // Setting a bit nothing claims is a leak.
    valid = valid && bitmap_flip(dev, &super, run + 9, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        bitmap_flip(dev, &super, run + 9, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // Clearing a bit inside the reserved index is corruption of a different
    // kind: the region must stay allocated, or the allocator hands out the
    // structure every hash lookup resolves through.
    valid = valid && bitmap_flip(dev, &super, super.index_start, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        bitmap_flip(dev, &super, super.index_start, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // The free count is the third copy of the truth. The lie is written to the
    // device and read back the way a mount reads it, so what the audit is
    // handed is what the volume actually claims.
    struct adytumfs_superblock lying = super;
    lying.free_blocks = super.free_blocks + 1;
    struct adytumfs_superblock probe;
    valid = valid && super_rewrite(dev, &lying, block) == 0 &&
        adytumfs_super_read(dev, &probe) == 0 &&
        probe.free_blocks == lying.free_blocks &&
        adytumfs_verify(dev, &probe) != 0 &&
        super_rewrite(dev, &super, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // A stray bit on its own trips the free count as well, so it does not
    // prove the ledger is checked. Setting the bit and correcting the count to
    // match leaves the totals as the only thing that disagrees: three blocks
    // are claimed, four are allocated, and nothing else can see it.
    struct adytumfs_superblock balanced = super;
    balanced.free_blocks = super.free_blocks - 1;
    valid = valid && bitmap_flip(dev, &super, run + 9, block) == 0 &&
        super_rewrite(dev, &balanced, block) == 0 &&
        adytumfs_super_read(dev, &probe) == 0 &&
        adytumfs_verify(dev, &probe) != 0 &&
        super_rewrite(dev, &super, block) == 0 &&
        bitmap_flip(dev, &super, run + 9, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // The inode counter is audited the same way: a volume that claims a
    // different number of free slots than the table holds is lying about one
    // of the two.
    struct adytumfs_superblock inodes_lie = super;
    inodes_lie.free_inodes = super.free_inodes - 1;
    valid = valid && super_rewrite(dev, &inodes_lie, block) == 0 &&
        adytumfs_super_read(dev, &probe) == 0 &&
        adytumfs_verify(dev, &probe) != 0 &&
        super_rewrite(dev, &super, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // An extent reaching into the index would let a file overwrite it. The
    // bitmap bits are already set, so only the claim is wrong.
    struct adytumfs_inode thief = file;
    thief.direct[0].start_block = super.index_start;
    valid = valid && inode_rewrite(dev, &super, number, &thief, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        inode_rewrite(dev, &super, number, &file, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // Two extents sharing a block means two files write through one
    // allocation. The bitmap counts the block once, so the claim total is what
    // disagrees.
    struct adytumfs_inode twin;
    valid = valid && adytumfs_inode_read(dev, &super, second, &twin) == 0;
    twin.blocks = 1;
    twin.direct[0].start_block = run + 2;
    twin.direct[0].length = 1;
    valid = valid && inode_rewrite(dev, &super, second, &twin, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        inode_rewrite(dev, &super, second, &(struct adytumfs_inode){
            .mode = ADYTUMFS_MODE_REG | 0644u, .links = 1, .generation = 1},
            block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // A mode that is neither directory, regular, nor symlink is a table lying
    // about what it holds.
    struct adytumfs_inode odd = file;
    odd.mode = 0777u;
    valid = valid && inode_rewrite(dev, &super, number, &odd, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        inode_rewrite(dev, &super, number, &file, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // An extent behind the terminator is a layout the format never writes.
    struct adytumfs_inode sparse = file;
    sparse.direct[0].length = 1;
    sparse.blocks = 3;
    sparse.direct[2].start_block = run + 1;
    sparse.direct[2].length = 2;
    valid = valid && inode_rewrite(dev, &super, number, &sparse, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        inode_rewrite(dev, &super, number, &file, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // A block count that disagrees with the extents is a file that believes it
    // is longer than the space it holds.
    struct adytumfs_inode short_count = file;
    short_count.blocks = 2;
    valid = valid &&
        inode_rewrite(dev, &super, number, &short_count, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        inode_rewrite(dev, &super, number, &file, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
