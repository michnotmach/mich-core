#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"
#include "adytumfs_index.h"
#include "blake2b.h"

// The mount audit is the last thing standing between a damaged volume and a
// mount that trusts it. It keeps three copies of the allocation truth in
// agreement: bitmap bits, the location index, and the superblock counters.
// Each
// corruption below breaks exactly one of the three. A lie confined to the
// index is one the committed generation can still account for, so the mount
// rebuilds it and the rebuilt index has to come back true rather than merely
// accepted. Everything else has to be refused, because a mount that takes it
// goes on to write through the disagreement.

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
    static struct adytumfs_cas store;
    struct adytumfs_superblock super;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_super_read(dev, &super) == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    // A formatted volume balances at zero: the reserved index is allocated and
    // owned by nobody, and the audit has to know that or it would report the
    // reservation as a leak on every mount.
    valid = valid && adytumfs_verify(dev, &super) == 0;

    // Give one file three blocks through the tree, then commit, so the bitmap,
    // the index, and the counters all reach the device the audit reads. What
    // lands is one block of zeroes and the leaf that names it, because a hole
    // is a run of identical blocks and the format says the hash repeats every
    // block of them.
    u64 number = 0;
    u64 second = 0;
    struct adytumfs_inode file;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u,
                             &number) == 0 &&
        adytumfs_inode_read(dev, &super, number, &file) == 0 &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u,
                             &second) == 0 &&
        adytumfs_inode_grow(dev, &super, &store, &file, number, 3) == 0 &&
        adytumfs_commit(dev, &super) == 0 &&
        // The commit flips the active slot, and unpack always guesses slot
        // zero, so the generation has to be picked the way the mount picks it
        // or the audit reads one generation's numbers against another's data.
        adytumfs_super_read(dev, &super) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    u8 key[ADYTUMFS_HASH_SIZE];
    u64 claimed = 0;
    valid = valid && adytumfs_zero_hash(key) == 0 &&
        adytumfs_cas_lookup(dev, &super, &store, key, &claimed) == 0;

    // A mapping reaching into the index would let file content overwrite the
    // structure every hash lookup resolves through. The bitmap bit is already
    // set, so only the location is wrong, and the location is exactly what the
    // rebuild recovers: the block still holds the content its own hash names.
    // So the mount takes the volume, and what has to come back is the true
    // mapping carrying the one reference the leaf owes it, not the forgery.
    static struct adytumfs_cas probe_store;
    u64 resolved = 0;
    u32 refs = 0;
    valid = valid &&
        adytumfs_index_repoint(dev, &store.index, key,
                               super.index_start) == 0 &&
        adytumfs_verify(dev, &super) == 0;
    adytumfs_cas_open(&probe_store, super.index_start, super.index_blocks);
    valid = valid &&
        adytumfs_index_fetch(dev, &probe_store.index, key, &resolved,
                             &refs) == 0 &&
        resolved == claimed && refs == 1u &&
        adytumfs_verify(dev, &super) == 0;

    // A block a mapping names but the bitmap says is free would be handed to
    // a second owner by the allocator.
    valid = valid && bitmap_flip(dev, &super, claimed, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        bitmap_flip(dev, &super, claimed, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // The superblock free count is audited against what the bitmap and the
    // index actually hold.
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
    // match leaves the totals as the only thing that disagrees: one more block
    // is allocated than any content names, and nothing else can see it.
    u64 stray = 0;
    valid = valid && adytumfs_block_read(dev, adytumfs_bitmap_block(&super, 0),
                                         block) == 0;
    for (u64 scan = super.data_start; valid &&
         scan < super.data_end; scan++)
        if (!(block[scan / 8] & (u8)(1u << (scan % 8)))) {
            stray = scan;
            break;
        }
    struct adytumfs_superblock balanced = super;
    balanced.free_blocks = super.free_blocks - 1;
    valid = valid && stray &&
        bitmap_flip(dev, &super, stray, block) == 0 &&
        super_rewrite(dev, &balanced, block) == 0 &&
        adytumfs_super_read(dev, &probe) == 0 &&
        adytumfs_verify(dev, &probe) != 0 &&
        super_rewrite(dev, &super, block) == 0 &&
        bitmap_flip(dev, &super, stray, block) == 0 &&
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

    // A mode that is neither directory, regular, nor symlink is a table lying
    // about what it holds.
    struct adytumfs_inode odd = file;
    odd.mode = 0777u;
    valid = valid && inode_rewrite(dev, &super, number, &odd, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        inode_rewrite(dev, &super, number, &file, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;

    // The v2 case for an extent behind the zero length terminator has no
    // counterpart here, and that is the point: a zero length entry is
    // unrepresentable, so there is no terminator to hide anything behind.

    // A block count that disagrees with the bytes the tree covers is a file
    // that believes it is longer than the space it holds.
    struct adytumfs_inode short_count = file;
    short_count.blocks = 2;
    valid = valid &&
        inode_rewrite(dev, &super, number, &short_count, block) == 0 &&
        adytumfs_verify(dev, &super) != 0 &&
        inode_rewrite(dev, &super, number, &file, block) == 0 &&
        adytumfs_verify(dev, &super) == 0;


    // Two mappings naming one block means two writers share a single
    // allocation. The bitmap counts the block once, so the mapping count is
    // what disagrees, and the audit needs no pairwise comparison to see it.
    // The forgery survives the rebuild only as the duplicate it is: the block
    // is rehashed once, so what comes back is the single mapping its content
    // earns and the twin is gone with the reference it took.
    // The forged entry takes a reference first: a bare insert leaves refs at
    // zero and the audit would reject the entry for that rather than for the
    // count. Dropping the reference again is not an option either, because it
    // would hand the block back while the tree still names it, so this is the
    // last thing the test does to the volume.
    u8 twin[ADYTUMFS_HASH_SIZE];
    u64 live_before = 0;
    u64 live_after = 0;
    valid = valid && adytumfs_block_read(dev, claimed, block) == 0;
    block[0] ^= 0x5au;
    valid = valid &&
        blake2b(twin, ADYTUMFS_HASH_SIZE, block, ADYTUMFS_BLOCK_SIZE) == 0 &&
        adytumfs_index_live(dev, &store.index, &live_before) == 0 &&
        adytumfs_index_insert(dev, &store.index, twin, claimed) == 0 &&
        adytumfs_cas_retain(dev, &super, &store, twin) == 0 &&
        adytumfs_verify(dev, &super) == 0;
    adytumfs_cas_open(&probe_store, super.index_start, super.index_blocks);
    valid = valid &&
        adytumfs_index_live(dev, &probe_store.index, &live_after) == 0 &&
        live_after == live_before &&
        adytumfs_cas_lookup(dev, &super, &probe_store, twin, &resolved) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
