#include "types.h"
#include "adytumfs_format.h"
#include "adytumfs_index.h"
#include "adytumfs_cas.h"
#include "adytumfs_tree.h"
#include "crypto.h"

// Mount time audit of the on-disk allocation state. The superblock and the
// inode table are checksummed, but the bitmap is not, and the allocation
// truth is stored three times: bitmap bits, the location index, and the
// superblock counters. A volume is only mountable when the three agree, so a
// forged or corrupted mapping cannot reach the metadata prefix, the checksum
// region and the shadow tail, or another file's blocks.
//
// The index replaces the extent ledger v2 walked, and it makes the audit
// stronger rather than weaker. Two entries naming one block, which is how two
// files would write through a single allocation behind each other's backs,
// shows up as the live count exceeding the allocated count, and a block marked
// allocated that no content names shows up as the reverse. Equality of the two
// counts is therefore the whole no-overlap and no-orphan condition, with no
// pairwise comparison and no ledger to bound.

// One 4 KiB bitmap window serves every bit test of a scan that moves in
// volume order, so a window is re-read only when an address jumps.
static u8 verify_bitmap[ADYTUMFS_BLOCK_SIZE];
static u64 verify_bitmap_window;

#define VERIFY_STACK_MAX \
    ((u32)ADYTUMFS_TREE_DEPTH_MAX * ADYTUMFS_TREE_BRANCH_MAX)

// Total bytes an extent tree covers, which is what the inode's block count has
// to agree with. The walk is iterative because a recursive one would share the
// node buffer with itself and the first call down would clobber the parent's
// entries. Each node is checked against the hash its parent promised, which is
// the same check the read path makes, so a tree that audits is a tree that
// reads.
static int verify_tree_bytes(struct kernel_object *device,
                             struct adytumfs_superblock *super,
                             struct adytumfs_cas *store, const u8 *root,
                             u64 *total) {
    static u8 stack[VERIFY_STACK_MAX][ADYTUMFS_HASH_SIZE];
    static u8 node[ADYTUMFS_BLOCK_SIZE];
    u8 hash[ADYTUMFS_HASH_SIZE];
    u8 check[ADYTUMFS_HASH_SIZE];
    u32 top = 0;
    *total = 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        stack[top][index] = root[index];
    top = 1u;
    while (top) {
        top--;
        for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
            hash[index] = stack[top][index];
        u64 block = 0;
        if (adytumfs_cas_lookup(device, super, store, hash, &block)) return -1;
        if (adytumfs_block_read(device, block, node)) return -1;
        if (adytumfs_tree_node_hash(node, check)) return -1;
        for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
            if (hash[index] != check[index]) return -1;
        u32 level = adytumfs_read_le32(node + 4);
        if (level > 1u) return -1;
        if (adytumfs_tree_node_check(node, level)) return -1;
        u32 count = adytumfs_read_le32(node + 8);
        u32 stride = level ? ADYTUMFS_TREE_BRANCH_ENTRY_SIZE
                           : ADYTUMFS_TREE_LEAF_ENTRY_SIZE;
        for (u32 index = 0; index < count; index++) {
            const u8 *at = node + ADYTUMFS_TREE_HEADER_SIZE + index * stride;
            if (!level) {
                *total += adytumfs_read_le64(at + ADYTUMFS_CAS_HASH_SIZE + 8);
                continue;
            }
            if (top >= VERIFY_STACK_MAX) return -1;
            for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
                stack[top][byte] = at[ADYTUMFS_TREE_KEY_SIZE + byte];
            top++;
        }
    }
    return 0;
}

// The same walk as the byte count, taking the reference each node owes on what
// it names instead of summing the leaves. It runs against an index the rebuild
// just filled with every mapping at zero references, so this walk is what puts
// the count the committed generation keeps alive back onto it.
static int verify_tree_refs(struct kernel_object *device,
                            struct adytumfs_superblock *super,
                            struct adytumfs_cas *store, const u8 *root) {
    static u8 stack[VERIFY_STACK_MAX][ADYTUMFS_HASH_SIZE];
    static u8 node[ADYTUMFS_BLOCK_SIZE];
    u8 hash[ADYTUMFS_HASH_SIZE];
    u8 check[ADYTUMFS_HASH_SIZE];
    u32 top = 0;
    for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
        stack[top][index] = root[index];
    top = 1u;
    while (top) {
        top--;
        for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
            hash[index] = stack[top][index];
        u64 block = 0;
        if (adytumfs_cas_lookup(device, super, store, hash, &block)) return -1;
        if (adytumfs_block_read(device, block, node)) return -1;
        if (adytumfs_tree_node_hash(node, check)) return -1;
        for (u32 index = 0; index < ADYTUMFS_HASH_SIZE; index++)
            if (hash[index] != check[index]) return -1;
        u32 level = adytumfs_read_le32(node + 4);
        if (level > 1u) return -1;
        if (adytumfs_tree_node_check(node, level)) return -1;
        u32 count = adytumfs_read_le32(node + 8);
        u32 stride = level ? ADYTUMFS_TREE_BRANCH_ENTRY_SIZE
                           : ADYTUMFS_TREE_LEAF_ENTRY_SIZE;
        for (u32 index = 0; index < count; index++) {
            const u8 *at = node + ADYTUMFS_TREE_HEADER_SIZE + index * stride;
            // The node names this hash, so the node holds the reference on it:
            // a child node for a branch and a content block for a leaf.
            if (adytumfs_cas_retain(device, super, store,
                                    at + ADYTUMFS_TREE_KEY_SIZE))
                return -1;
            if (!level) continue;
            if (top >= VERIFY_STACK_MAX) return -1;
            for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
                stack[top][byte] = at[ADYTUMFS_TREE_KEY_SIZE + byte];
            top++;
        }
    }
    return 0;
}

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

// Every live mapping has to name a block inside the allocatable span with its
// bitmap bit set, and there have to be exactly as many of them as there are
// allocated data blocks. Two entries naming one block makes the mapping count
// the larger of the two and a block nothing names makes it the smaller, so the
// equality is the no-overlap and no-orphan condition in one comparison.
static int verify_index(struct kernel_object *device,
                        const struct adytumfs_superblock *super, u64 index_end,
                        u64 allocated, u64 *live_out) {
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    u64 live = 0;
    for (u64 number = super->index_start + 1u;
         number < super->index_start + super->index_blocks; number++) {
        if (adytumfs_block_read(device, number, block)) return -1;
        if (adytumfs_read_le32(block) != ADYTUMFS_INDEX_MAGIC) return -1;
        for (u32 slot = 0; slot < ADYTUMFS_INDEX_PER_BLOCK; slot++) {
            const u8 *entry = block + ADYTUMFS_INDEX_HEADER_SIZE +
                (u64)slot * ADYTUMFS_INDEX_ENTRY_SIZE;
            // Only a live entry is a mapping. A released one keeps its hash
            // and becomes a tombstone so an open probe run stays unbroken,
            // and the hash alone would read as a mapping that names nothing.
            if (adytumfs_read_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 12) !=
                ADYTUMFS_INDEX_LIVE)
                continue;
            u64 target = adytumfs_read_le64(entry + ADYTUMFS_INDEX_HASH_SIZE);
            // A mapping with no reference is a leak the collection walk
            // missed, and mounting it would hide it for good.
            if (!adytumfs_read_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 8))
                return -1;
            if (target < super->data_start ||
                target >= super->data_checksum_region)
                return -1;
            // A mapping reaching the index would let file content overwrite
            // the structure every hash lookup resolves through.
            if (target >= super->index_start && target < index_end) return -1;
            if (verify_bit(device, super, target) != 1) return -1;
            live++;
        }
    }
    *live_out = live;
    return live == allocated ? 0 : -1;
}

// Rebuild the index from the generation the superblock actually points at.
//
// The index is written through, outside the two generation slots: a mapping is
// recorded the moment a block is placed and tombstoned the moment its last
// reference goes. A commit that dies before the flipped superblock lands
// therefore leaves the committed generation naming hashes the index has
// already dropped. Nothing on disk is lost by that, because the committed
// generation still names a block for every hash its trees hold, so the mount
// rebuilds the index rather than refusing a volume it can repair.
//
// A tree entry carries the content hash and the length, never the block, so
// the mapping cannot be read back out of the trees alone. It is recovered by
// rehashing every allocated block, which costs one read and one hash per block
// and needs no extra structure on disk.
static int rebuild_index(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store) {
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    u8 hash[ADYTUMFS_HASH_SIZE];
    u64 index_end = super->index_start + super->index_blocks;
    if (adytumfs_index_format(device, super, &store->index)) return -1;
    // Formatting leaves the store cache describing an index that no longer
    // exists, and a stale hit would resolve a hash to a block nothing maps.
    adytumfs_cas_open(store, super->index_start, super->index_blocks);
    verify_bitmap_window = ~(u64)0;
    // The reserved index region is allocated metadata no inode owns, so it is
    // outside the scan for the same reason it is outside the audit counts.
    for (u64 number = super->data_start; number < super->data_checksum_region;
         number++) {
        if (number >= super->index_start && number < index_end) continue;
        int bit = verify_bit(device, super, number);
        if (bit < 0) return -1;
        if (!bit) continue;
        if (adytumfs_block_read(device, number, block)) return -1;
        if (adytumfs_tree_node_hash(block, hash)) return -1;
        // A content address names one block, so a second allocated block
        // hashing to a value already mapped is corruption. Inserting refuses
        // the duplicate instead of repointing it, which fails the rebuild.
        if (adytumfs_index_insert(device, super, &store->index, hash, number))
            return -1;
    }
    // Every mapping now sits at zero references. The trees put the real count
    // back: a node holds a reference on everything it names, and the inode
    // holds the one on the root of its own tree.
    for (u64 inode = 1; inode < super->inode_count; inode++) {
        struct adytumfs_inode in;
        if (adytumfs_inode_read(device, super, inode, &in)) return -1;
        if (!in.mode) continue;
        if (adytumfs_tree_root_empty(in.extent_root)) continue;
        if (adytumfs_cas_retain(device, super, store, in.extent_root))
            return -1;
        if (verify_tree_refs(device, super, store, in.extent_root)) return -1;
    }
    return 0;
}

// One pass of the audit. The store belongs to the caller because the pass that
// follows a rebuild has to see the index that rebuild just wrote.
static int verify_volume(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store) {
    if (!device || !super || !store) return -1;
    verify_bitmap_window = ~(u64)0;
    u64 free_inodes = 0;
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
        // An inode names the root of its extent tree. All zero is the empty
        // tree, which only a file with no blocks may hold, and anything else
        // has to resolve and cover exactly the blocks the inode claims.
        int empty = adytumfs_tree_root_empty(in.extent_root);
        if (empty ? in.blocks != 0 : in.blocks == 0) return -1;
        u64 mapped = 0;
        if (!empty && verify_tree_bytes(device, super, store, in.extent_root,
                                        &mapped))
            return -1;
        if (mapped != in.blocks * ADYTUMFS_BLOCK_SIZE) return -1;
        // Size is deliberately not audited: the write path persists a grown
        // size before the matching block count lands, and reads clamp to the
        // mapped blocks anyway.
    }

    // The metadata prefix, the reserved index region, and the tail from the
    // checksum region on must stay allocated, and every allocated data block
    // must be named by exactly one mapping in the index.
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
    u64 live = 0;
    if (verify_index(device, super, index_end, allocated, &live)) return -1;
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

// A volume that fails the audit on the index is not necessarily lost. The
// index is the one part of the allocation state written outside the generation
// scheme, so an interrupted commit leaves it describing a generation that was
// never committed while the committed one still stands. Rebuilding it from the
// committed trees costs one pass over the allocated blocks and recovers the
// volume, so the mount does that and audits again. Anything the rebuild cannot
// account for shows up in the second pass and still refuses the mount.
int adytumfs_verify(struct kernel_object *device,
                    struct adytumfs_superblock *super) {
    // The audit resolves extent trees, so it needs a store of its own: the
    // mount is not open yet and must not be, because a volume that fails the
    // audit is never mounted.
    static struct adytumfs_cas store;
    if (!device || !super) return -1;
    adytumfs_cas_open(&store, super->index_start, super->index_blocks);
    if (verify_volume(device, super, &store) == 0) return 0;
    if (rebuild_index(device, super, &store)) return -1;
    return verify_volume(device, super, &store);
}
