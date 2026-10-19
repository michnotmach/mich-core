#include "adytumfs_item.h"
#include "blake2b.h"

static u32 level_stride(u32 level) {
    return level ? ADYTUMFS_ITEM_BRANCH_SLOT_SIZE
                 : ADYTUMFS_ITEM_LEAF_SLOT_SIZE;
}

static u32 level_capacity(u32 level) {
    return level ? ADYTUMFS_ITEM_BRANCH_SLOT_MAX
                 : ADYTUMFS_ITEM_LEAF_SLOT_MAX;
}

// Objectid first so every item of one file sits together, type second so an
// inode item precedes the items describing it, offset last so extents come out
// in file order. The order is the one the on-disk format commits to.
static int key_compare(const struct adytumfs_item_key *a,
                       const struct adytumfs_item_key *b) {
    if (a->objectid < b->objectid) return -1;
    if (a->objectid > b->objectid) return 1;
    if (a->type < b->type) return -1;
    if (a->type > b->type) return 1;
    if (a->offset < b->offset) return -1;
    if (a->offset > b->offset) return 1;
    return 0;
}

static void key_write(u8 *slot, const struct adytumfs_item_key *key) {
    adytumfs_write_le64(slot, key->objectid);
    adytumfs_write_le64(slot + 8, key->offset);
    adytumfs_write_le32(slot + 16, key->type);
    // The spare word keeps the slot a round size and stays a checked zero, so
    // widening the key later cannot be mistaken for an old node.
    adytumfs_write_le32(slot + 20, 0);
}

static void key_read(const u8 *slot, struct adytumfs_item_key *key) {
    key->objectid = adytumfs_read_le64(slot);
    key->offset = adytumfs_read_le64(slot + 8);
    key->type = adytumfs_read_le32(slot + 16);
    key->spare = adytumfs_read_le32(slot + 20);
}

static void node_header(u8 *block, u32 level, u32 count, u32 data_start) {
    adytumfs_write_le32(block, ADYTUMFS_ITEM_MAGIC);
    adytumfs_write_le32(block + 4, ADYTUMFS_ITEM_VERSION);
    adytumfs_write_le32(block + 8, level);
    adytumfs_write_le32(block + 12, count);
    adytumfs_write_le32(block + 16, data_start);
    adytumfs_write_le32(block + 20, 0);
}

int adytumfs_item_leaf_pack(u8 *block, u32 count,
                            const struct adytumfs_item_key *keys,
                            const u8 *const *data, const u32 *sizes) {
    if (!block || !keys || !data || !sizes) return -1;
    if (!count || count > ADYTUMFS_ITEM_LEAF_SLOT_MAX) return -1;
    u32 slot_bytes = count * ADYTUMFS_ITEM_LEAF_SLOT_SIZE;
    // The budget is fixed and the running total climbs toward it. Comparing
    // against a cursor that falls instead wraps once the data passes the slot
    // area, and a wrapped bound accepts a node whose items overlap its slots.
    u32 budget = ADYTUMFS_BLOCK_SIZE - ADYTUMFS_ITEM_HEADER_SIZE - slot_bytes;
    u32 used = 0;
    for (u32 index = 0; index < count; index++) {
        if (!data[index] || !sizes[index]) return -1;
        if (index && key_compare(&keys[index - 1], &keys[index]) >= 0)
            return -1;
        if (sizes[index] > budget - used) return -1;
        used += sizes[index];
    }
    u32 data_start = ADYTUMFS_BLOCK_SIZE - used;
    node_header(block, 0, count, data_start);
    u32 cursor = ADYTUMFS_BLOCK_SIZE;
    for (u32 index = 0; index < count; index++) {
        u8 *slot = block + ADYTUMFS_ITEM_HEADER_SIZE +
                   index * ADYTUMFS_ITEM_LEAF_SLOT_SIZE;
        cursor -= sizes[index];
        key_write(slot, &keys[index]);
        adytumfs_write_le32(slot + ADYTUMFS_ITEM_KEY_SIZE, cursor);
        adytumfs_write_le32(slot + ADYTUMFS_ITEM_KEY_SIZE + 4, sizes[index]);
        for (u32 byte = 0; byte < sizes[index]; byte++)
            block[cursor + byte] = data[index][byte];
    }
    return 0;
}

int adytumfs_item_branch_pack(u8 *block, u32 level, u32 count,
                              const struct adytumfs_item_key *keys,
                              const u8 (*children)[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!block || !keys || !children) return -1;
    if (!level || level >= ADYTUMFS_ITEM_DEPTH_MAX) return -1;
    if (!count || count > ADYTUMFS_ITEM_BRANCH_SLOT_MAX) return -1;
    for (u32 index = 0; index < count; index++) {
        if (index && key_compare(&keys[index - 1], &keys[index]) >= 0)
            return -1;
    }
    // A branch carries no item bytes, so its data area is empty by definition
    // and a branch claiming otherwise is not one this file wrote.
    node_header(block, level, count, ADYTUMFS_BLOCK_SIZE);
    for (u32 index = 0; index < count; index++) {
        u8 *slot = block + ADYTUMFS_ITEM_HEADER_SIZE +
                   index * ADYTUMFS_ITEM_BRANCH_SLOT_SIZE;
        key_write(slot, &keys[index]);
        for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
            slot[ADYTUMFS_ITEM_KEY_SIZE + byte] = children[index][byte];
    }
    return 0;
}

int adytumfs_item_node_count(const u8 *block, u32 *count) {
    if (!block || !count) return -1;
    *count = adytumfs_read_le32(block + 12);
    return 0;
}

int adytumfs_item_leaf_get(const u8 *block, u32 index,
                           struct adytumfs_item_key *key, const u8 **data,
                           u32 *size) {
    if (!block || !key || !data || !size) return -1;
    if (index >= adytumfs_read_le32(block + 12)) return -1;
    const u8 *slot = block + ADYTUMFS_ITEM_HEADER_SIZE +
                     index * ADYTUMFS_ITEM_LEAF_SLOT_SIZE;
    key_read(slot, key);
    u32 offset = adytumfs_read_le32(slot + ADYTUMFS_ITEM_KEY_SIZE);
    u32 length = adytumfs_read_le32(slot + ADYTUMFS_ITEM_KEY_SIZE + 4);
    if (offset >= ADYTUMFS_BLOCK_SIZE) return -1;
    if (length > ADYTUMFS_BLOCK_SIZE - offset) return -1;
    *data = block + offset;
    *size = length;
    return 0;
}

int adytumfs_item_branch_get(const u8 *block, u32 index,
                             struct adytumfs_item_key *key,
                             u8 child[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!block || !child) return -1;
    if (index >= adytumfs_read_le32(block + 12)) return -1;
    const u8 *slot = block + ADYTUMFS_ITEM_HEADER_SIZE +
                     index * ADYTUMFS_ITEM_BRANCH_SLOT_SIZE;
    if (key) key_read(slot, key);
    for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
        child[byte] = slot[ADYTUMFS_ITEM_KEY_SIZE + byte];
    return 0;
}

int adytumfs_item_node_hash(const u8 *block,
                            u8 hash[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!block || !hash) return -1;
    return blake2b(hash, ADYTUMFS_ITEM_CHILD_SIZE, block,
                   ADYTUMFS_BLOCK_SIZE);
}

int adytumfs_item_node_check(const u8 *block, u32 level) {
    if (!block) return -1;
    if (adytumfs_read_le32(block) != ADYTUMFS_ITEM_MAGIC) return -1;
    if (adytumfs_read_le32(block + 4) != ADYTUMFS_ITEM_VERSION) return -1;
    if (adytumfs_read_le32(block + 8) != level) return -1;
    if (adytumfs_read_le32(block + 20)) return -1;
    u32 count = adytumfs_read_le32(block + 12);
    if (!count || count > level_capacity(level)) return -1;
    u32 stride = level_stride(level);
    u32 slot_end = ADYTUMFS_ITEM_HEADER_SIZE + count * stride;
    u32 data_start = adytumfs_read_le32(block + 16);
    // A branch has no data area, so its start sits at the end of the block and
    // any other value means the node was not packed here.
    if (level ? data_start != ADYTUMFS_BLOCK_SIZE : data_start < slot_end ||
                    data_start > ADYTUMFS_BLOCK_SIZE)
        return -1;
    struct adytumfs_item_key previous;
    u32 expect = ADYTUMFS_BLOCK_SIZE;
    for (u32 index = 0; index < count; index++) {
        const u8 *slot = block + ADYTUMFS_ITEM_HEADER_SIZE + index * stride;
        struct adytumfs_item_key key;
        key_read(slot, &key);
        if (key.spare) return -1;
        if (index && key_compare(&previous, &key) >= 0) return -1;
        previous = key;
        if (!level) {
            // Items are packed downward in slot order, so each one ends
            // exactly where the one before it began. A gap means a node this
            // file never wrote, and refusing it is cheaper than trusting it.
            u32 offset = adytumfs_read_le32(slot + ADYTUMFS_ITEM_KEY_SIZE);
            u32 length = adytumfs_read_le32(slot + ADYTUMFS_ITEM_KEY_SIZE + 4);
            if (!length || length > expect) return -1;
            if (offset != expect - length) return -1;
            if (offset < data_start) return -1;
            expect = offset;
        }
    }
    // The last item must reach the front of the data area, or the node claims
    // a data_start that its own items do not fill.
    if (!level && expect != data_start) return -1;
    return 0;
}

int adytumfs_item_node_search(const u8 *block,
                              const struct adytumfs_item_key *key) {
    if (!block || !key) return -1;
    u32 count = adytumfs_read_le32(block + 12);
    u32 level = adytumfs_read_le32(block + 8);
    u32 stride = level_stride(level);
    u32 low = 0;
    u32 high = count;
    while (low < high) {
        u32 middle = low + (high - low) / 2u;
        const u8 *slot = block + ADYTUMFS_ITEM_HEADER_SIZE + middle * stride;
        struct adytumfs_item_key candidate;
        key_read(slot, &candidate);
        if (key_compare(&candidate, key) < 0)
            low = middle + 1u;
        else
            high = middle;
    }
    return low < count ? (int)low : -1;
}

int adytumfs_item_root_empty(const u8 root[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!root) return 1;
    for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
        if (root[byte]) return 0;
    return 1;
}

int adytumfs_item_lookup(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                         const struct adytumfs_item_key *key, u8 *buffer,
                         u32 buffer_size, u32 *size) {
    if (!device || !super || !store || !root || !key || !buffer || !size)
        return -1;
    if (adytumfs_item_root_empty(root)) return -1;
    static u8 node[ADYTUMFS_BLOCK_SIZE];
    u8 child[ADYTUMFS_ITEM_CHILD_SIZE];
    for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
        child[byte] = root[byte];
    // Depth is bounded so a cycle in the location table cannot hang the
    // mount. A real tree at 64K inodes is three or four deep.
    for (u32 depth = 0; depth < ADYTUMFS_ITEM_DEPTH_MAX; depth++) {
        if (adytumfs_cas_read(device, super, store, child, node)) return -1;
        u32 level = adytumfs_read_le32(node + 8);
        if (level >= ADYTUMFS_ITEM_DEPTH_MAX) return -1;
        if (adytumfs_item_node_check(node, level)) return -1;
        int index = adytumfs_item_node_search(node, key);
        if (index < 0 && !level) return -1;
        if (index < 0) {
            u32 slots;
            if (adytumfs_item_node_count(node, &slots) || !slots) return -1;
            index = (int)slots - 1;
        }
        if (!level) {
            struct adytumfs_item_key found;
            const u8 *data;
            u32 length;
            if (adytumfs_item_leaf_get(node, (u32)index, &found, &data,
                                       &length))
                return -1;
            // Search finds the first key at or above the query, so an exact
            // match still has to be confirmed before the item is returned.
            if (key_compare(&found, key)) return -1;
            if (length > buffer_size) return -1;
            for (u32 byte = 0; byte < length; byte++) buffer[byte] = data[byte];
            *size = length;
            return 0;
        }
        if (adytumfs_item_branch_get(node, (u32)index, 0, child)) return -1;
    }
    return -1;
}

// Depth first over an explicit stack, because the walk is as deep as the tree
// and a recursive one would put that depth on the kernel stack. The bound is
// the worst case for depth first: every level leaves its other children
// pending while one of them is descended into.
#define ADYTUMFS_ITEM_WALK_STACK \
    (ADYTUMFS_ITEM_DEPTH_MAX * ADYTUMFS_ITEM_BRANCH_SLOT_MAX)

static u8 walk_node[ADYTUMFS_BLOCK_SIZE];
static u8 walk_stack[ADYTUMFS_ITEM_WALK_STACK][ADYTUMFS_ITEM_CHILD_SIZE];
static u32 walk_top;

static int walk_push(const u8 child[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (walk_top >= ADYTUMFS_ITEM_WALK_STACK) return -1;
    for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
        walk_stack[walk_top][byte] = child[byte];
    walk_top++;
    return 0;
}

// Set when a leaf passes the far end of a range, which ends the walk without
// borrowing a return value a visitor might legitimately produce.
static u32 walk_done;

// One traversal serves the whole tree and a key range, because a range is the
// same walk with the branches that cannot hold it left unpushed and the leaves
// stopping at the far end. Two traversals would be two places to get the key
// order wrong, and the order is what an audit compares a rebuild against.
//
// Both bounds are inclusive and either may be absent. A directory listing is
// the case this exists for: its entries share an objectid, so the range is the
// whole listing and the rest of the tree is never read.
static int walk_range(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store,
                      const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                      const struct adytumfs_item_key *from,
                      const struct adytumfs_item_key *to,
                      int (*visit)(const struct adytumfs_item_key *key,
                                   const u8 *data, u32 size, void *context),
                      void *context) {
    if (!device || !super || !store || !root || !visit) return -1;
    walk_top = 0;
    walk_done = 0;
    if (adytumfs_item_root_empty(root)) return 0;
    if (walk_push(root)) return -1;
    while (walk_top && !walk_done) {
        walk_top--;
        u8 child[ADYTUMFS_ITEM_CHILD_SIZE];
        for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
            child[byte] = walk_stack[walk_top][byte];
        if (adytumfs_cas_read(device, super, store, child, walk_node))
            return -1;
        u32 level = adytumfs_read_le32(walk_node + 8);
        if (level >= ADYTUMFS_ITEM_DEPTH_MAX) return -1;
        if (adytumfs_item_node_check(walk_node, level)) return -1;
        u32 count;
        if (adytumfs_item_node_count(walk_node, &count)) return -1;
        if (!level) {
            for (u32 index = 0; index < count; index++) {
                struct adytumfs_item_key key;
                const u8 *data;
                u32 length;
                if (adytumfs_item_leaf_get(walk_node, index, &key, &data,
                                           &length))
                    return -1;
                // Keys ascend within a leaf, so the first one past the far end
                // ends the walk rather than being skipped over.
                if (to && key_compare(&key, to) > 0) {
                    walk_done = 1;
                    break;
                }
                if (from && key_compare(&key, from) < 0) continue;
                int result = visit(&key, data, length, context);
                if (result) return result;
            }
            continue;
        }
        // Children go on in reverse so that popping yields ascending key
        // order, which is what an audit comparing against a sorted rebuild
        // needs.
        for (u32 index = count; index-- > 0;) {
            struct adytumfs_item_key bound;
            u8 next[ADYTUMFS_ITEM_CHILD_SIZE];
            if (adytumfs_item_branch_get(walk_node, index, &bound, next))
                return -1;
            // A branch key is the largest key in its child's subtree, so a
            // child ending below the range holds nothing in it, and walking
            // down from here only meets more of the same.
            if (from && key_compare(&bound, from) < 0) break;
            // The child before this one carries the smallest key this child
            // can hold, and a subtree starting above the range is out too.
            if (to && index) {
                struct adytumfs_item_key lower;
                u8 skip[ADYTUMFS_ITEM_CHILD_SIZE];
                if (adytumfs_item_branch_get(walk_node, index - 1, &lower,
                                             skip))
                    return -1;
                if (key_compare(&lower, to) > 0) continue;
            }
            if (walk_push(next)) return -1;
        }
    }
    return 0;
}

int adytumfs_item_walk(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                       int (*visit)(const struct adytumfs_item_key *key,
                                    const u8 *data, u32 size, void *context),
                       void *context) {
    return walk_range(device, super, store, root, 0, 0, visit, context);
}

int adytumfs_item_walk_range(struct kernel_object *device,
                             struct adytumfs_superblock *super,
                             struct adytumfs_cas *store,
                             const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                             const struct adytumfs_item_key *from,
                             const struct adytumfs_item_key *to,
                             int (*visit)(const struct adytumfs_item_key *key,
                                          const u8 *data, u32 size,
                                          void *context),
                             void *context) {
    return walk_range(device, super, store, root, from, to, visit, context);
}

static void hash_copy(u8 *to, const u8 *from) {
    for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
        to[byte] = from[byte];
}

struct adytumfs_item_step {
    u8 hash[ADYTUMFS_ITEM_CHILD_SIZE];
    u32 index;
    u32 level;
};

struct adytumfs_item_growth {
    u8 left[ADYTUMFS_ITEM_CHILD_SIZE];
    u8 right[ADYTUMFS_ITEM_CHILD_SIZE];
    struct adytumfs_item_key left_max;
    struct adytumfs_item_key right_max;
    int split;
};

// Node buffers are static rather than on the stack because a 4 KiB frame per
// level of descent is more than the kernel stack carries, and the insert is
// one operation at a time.
static u8 item_node[ADYTUMFS_BLOCK_SIZE];
static u8 item_left[ADYTUMFS_BLOCK_SIZE];
static u8 item_right[ADYTUMFS_BLOCK_SIZE];

static int item_store(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store, const u8 *block,
                      u8 hash[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (adytumfs_item_node_hash(block, hash)) return -1;
    u64 number = 0;
    if (adytumfs_cas_place(device, super, store, hash, &number)) return -1;
    // A branch holds a reference on every child it names, taken here rather
    // than at each pack site so that no new store can forget it. Without this
    // the count says how often a node was written rather than how many parents
    // reach it, and a discard frees subtrees the committed root still uses. A
    // leaf names nothing outside itself: its items are inline bytes, so there
    // is nothing to retain and dropping the leaf is what lets them go.
    if (adytumfs_read_le32(block + 8)) {
        u32 count = adytumfs_read_le32(block + 12);
        for (u32 index = 0; index < count; index++)
            if (adytumfs_cas_retain(device, super, store,
                                    block + ADYTUMFS_ITEM_HEADER_SIZE +
                                        index *
                                            ADYTUMFS_ITEM_BRANCH_SLOT_SIZE +
                                        ADYTUMFS_ITEM_KEY_SIZE))
                return -1;
    }
    return adytumfs_block_write(device, number, block);
}

// Record the path from the root to the leaf that would hold the key, so the
// rewrite can walk back up without descending twice.
static int item_descend(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                        const struct adytumfs_item_key *key,
                        struct adytumfs_item_step *path, u32 *depth) {
    u8 child[ADYTUMFS_ITEM_CHILD_SIZE];
    hash_copy(child, root);
    for (u32 level = 0; level < ADYTUMFS_ITEM_DEPTH_MAX; level++) {
        if (adytumfs_cas_read(device, super, store, child, item_node))
            return -1;
        u32 node_level = adytumfs_read_le32(item_node + 8);
        if (node_level >= ADYTUMFS_ITEM_DEPTH_MAX) return -1;
        if (adytumfs_item_node_check(item_node, node_level)) return -1;
        int index = adytumfs_item_node_search(item_node, key);
        // Search is a lower bound, so a key above every slot returns nothing.
        // That is not an absent key, it is the last slot: in a branch the
        // rightmost child is where anything above the greatest separator lives,
        // and in a leaf the insert works out its own position.
        if (index < 0) {
            u32 slots;
            if (adytumfs_item_node_count(item_node, &slots) || !slots)
                return -1;
            index = (int)slots - 1;
        }
        hash_copy(path[level].hash, child);
        path[level].index = (u32)index;
        path[level].level = node_level;
        if (!node_level) {
            *depth = level + 1u;
            return 0;
        }
        if (adytumfs_item_branch_get(item_node, (u32)index, 0, child))
            return -1;
    }
    return -1;
}

// The greatest key in a packed node, which is what a branch stores as the
// separator for the child below it. The slot layout differs between a leaf and
// a branch, so the level decides the stride; reading a branch with the leaf
// stride returns the child hash where a key was expected.
static int node_max_key(const u8 *block, struct adytumfs_item_key *key) {
    u32 count;
    if (adytumfs_item_node_count(block, &count)) return -1;
    if (!count) return -1;
    u32 level = adytumfs_read_le32(block + 8);
    u32 stride = level ? ADYTUMFS_ITEM_BRANCH_SLOT_SIZE
                       : ADYTUMFS_ITEM_LEAF_SLOT_SIZE;
    key_read(block + ADYTUMFS_ITEM_HEADER_SIZE + (count - 1u) * stride, key);
    return 0;
}

static int leaf_insert(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, const u8 *node,
                       const struct adytumfs_item_key *key, const u8 *data,
                       u32 size, struct adytumfs_item_growth *growth) {
    static u8 staged[ADYTUMFS_BLOCK_SIZE];
    static struct adytumfs_item_key keys[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static const u8 *staged_at[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static u32 staged_size[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static struct adytumfs_item_key out_keys[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static const u8 *out_at[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static u32 out_size[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    u32 count;
    if (adytumfs_item_node_count(node, &count)) return -1;
    if (count >= ADYTUMFS_ITEM_LEAF_SLOT_MAX) return -1;
    u32 used = 0;
    for (u32 index = 0; index < count; index++) {
        const u8 *bytes;
        u32 length;
        if (adytumfs_item_leaf_get(node, index, &keys[index], &bytes, &length))
            return -1;
        if (used + length > ADYTUMFS_BLOCK_SIZE) return -1;
        for (u32 byte = 0; byte < length; byte++)
            staged[used + byte] = bytes[byte];
        staged_at[index] = staged + used;
        staged_size[index] = length;
        used += length;
    }
    u32 at = 0;
    while (at < count && key_compare(&keys[at], key) < 0) at++;
    // Replacing an item of a different size rebuilds the leaf rather than
    // patching it, because the data area is packed with no gaps and moving one
    // item moves every one after it.
    int replacing = at < count && key_compare(&keys[at], key) == 0;
    u32 total = 0;
    u32 placed = 0;
    for (u32 index = 0; index < count; index++) {
        if (index == at) {
            out_keys[total] = *key;
            out_at[total] = data;
            out_size[total] = size;
            total++;
            placed = 1;
            if (replacing) continue;
        }
        out_keys[total] = keys[index];
        out_at[total] = staged_at[index];
        out_size[total] = staged_size[index];
        total++;
    }
    if (!placed) {
        out_keys[total] = *key;
        out_at[total] = data;
        out_size[total] = size;
        total++;
    }
    if (adytumfs_item_leaf_pack(item_node, total, out_keys, out_at,
                                out_size) == 0) {
        growth->split = 0;
        if (node_max_key(item_node, &growth->left_max)) return -1;
        return item_store(device, super, store, item_node, growth->left);
    }
    // The scan for a workable boundary has to repack, so the candidate arrays
    // stay live across it. Trying the middle first keeps the tree shallow; a
    // leaf whose items are wildly uneven simply splits off centre.
    for (u32 shift = 0; shift < total; shift++) {
        for (u32 side = 0; side < 2u; side++) {
            if (shift && !side && total / 2u < shift) continue;
            u32 candidate = shift ? (side ? total / 2u + shift
                                          : total / 2u - shift)
                                  : total / 2u;
            if (!candidate || candidate >= total) continue;
            if (adytumfs_item_leaf_pack(item_left, candidate, out_keys, out_at,
                                        out_size))
                continue;
            if (adytumfs_item_leaf_pack(item_right, total - candidate,
                                        out_keys + candidate,
                                        out_at + candidate,
                                        out_size + candidate))
                continue;
            growth->split = 1;
            if (node_max_key(item_left, &growth->left_max)) return -1;
            if (node_max_key(item_right, &growth->right_max)) return -1;
            if (item_store(device, super, store, item_right, growth->right))
                return -1;
            return item_store(device, super, store, item_left, growth->left);
        }
    }
    return -1;
}

// Rewrite one branch above a changed child. The child's new hash replaces the
// old one at the slot the descent recorded, and a split adds the sibling next
// to it. When the branch itself overflows it splits the same way a leaf does,
// and says so upward.
static int branch_rewrite(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store, const u8 *node, u32 at,
                          const struct adytumfs_item_growth *below,
                          struct adytumfs_item_growth *growth) {
    static struct adytumfs_item_key keys[ADYTUMFS_ITEM_BRANCH_SLOT_MAX + 1u];
    static u8 children[ADYTUMFS_ITEM_BRANCH_SLOT_MAX +
                       1u][ADYTUMFS_ITEM_CHILD_SIZE];
    u32 count;
    if (adytumfs_item_node_count(node, &count)) return -1;
    if (at >= count) return -1;
    u32 level = adytumfs_read_le32(node + 8);
    for (u32 index = 0; index < count; index++)
        if (adytumfs_item_branch_get(node, index, &keys[index],
                                     children[index]))
            return -1;
    u32 total = count;
    if (below->split) {
        if (count >= ADYTUMFS_ITEM_BRANCH_SLOT_MAX) {
            // A full branch gaining an entry splits first, so the entry lands
            // in a half with room and the arrays never exceed what the format
            // holds.
            u32 half = count / 2u;
            u32 left_total = at < half ? half + 1u : half;
            u32 right_total = at < half ? count - half : count - half + 1u;
            u32 place = at < half ? at : at - half;
            static struct adytumfs_item_key left_keys[
                ADYTUMFS_ITEM_BRANCH_SLOT_MAX + 1u];
            static u8 left_children[ADYTUMFS_ITEM_BRANCH_SLOT_MAX +
                                    1u][ADYTUMFS_ITEM_CHILD_SIZE];
            static struct adytumfs_item_key right_keys[
                ADYTUMFS_ITEM_BRANCH_SLOT_MAX + 1u];
            static u8 right_children[ADYTUMFS_ITEM_BRANCH_SLOT_MAX +
                                     1u][ADYTUMFS_ITEM_CHILD_SIZE];
            for (u32 index = 0; index < half; index++) {
                left_keys[index] = keys[index];
                hash_copy(left_children[index], children[index]);
            }
            for (u32 index = half; index < count; index++) {
                right_keys[index - half] = keys[index];
                hash_copy(right_children[index - half], children[index]);
            }
            struct adytumfs_item_key *target_keys =
                at < half ? left_keys : right_keys;
            u8 (*target_children)[ADYTUMFS_ITEM_CHILD_SIZE] =
                at < half ? left_children : right_children;
            u32 target_total = at < half ? left_total : right_total;
            for (u32 index = target_total - 1u; index > place + 1u; index--) {
                target_keys[index] = target_keys[index - 1u];
                hash_copy(target_children[index], target_children[index - 1u]);
            }
            target_keys[place] = below->left_max;
            hash_copy(target_children[place], below->left);
            target_keys[place + 1u] = below->right_max;
            hash_copy(target_children[place + 1u], below->right);
            growth->split = 1;
            if (adytumfs_item_branch_pack(item_left, level, left_total,
                                          left_keys, left_children) ||
                adytumfs_item_branch_pack(item_right, level, right_total,
                                          right_keys, right_children))
                return -1;
            if (node_max_key(item_left, &growth->left_max)) return -1;
            if (node_max_key(item_right, &growth->right_max)) return -1;
            if (item_store(device, super, store, item_right, growth->right))
                return -1;
            return item_store(device, super, store, item_left, growth->left);
        }
        for (u32 index = count; index > at + 1u; index--) {
            keys[index] = keys[index - 1u];
            hash_copy(children[index], children[index - 1u]);
        }
        keys[at + 1u] = below->right_max;
        hash_copy(children[at + 1u], below->right);
        total = count + 1u;
    }
    keys[at] = below->left_max;
    hash_copy(children[at], below->left);
    if (adytumfs_item_branch_pack(item_node, level, total, keys, children))
        return -1;
    growth->split = 0;
    if (node_max_key(item_node, &growth->left_max)) return -1;
    return item_store(device, super, store, item_node, growth->left);
}

static int item_insert(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                       const struct adytumfs_item_key *key, const u8 *data,
                       u32 size,
                       u8 new_root[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!device || !super || !store || !root || !key || !data || !size ||
        !new_root)
        return -1;
    if (adytumfs_item_root_empty(root)) {
        static const u8 *single[1];
        static u32 single_size[1];
        single[0] = data;
        single_size[0] = size;
        if (adytumfs_item_leaf_pack(item_node, 1u, key, single, single_size))
            return -1;
        return item_store(device, super, store, item_node, new_root);
    }
    static struct adytumfs_item_step path[ADYTUMFS_ITEM_DEPTH_MAX];
    static u8 node_copy[ADYTUMFS_BLOCK_SIZE];
    u32 depth = 0;
    if (item_descend(device, super, store, root, key, path, &depth)) return -1;
    struct adytumfs_item_growth below;
    struct adytumfs_item_growth above;
    if (adytumfs_cas_read(device, super, store, path[depth - 1u].hash,
                          item_node))
        return -1;
    // The leaf is copied out of the shared buffer because the insert writes its
    // result back into that same buffer.
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        node_copy[index] = item_node[index];
    if (leaf_insert(device, super, store, node_copy, key, data, size, &below))
        return -1;
    for (u32 step = depth - 1u; step > 0; step--) {
        if (adytumfs_cas_read(device, super, store, path[step - 1u].hash,
                              item_node))
            return -1;
        for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
            node_copy[index] = item_node[index];
        if (branch_rewrite(device, super, store, node_copy,
                           path[step - 1u].index, &below, &above))
            return -1;
        below = above;
    }
    if (!below.split) {
        hash_copy(new_root, below.left);
        return 0;
    }
    // The root split, so the tree grew a level. The two halves become the whole
    // of a new branch root.
    struct adytumfs_item_key keys[2];
    u8 children[2][ADYTUMFS_ITEM_CHILD_SIZE];
    keys[0] = below.left_max;
    keys[1] = below.right_max;
    hash_copy(children[0], below.left);
    hash_copy(children[1], below.right);
    if (adytumfs_item_branch_pack(item_node, path[0].level + 1u, 2u, keys,
                                  children))
        return -1;
    return item_store(device, super, store, item_node, new_root);
}

int adytumfs_item_insert(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                         const struct adytumfs_item_key *key, const u8 *data,
                         u32 size,
                         u8 new_root[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (item_insert(device, super, store, root, key, data, size, new_root))
        return -1;
    // Every other node is reached through its parent, and the root's parent is
    // whoever commits it, so the caller is handed a reference and drops it by
    // discarding that root once a later one is committed.
    return adytumfs_cas_retain(device, super, store, new_root);
}

// A leaf that loses its last item cannot be repacked, because both pack
// functions reject an empty node and the format has no representation for one.
// Removal therefore says upward that the child is gone rather than handing back
// a smaller node, and a branch that loses its last child is gone the same way.
// A root ending that way leaves the tree empty, which the zero root already
// means, so no empty node is ever left behind to be found by a later walk.
struct adytumfs_item_shrink {
    u8 left[ADYTUMFS_ITEM_CHILD_SIZE];
    struct adytumfs_item_key left_max;
    int gone;
};

// Remove one item from a leaf. The leaf is rebuilt without it rather than
// patched for the same reason an insert of a different size rebuilds: the data
// area is packed with no gaps, so taking one item out moves every item after
// it. No merging happens here or above, so a leaf keeps whatever it is left
// with and the tree simply gets sparser.
static int leaf_remove(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, const u8 *node,
                       const struct adytumfs_item_key *key,
                       struct adytumfs_item_shrink *shrink) {
    static u8 staged[ADYTUMFS_BLOCK_SIZE];
    static struct adytumfs_item_key keys[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static const u8 *staged_at[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static u32 staged_size[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static struct adytumfs_item_key out_keys[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static const u8 *out_at[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static u32 out_size[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    u32 count;
    if (adytumfs_item_node_count(node, &count) || !count) return -1;
    int at = adytumfs_item_node_search(node, key);
    if (at < 0) return -1;
    const u8 *probe;
    u32 probe_size;
    if (adytumfs_item_leaf_get(node, (u32)at, &keys[0], &probe, &probe_size))
        return -1;
    // Search is a lower bound, so the slot it lands on holds the key asked for
    // only if the key really matches. A miss is an error and not a no-op: the
    // caller asked for one named thing and has to hear when it is absent.
    if (key_compare(&keys[0], key)) return -1;
    u32 used = 0;
    for (u32 index = 0; index < count; index++) {
        if (index == (u32)at) continue;
        const u8 *bytes;
        u32 size;
        if (adytumfs_item_leaf_get(node, index, &keys[index], &bytes, &size))
            return -1;
        if (used + size > ADYTUMFS_BLOCK_SIZE) return -1;
        for (u32 byte = 0; byte < size; byte++)
            staged[used + byte] = bytes[byte];
        staged_at[index] = staged + used;
        staged_size[index] = size;
        used += size;
    }
    u32 total = 0;
    for (u32 index = 0; index < count; index++) {
        if (index == (u32)at) continue;
        out_keys[total] = keys[index];
        out_at[total] = staged_at[index];
        out_size[total] = staged_size[index];
        total++;
    }
    if (!total) {
        shrink->gone = 1;
        return 0;
    }
    if (adytumfs_item_leaf_pack(item_node, total, out_keys, out_at, out_size))
        return -1;
    shrink->gone = 0;
    if (node_max_key(item_node, &shrink->left_max)) return -1;
    return item_store(device, super, store, item_node, shrink->left);
}

// Rewrite one branch above a changed child, either naming the child's
// replacement or dropping the slot when the child emptied. Dropping a slot
// leaves the remaining separators correct without adjusting them: the separator
// that went described the child that went, and no key it covered is in the tree
// any more, so routing that would have landed there has nowhere left to go.
static int branch_shrink(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store, const u8 *node, u32 at,
                         const struct adytumfs_item_shrink *below,
                         struct adytumfs_item_shrink *above) {
    static struct adytumfs_item_key keys[ADYTUMFS_ITEM_BRANCH_SLOT_MAX];
    static u8 children[ADYTUMFS_ITEM_BRANCH_SLOT_MAX]
                      [ADYTUMFS_ITEM_CHILD_SIZE];
    u32 count;
    if (adytumfs_item_node_count(node, &count)) return -1;
    if (!count || at >= count) return -1;
    u32 level = adytumfs_read_le32(node + 8);
    for (u32 index = 0; index < count; index++)
        if (adytumfs_item_branch_get(node, index, &keys[index],
                                     children[index]))
            return -1;
    u32 total;
    if (below->gone) {
        total = count - 1u;
        for (u32 index = at; index < total; index++) {
            keys[index] = keys[index + 1u];
            hash_copy(children[index], children[index + 1u]);
        }
    } else {
        total = count;
        keys[at] = below->left_max;
        hash_copy(children[at], below->left);
    }
    if (!total) {
        above->gone = 1;
        return 0;
    }
    if (adytumfs_item_branch_pack(item_node, level, total, keys, children))
        return -1;
    above->gone = 0;
    if (node_max_key(item_node, &above->left_max)) return -1;
    return item_store(device, super, store, item_node, above->left);
}

static int item_remove(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                       const struct adytumfs_item_key *key,
                       u8 new_root[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!device || !super || !store || !root || !key || !new_root) return -1;
    if (adytumfs_item_root_empty(root)) return -1;
    static struct adytumfs_item_step path[ADYTUMFS_ITEM_DEPTH_MAX];
    static u8 node_copy[ADYTUMFS_BLOCK_SIZE];
    u32 depth = 0;
    if (item_descend(device, super, store, root, key, path, &depth)) return -1;
    struct adytumfs_item_shrink below;
    struct adytumfs_item_shrink above;
    if (adytumfs_cas_read(device, super, store, path[depth - 1u].hash,
                          item_node))
        return -1;
    // The leaf is copied out of the shared buffer because the rebuild writes
    // its result back into that same buffer.
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        node_copy[index] = item_node[index];
    if (leaf_remove(device, super, store, node_copy, key, &below)) return -1;
    for (u32 step = depth - 1u; step > 0; step--) {
        if (adytumfs_cas_read(device, super, store, path[step - 1u].hash,
                              item_node))
            return -1;
        for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
            node_copy[index] = item_node[index];
        if (branch_shrink(device, super, store, node_copy,
                          path[step - 1u].index, &below, &above))
            return -1;
        below = above;
    }
    if (below.gone) {
        for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
            new_root[byte] = 0;
        return 0;
    }
    hash_copy(new_root, below.left);
    return 0;
}

int adytumfs_item_remove(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                         const struct adytumfs_item_key *key,
                         u8 new_root[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (item_remove(device, super, store, root, key, new_root)) return -1;
    // An emptied tree has no node left to hold and the zero root already means
    // empty, so only a surviving root is handed back with a reference on it.
    if (adytumfs_item_root_empty(new_root)) return 0;
    return adytumfs_cas_retain(device, super, store, new_root);
}

// Depth first over an explicit stack for the same reason the walk is: the
// descent is as deep as the tree and a recursive one would put that depth on
// the kernel stack. The bound is the worst case, every level leaving its other
// children pending while one is descended into.
#define ADYTUMFS_ITEM_DROP_STACK \
    (ADYTUMFS_ITEM_DEPTH_MAX * ADYTUMFS_ITEM_BRANCH_SLOT_MAX)

static u8 drop_node[ADYTUMFS_BLOCK_SIZE];
static u8 drop_stack[ADYTUMFS_ITEM_DROP_STACK][ADYTUMFS_ITEM_CHILD_SIZE];
static u32 drop_top;

static int drop_push(const u8 child[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (drop_top >= ADYTUMFS_ITEM_DROP_STACK) return -1;
    for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
        drop_stack[drop_top][byte] = child[byte];
    drop_top++;
    return 0;
}

int adytumfs_item_drop(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!device || !super || !store || !root) return -1;
    if (adytumfs_item_root_empty(root)) return 0;
    drop_top = 0;
    if (drop_push(root)) return -1;
    while (drop_top) {
        drop_top--;
        u8 hash[ADYTUMFS_ITEM_CHILD_SIZE];
        for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
            hash[byte] = drop_stack[drop_top][byte];
        u32 refs = 0;
        if (adytumfs_cas_refs(device, super, store, hash, &refs)) return -1;
        if (!refs) return -1;
        if (adytumfs_cas_read(device, super, store, hash, drop_node))
            return -1;
        u32 level = adytumfs_read_le32(drop_node + 8);
        if (level >= ADYTUMFS_ITEM_DEPTH_MAX) return -1;
        if (adytumfs_item_node_check(drop_node, level)) return -1;
        // Whatever the node names is copied out before the release, because
        // dropping the last reference hands the block back to the allocator
        // and the next allocation is free to overwrite it.
        static u8 children[ADYTUMFS_ITEM_BRANCH_SLOT_MAX]
                          [ADYTUMFS_ITEM_CHILD_SIZE];
        u32 count = 0;
        if (adytumfs_item_node_count(drop_node, &count)) return -1;
        if (level)
            for (u32 index = 0; index < count; index++)
                if (adytumfs_item_branch_get(drop_node, index, 0,
                                             children[index]))
                    return -1;
        if (adytumfs_cas_release(device, super, store, hash)) return -1;
        // Only a node whose last reference just went takes what it named with
        // it. One still held elsewhere belongs to that holder, and a later drop
        // of that root reaches it then. A leaf names nothing outside itself, so
        // there is nothing to queue.
        if (refs != 1u || !level) continue;
        for (u32 index = 0; index < count; index++)
            if (drop_push(children[index])) return -1;
    }
    return 0;
}
