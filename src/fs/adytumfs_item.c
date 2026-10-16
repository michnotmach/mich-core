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
    u32 cursor = ADYTUMFS_BLOCK_SIZE;
    for (u32 index = 0; index < count; index++) {
        if (!data[index] || !sizes[index]) return -1;
        if (index && key_compare(&keys[index - 1], &keys[index]) >= 0)
            return -1;
        if (sizes[index] > cursor - ADYTUMFS_ITEM_HEADER_SIZE - slot_bytes)
            return -1;
        cursor -= sizes[index];
    }
    u32 data_start = cursor;
    node_header(block, 0, count, data_start);
    cursor = ADYTUMFS_BLOCK_SIZE;
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

int adytumfs_item_branch_pack(u8 *block, u32 count,
                              const struct adytumfs_item_key *keys,
                              const u8 (*children)[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!block || !keys || !children) return -1;
    if (!count || count > ADYTUMFS_ITEM_BRANCH_SLOT_MAX) return -1;
    for (u32 index = 0; index < count; index++) {
        if (index && key_compare(&keys[index - 1], &keys[index]) >= 0)
            return -1;
    }
    // A branch carries no item bytes, so its data area is empty by definition
    // and a branch claiming otherwise is not one this file wrote.
    node_header(block, 1, count, ADYTUMFS_BLOCK_SIZE);
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
        if (index < 0) return -1;
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

int adytumfs_item_walk(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                       int (*visit)(const struct adytumfs_item_key *key,
                                    const u8 *data, u32 size, void *context),
                       void *context) {
    if (!device || !super || !store || !root || !visit) return -1;
    walk_top = 0;
    if (adytumfs_item_root_empty(root)) return 0;
    if (walk_push(root)) return -1;
    while (walk_top) {
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
                int result = visit(&key, data, length, context);
                if (result) return result;
            }
            continue;
        }
        // Children go on in reverse so that popping yields ascending key
        // order, which is what an audit comparing against a sorted rebuild
        // needs.
        for (u32 index = count; index-- > 0;) {
            u8 next[ADYTUMFS_ITEM_CHILD_SIZE];
            if (adytumfs_item_branch_get(walk_node, index, 0, next)) return -1;
            if (walk_push(next)) return -1;
        }
    }
    return 0;
}
