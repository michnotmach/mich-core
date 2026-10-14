#include "adytumfs_tree.h"
#include "blake2b.h"
#include "crypto.h"

static u32 level_stride(u32 level) {
    return level ? ADYTUMFS_TREE_BRANCH_ENTRY_SIZE
                 : ADYTUMFS_TREE_LEAF_ENTRY_SIZE;
}

static u32 level_capacity(u32 level) {
    return level ? ADYTUMFS_TREE_BRANCH_MAX : ADYTUMFS_TREE_LEAF_MAX;
}

static int key_equal(const struct adytumfs_tree_key *left,
                     const struct adytumfs_tree_key *right) {
    return left->end == right->end;
}

static int key_less(const struct adytumfs_tree_key *left,
                    const struct adytumfs_tree_key *right) {
    return left->end < right->end;
}

static void write_key(u8 *entry, const struct adytumfs_tree_key *key) {
    adytumfs_write_le64(entry, key->end);
}

static void read_key(const u8 *entry, struct adytumfs_tree_key *key) {
    key->end = adytumfs_read_le64(entry);
}

// One leaf entry is [end - length, end) of the file, so the invariants below
// are what make the entries tile the file without gaps in the accounting and
// without overlap. They are checked on the write side because a leaf that
// breaks them is a bug in this file, and no reader can repair one.
static int leaf_entries_valid(u32 count,
                              const struct adytumfs_tree_key *keys,
                              const struct adytumfs_tree_value *values) {
    u64 previous = 0;
    for (u32 index = 0; index < count; index++) {
        if (keys[index].end & (ADYTUMFS_BLOCK_SIZE - 1u)) return -1;
        if (values[index].length & (ADYTUMFS_BLOCK_SIZE - 1u)) return -1;
        if (values[index].length < ADYTUMFS_BLOCK_SIZE) return -1;
        if (keys[index].end < values[index].length) return -1;
        if (keys[index].end - values[index].length < previous) return -1;
        previous = keys[index].end;
    }
    return 0;
}

static void write_header(u8 *block, u32 level, u32 count) {
    adytumfs_write_le32(block, ADYTUMFS_TREE_MAGIC);
    adytumfs_write_le32(block + 4, level);
    adytumfs_write_le32(block + 8, count);
    adytumfs_write_le32(block + 12, 0);
}

// Keys must arrive sorted and unique. A node with a repeated or out of order
// key would make the binary search below miss entries that are present, which
// is a silent wrong answer rather than a failure.
static int keys_sorted(u32 count, const struct adytumfs_tree_key *keys) {
    for (u32 index = 1; index < count; index++)
        if (!key_less(&keys[index - 1], &keys[index])) return -1;
    return 0;
}

static int node_pack(u8 *block, u32 level, u32 count,
                     const struct adytumfs_tree_key *keys) {
    if (!block || !keys || !count || count > level_capacity(level)) return -1;
    if (keys_sorted(count, keys)) return -1;
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++) block[index] = 0;
    write_header(block, level, count);
    u32 stride = level_stride(level);
    for (u32 index = 0; index < count; index++)
        write_key(block + ADYTUMFS_TREE_HEADER_SIZE + index * stride,
                  &keys[index]);
    return 0;
}

int adytumfs_tree_leaf_pack(u8 *block, u32 count,
                            const struct adytumfs_tree_key *keys,
                            const struct adytumfs_tree_value *values) {
    if (!values) return -1;
    if (leaf_entries_valid(count, keys, values)) return -1;
    if (node_pack(block, 0, count, keys)) return -1;
    for (u32 index = 0; index < count; index++) {
        u8 *entry = block + ADYTUMFS_TREE_HEADER_SIZE +
            index * ADYTUMFS_TREE_LEAF_ENTRY_SIZE + ADYTUMFS_TREE_KEY_SIZE;
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            entry[byte] = values[index].hash[byte];
        adytumfs_write_le64(entry + ADYTUMFS_CAS_HASH_SIZE,
                            values[index].length);
    }
    return 0;
}

int adytumfs_tree_branch_pack(u8 *block, u32 count,
                              const struct adytumfs_tree_key *keys,
                              const u8 (*children)[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!children) return -1;
    if (node_pack(block, 1, count, keys)) return -1;
    for (u32 index = 0; index < count; index++) {
        u8 *entry = block + ADYTUMFS_TREE_HEADER_SIZE +
            index * ADYTUMFS_TREE_BRANCH_ENTRY_SIZE + ADYTUMFS_TREE_KEY_SIZE;
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            entry[byte] = children[index][byte];
    }
    return 0;
}

int adytumfs_tree_leaf_unpack(const u8 *block, u32 *count,
                              struct adytumfs_tree_key *keys,
                              struct adytumfs_tree_value *values) {
    if (!block || !count || !keys || !values) return -1;
    if (adytumfs_tree_node_check(block, 0)) return -1;
    *count = adytumfs_read_le32(block + 8);
    for (u32 index = 0; index < *count; index++) {
        const u8 *entry = block + ADYTUMFS_TREE_HEADER_SIZE +
            index * ADYTUMFS_TREE_LEAF_ENTRY_SIZE;
        read_key(entry, &keys[index]);
        const u8 *value = entry + ADYTUMFS_TREE_KEY_SIZE;
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            values[index].hash[byte] = value[byte];
        values[index].length = adytumfs_read_le64(value + ADYTUMFS_CAS_HASH_SIZE);
    }
    return 0;
}

int adytumfs_tree_branch_unpack(const u8 *block, u32 *count,
                                struct adytumfs_tree_key *keys,
                                u8 (*children)[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!block || !count || !keys || !children) return -1;
    if (adytumfs_tree_node_check(block, 1)) return -1;
    *count = adytumfs_read_le32(block + 8);
    for (u32 index = 0; index < *count; index++) {
        const u8 *entry = block + ADYTUMFS_TREE_HEADER_SIZE +
            index * ADYTUMFS_TREE_BRANCH_ENTRY_SIZE;
        read_key(entry, &keys[index]);
        const u8 *child = entry + ADYTUMFS_TREE_KEY_SIZE;
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            children[index][byte] = child[byte];
    }
    return 0;
}

int adytumfs_tree_node_hash(const u8 *block, u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!block || !hash) return -1;
    return blake2b(hash, ADYTUMFS_CAS_HASH_SIZE, block, ADYTUMFS_BLOCK_SIZE);
}

int adytumfs_tree_node_check(const u8 *block, u32 level) {
    if (!block) return -1;
    if (adytumfs_read_le32(block) != ADYTUMFS_TREE_MAGIC) return -1;
    if (adytumfs_read_le32(block + 4) != level) return -1;
    if (adytumfs_read_le32(block + 12)) return -1;
    u32 count = adytumfs_read_le32(block + 8);
    if (!count || count > level_capacity(level)) return -1;
    u32 stride = level_stride(level);
    struct adytumfs_tree_key previous;
    struct adytumfs_tree_key current;
    read_key(block + ADYTUMFS_TREE_HEADER_SIZE, &previous);
    for (u32 index = 1; index < count; index++) {
        read_key(block + ADYTUMFS_TREE_HEADER_SIZE + index * stride, &current);
        if (!key_less(&previous, &current)) return -1;
        previous = current;
    }
    return 0;
}

int adytumfs_tree_node_search(const u8 *block,
                              const struct adytumfs_tree_key *key) {
    if (!block || !key) return -1;
    u32 level = adytumfs_read_le32(block + 4);
    if (level > 1u) return -1;
    u32 count = adytumfs_read_le32(block + 8);
    if (!count || count > level_capacity(level)) return -1;
    u32 stride = level_stride(level);
    u32 low = 0;
    u32 high = count;
    while (low < high) {
        u32 mid = low + (high - low) / 2u;
        struct adytumfs_tree_key candidate;
        read_key(block + ADYTUMFS_TREE_HEADER_SIZE + mid * stride, &candidate);
        if (key_less(&candidate, key)) low = mid + 1u;
        else high = mid;
    }
    return low < count ? (int)low : -1;
}

// One split for both levels. Cutting at the half keeps the left half's greatest
// key as the new separator and leaves the parent's existing separator standing
// for the right half, so the shapes do not diverge.
static int node_split(const u8 *full, u8 *left, u8 *right, u32 level,
                      struct adytumfs_tree_key *split_key) {
    if (!full || !left || !right || !split_key) return -1;
    if (adytumfs_tree_node_check(full, level)) return -1;
    u32 count = adytumfs_read_le32(full + 8);
    if (count < 2u) return -1;
    u32 stride = level_stride(level);
    u32 half = count / 2u;
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++) {
        left[index] = 0;
        right[index] = 0;
    }
    write_header(left, level, half);
    write_header(right, level, count - half);
    for (u32 index = 0; index < half; index++) {
        const u8 *from = full + ADYTUMFS_TREE_HEADER_SIZE + index * stride;
        u8 *to = left + ADYTUMFS_TREE_HEADER_SIZE + index * stride;
        for (u32 byte = 0; byte < stride; byte++) to[byte] = from[byte];
    }
    for (u32 index = half; index < count; index++) {
        const u8 *from = full + ADYTUMFS_TREE_HEADER_SIZE + index * stride;
        u8 *to = right + ADYTUMFS_TREE_HEADER_SIZE + (index - half) * stride;
        for (u32 byte = 0; byte < stride; byte++) to[byte] = from[byte];
    }
    read_key(left + ADYTUMFS_TREE_HEADER_SIZE + (half - 1u) * stride,
             split_key);
    return 0;
}

int adytumfs_tree_leaf_split(const u8 *full, u8 *left, u8 *right,
                             struct adytumfs_tree_key *split_key) {
    return node_split(full, left, right, 0, split_key);
}

int adytumfs_tree_branch_split(const u8 *full, u8 *left, u8 *right,
                               struct adytumfs_tree_key *split_key) {
    return node_split(full, left, right, 1, split_key);
}

struct adytumfs_tree_step {
    u8 hash[ADYTUMFS_CAS_HASH_SIZE];
    u32 index;
    u32 level;
};

struct adytumfs_tree_growth {
    u8 left[ADYTUMFS_CAS_HASH_SIZE];
    u8 right[ADYTUMFS_CAS_HASH_SIZE];
    struct adytumfs_tree_key left_max;
    struct adytumfs_tree_key right_max;
    int split;
};

// Node buffers are static rather than on the stack because a 4 KiB frame per
// level would cost more stack than the deepest syscall path has, and this file
// runs under the filesystem lock the way the bitmap and location scratch
// buffers do.
static u8 tree_node[ADYTUMFS_BLOCK_SIZE];
static u8 tree_left[ADYTUMFS_BLOCK_SIZE];
static u8 tree_right[ADYTUMFS_BLOCK_SIZE];

int adytumfs_tree_root_empty(const u8 root[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!root) return 1;
    for (u32 index = 0; index < ADYTUMFS_CAS_HASH_SIZE; index++)
        if (root[index]) return 0;
    return 1;
}

// Resolve a hash to a block and read it. The caller checks the level, because
// the root declares its own while every child must be exactly one below its
// parent.
static int tree_fetch(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store,
                      const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u8 *block) {
    u64 number = 0;
    if (adytumfs_cas_lookup(device, super, store, hash, &number)) return -1;
    if (adytumfs_data_read(device, super, number, block)) return -1;
    // Compare against the hash the parent stored. Skipping this would make
    // that hash decorative: a block silently holding something else would be
    // walked as if it were the node that was promised.
    u8 actual[ADYTUMFS_CAS_HASH_SIZE];
    if (adytumfs_tree_node_hash(block, actual)) return -1;
    if (!crypto_equal(actual, hash, ADYTUMFS_CAS_HASH_SIZE)) return -1;
    return 0;
}

static int tree_store(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store, const u8 *block,
                      u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    if (adytumfs_tree_node_hash(block, hash)) return -1;
    u64 number = 0;
    if (adytumfs_cas_place(device, super, store, hash, &number)) return -1;
    // A branch holds a reference on every child it names, taken here rather
    // than at each pack site so that no new store can forget it. Without this
    // the count says how often a node was written rather than how many parents
    // reach it, and a discard frees subtrees the committed root still uses.
    if (adytumfs_read_le32(block + 4) == 1u) {
        u32 count = adytumfs_read_le32(block + 8);
        for (u32 index = 0; index < count; index++)
            if (adytumfs_cas_retain(device, super, store,
                                    block + ADYTUMFS_TREE_HEADER_SIZE +
                                        index *
                                            ADYTUMFS_TREE_BRANCH_ENTRY_SIZE +
                                        ADYTUMFS_TREE_KEY_SIZE))
                return -1;
    }
    return adytumfs_data_write(device, super, number, block);
}

static void hash_copy(u8 *to, const u8 *from) {
    for (u32 index = 0; index < ADYTUMFS_CAS_HASH_SIZE; index++)
        to[index] = from[index];
}

// Walk from the root to the leaf that owns key, recording each node's hash,
// its level and the entry index the descent took. The recorded path is what
// lets the insert rewrite bottom up without recursion.
static void key_from_entry(const u8 *block, u32 index, u32 level,
                           struct adytumfs_tree_key *key) {
    const u8 *entry = block + ADYTUMFS_TREE_HEADER_SIZE +
        index * level_stride(level);
    key->end = adytumfs_read_le64(entry);
}

static int tree_descend(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                        const struct adytumfs_tree_key *key,
                        struct adytumfs_tree_step *path, u32 *depth,
                        int *found) {
    u8 current[ADYTUMFS_CAS_HASH_SIZE];
    hash_copy(current, root);
    u32 level = 0;
    for (u32 step = 0; step < ADYTUMFS_TREE_DEPTH_MAX; step++) {
        if (tree_fetch(device, super, store, current, tree_node)) return -1;
        if (!step) level = adytumfs_read_le32(tree_node + 4);
        else if (adytumfs_read_le32(tree_node + 4) != level) return -1;
        if (level > ADYTUMFS_TREE_DEPTH_MAX) return -1;
        if (adytumfs_tree_node_check(tree_node, level)) return -1;
        u32 count = adytumfs_read_le32(tree_node + 8);
        int index = adytumfs_tree_node_search(tree_node, key);
        path[step].level = level;
        hash_copy(path[step].hash, current);
        if (!level) {
            // node_search returns a lower bound, so the slot it lands on is the
            // place the key belongs in but only proves a hit once the key there
            // is compared. Callers that rewrite must not read a lower bound as
            // an existing entry.
            path[step].index = index >= 0 ? (u32)index : count;
            *depth = step + 1u;
            *found = -1;
            if (index >= 0) {
                struct adytumfs_tree_key candidate;
                key_from_entry(tree_node, (u32)index, 0, &candidate);
                if (key_equal(&candidate, key)) *found = index;
            }
            return 0;
        }
        // In a branch it is the child to descend into, and a key above every
        // separator belongs to the last child, not to a child past the end.
        if (index < 0) index = (int)count - 1;
        path[step].index = (u32)index;
        hash_copy(current, tree_node + ADYTUMFS_TREE_HEADER_SIZE +
                  (u32)index * ADYTUMFS_TREE_BRANCH_ENTRY_SIZE +
                  ADYTUMFS_TREE_KEY_SIZE);
        level--;
    }
    return -1;
}


static int leaf_insert(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, const u8 *node, u32 at,
                       int replace, const struct adytumfs_tree_key *key,
                       const struct adytumfs_tree_value *value,
                       struct adytumfs_tree_growth *growth) {
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_LEAF_MAX];
    static struct adytumfs_tree_value values[ADYTUMFS_TREE_LEAF_MAX];
    u32 count = 0;
    if (adytumfs_tree_leaf_unpack(node, &count, keys, values)) return -1;
    if (replace) {
        values[at] = *value;
        if (adytumfs_tree_leaf_pack(tree_node, count, keys, values)) return -1;
        growth->split = 0;
        key_from_entry(tree_node, count - 1u, 0, &growth->left_max);
        return tree_store(device, super, store, tree_node, growth->left);
    }
    if (count < ADYTUMFS_TREE_LEAF_MAX) {
        for (u32 index = count; index > at; index--) {
            keys[index] = keys[index - 1u];
            values[index] = values[index - 1u];
        }
        keys[at] = *key;
        values[at] = *value;
        if (adytumfs_tree_leaf_pack(tree_node, count + 1u, keys, values))
            return -1;
        growth->split = 0;
        key_from_entry(tree_node, count, 0, &growth->left_max);
        return tree_store(device, super, store, tree_node, growth->left);
    }
    // A full leaf splits before the entry goes in, so both halves have room and
    // no array ever has to hold one more entry than the format allows.
    struct adytumfs_tree_key separator;
    if (adytumfs_tree_leaf_split(node, tree_left, tree_right, &separator))
        return -1;
    u8 *target = key_less(key, &separator) ? tree_left : tree_right;
    u8 *other = target == tree_left ? tree_right : tree_left;
    u32 half = 0;
    if (adytumfs_tree_leaf_unpack(target, &half, keys, values)) return -1;
    u32 place = 0;
    while (place < half && key_less(&keys[place], key)) place++;
    for (u32 index = half; index > place; index--) {
        keys[index] = keys[index - 1u];
        values[index] = values[index - 1u];
    }
    keys[place] = *key;
    values[place] = *value;
    if (adytumfs_tree_leaf_pack(target, half + 1u, keys, values)) return -1;
    growth->split = 1;
    key_from_entry(tree_left, adytumfs_read_le32(tree_left + 8) - 1u, 0,
                   &growth->left_max);
    key_from_entry(tree_right, adytumfs_read_le32(tree_right + 8) - 1u, 0,
                   &growth->right_max);
    if (tree_store(device, super, store, other,
                   target == tree_left ? growth->right : growth->left))
        return -1;
    return tree_store(device, super, store, target,
                      target == tree_left ? growth->left : growth->right);
}

// Rewrite one branch on the way up: the child the descent took is replaced by
// the carried node, and a split adds the right half beside it. The separator
// for that child becomes the subtree's new greatest key, which is the one
// thing an insert into the rightmost child can change.
static int branch_rewrite(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store, const u8 *node,
                          u32 at, const struct adytumfs_tree_growth *below,
                          struct adytumfs_tree_growth *growth) {
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_BRANCH_MAX];
    static u8 children[ADYTUMFS_TREE_BRANCH_MAX][ADYTUMFS_CAS_HASH_SIZE];
    u32 count = 0;
    if (adytumfs_tree_branch_unpack(node, &count, keys, children)) return -1;
    if (at >= count) return -1;

    // A full branch that has to gain an entry splits first, so the entry lands
    // in a half with room and the arrays never exceed what the format holds.
    if (below->split && count == ADYTUMFS_TREE_BRANCH_MAX) {
        struct adytumfs_tree_key separator;
        if (adytumfs_tree_branch_pack(tree_node, count, keys, children) ||
            adytumfs_tree_branch_split(tree_node, tree_left, tree_right,
                                       &separator))
            return -1;
        u32 left_count = adytumfs_read_le32(tree_left + 8);
        u8 *target = at < left_count ? tree_left : tree_right;
        u8 *other = target == tree_left ? tree_right : tree_left;
        u32 place = at < left_count ? at : at - left_count;
        u32 half = 0;
        if (adytumfs_tree_branch_unpack(target, &half, keys, children))
            return -1;
        if (place >= half || half + 1u >= ADYTUMFS_TREE_BRANCH_MAX) return -1;
        keys[place] = below->left_max;
        hash_copy(children[place], below->left);
        for (u32 index = half; index > place + 1u; index--) {
            keys[index] = keys[index - 1u];
            hash_copy(children[index], children[index - 1u]);
        }
        keys[place + 1u] = below->right_max;
        hash_copy(children[place + 1u], below->right);
        if (adytumfs_tree_branch_pack(target, half + 1u, keys, children))
            return -1;
        growth->split = 1;
        key_from_entry(tree_left,
                       adytumfs_read_le32(tree_left + 8) - 1u, 1,
                       &growth->left_max);
        key_from_entry(tree_right,
                       adytumfs_read_le32(tree_right + 8) - 1u, 1,
                       &growth->right_max);
        if (tree_store(device, super, store, other,
                       target == tree_left ? growth->right : growth->left))
            return -1;
        return tree_store(device, super, store, target,
                          target == tree_left ? growth->left : growth->right);
    }

    keys[at] = below->left_max;
    hash_copy(children[at], below->left);
    u32 total = count;
    if (below->split) {
        if (count >= ADYTUMFS_TREE_BRANCH_MAX) return -1;
        for (u32 index = count; index > at + 1u; index--) {
            keys[index] = keys[index - 1u];
            hash_copy(children[index], children[index - 1u]);
        }
        keys[at + 1u] = below->right_max;
        hash_copy(children[at + 1u], below->right);
        total = count + 1u;
    }
    if (adytumfs_tree_branch_pack(tree_node, total, keys, children)) return -1;
    growth->split = 0;
    key_from_entry(tree_node, total - 1u, 1, &growth->left_max);
    return tree_store(device, super, store, tree_node, growth->left);
}

int adytumfs_tree_lookup(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                         const struct adytumfs_tree_key *key,
                         struct adytumfs_tree_value *value) {
    if (!device || !super || !store || !root || !key || !value) return -1;
    if (adytumfs_tree_root_empty(root)) return -1;
    static struct adytumfs_tree_step path[ADYTUMFS_TREE_DEPTH_MAX];
    u32 depth = 0;
    int found = -1;
    if (tree_descend(device, super, store, root, key, path, &depth, &found))
        return -1;
    if (found < 0) return -1;
    if (tree_fetch(device, super, store, path[depth - 1u].hash, tree_node))
        return -1;
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_LEAF_MAX];
    static struct adytumfs_tree_value values[ADYTUMFS_TREE_LEAF_MAX];
    u32 count = 0;
    if (adytumfs_tree_leaf_unpack(tree_node, &count, keys, values)) return -1;
    if ((u32)found >= count) return -1;
    if (keys[found].end != key->end) return -1;
    *value = values[found];
    return 0;
}

static int tree_insert(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                       const struct adytumfs_tree_key *key,
                       const struct adytumfs_tree_value *value,
                       u8 new_root[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!device || !super || !store || !root || !key || !value || !new_root)
        return -1;
    if (adytumfs_tree_root_empty(root)) {
        if (adytumfs_tree_leaf_pack(tree_node, 1u, key, value)) return -1;
        return tree_store(device, super, store, tree_node, new_root);
    }
    static struct adytumfs_tree_step path[ADYTUMFS_TREE_DEPTH_MAX];
    u32 depth = 0;
    int found = -1;
    if (tree_descend(device, super, store, root, key, path, &depth, &found))
        return -1;
    struct adytumfs_tree_growth below;
    struct adytumfs_tree_growth above;
    // The leaf and each branch are copied out of the shared node buffer before
    // being rewritten, because the rewrite writes its result back into that
    // same buffer. Static for the same reason the node buffers are.
    static u8 node_copy[ADYTUMFS_BLOCK_SIZE];
    if (tree_fetch(device, super, store, path[depth - 1u].hash, tree_node))
        return -1;
    // The leaf is copied out of the shared buffer because the insert writes its
    // result back into that same buffer.
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        node_copy[index] = tree_node[index];
    u32 at = found >= 0 ? (u32)found : path[depth - 1u].index;
    if (leaf_insert(device, super, store, node_copy, at, found >= 0, key,
                    value, &below))
        return -1;
    for (u32 step = depth - 1u; step > 0; step--) {
        if (tree_fetch(device, super, store, path[step - 1u].hash, tree_node))
            return -1;
        for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
            node_copy[index] = tree_node[index];
        if (branch_rewrite(device, super, store, node_copy,
                           path[step - 1u].index, &below, &above))
            return -1;
        below = above;
    }
    if (!below.split) {
        hash_copy(new_root, below.left);
        return 0;
    }
    // The root split, so the tree grew a level. The two halves become the
    // whole of a new branch root.
    struct adytumfs_tree_key keys[2];
    u8 children[2][ADYTUMFS_CAS_HASH_SIZE];
    keys[0] = below.left_max;
    keys[1] = below.right_max;
    hash_copy(children[0], below.left);
    hash_copy(children[1], below.right);
    if (adytumfs_tree_branch_pack(tree_node, 2u, keys, children)) return -1;
    return tree_store(device, super, store, tree_node, new_root);
}

// The bottom up result of a removal. A node that lost its last entry is never
// stored, because node_check requires at least one entry: an empty node is not
// a node this filesystem writes, so the parent drops the entry that named it
// instead of being handed a hash for nothing.
struct adytumfs_tree_shrink {
    u8 child[ADYTUMFS_CAS_HASH_SIZE];
    struct adytumfs_tree_key child_max;
    int gone;
};

static int leaf_remove(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, const u8 *node, u32 at,
                       struct adytumfs_tree_shrink *below) {
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_LEAF_MAX];
    static struct adytumfs_tree_value values[ADYTUMFS_TREE_LEAF_MAX];
    u32 count = 0;
    if (adytumfs_tree_leaf_unpack(node, &count, keys, values)) return -1;
    if (at >= count) return -1;
    if (count == 1u) {
        below->gone = 1;
        return 0;
    }
    for (u32 index = at; index + 1u < count; index++) {
        keys[index] = keys[index + 1u];
        values[index] = values[index + 1u];
    }
    if (adytumfs_tree_leaf_pack(tree_node, count - 1u, keys, values)) return -1;
    below->gone = 0;
    key_from_entry(tree_node, count - 2u, 0, &below->child_max);
    return tree_store(device, super, store, tree_node, below->child);
}

static int branch_remove(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store, const u8 *node,
                         u32 at, int is_root,
                         const struct adytumfs_tree_shrink *below,
                         struct adytumfs_tree_shrink *above) {
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_BRANCH_MAX];
    static u8 children[ADYTUMFS_TREE_BRANCH_MAX][ADYTUMFS_CAS_HASH_SIZE];
    u32 count = 0;
    if (adytumfs_tree_branch_unpack(node, &count, keys, children)) return -1;
    if (at >= count) return -1;
    u32 total = count;
    if (below->gone) {
        for (u32 index = at; index + 1u < count; index++) {
            keys[index] = keys[index + 1u];
            hash_copy(children[index], children[index + 1u]);
        }
        total = count - 1u;
        if (!total) {
            above->gone = 1;
            return 0;
        }
    } else {
        // A separator stays correct if it is left alone, because routing only
        // needs it below the next child's first key and removing the greatest
        // key cannot break that. It is rewritten anyway: the format defines a
        // separator as exactly the subtree's greatest key, and a tree whose
        // separators drift stops being the tree the format describes.
        keys[at] = below->child_max;
        hash_copy(children[at], below->child);
    }
    // A root left with one child is a level the tree no longer needs. Dropping
    // it here rather than after the store matters: a one entry branch written
    // first would be referenced by nothing afterwards and stay in the index as
    // garbage no root can reach.
    if (is_root && total == 1u) {
        above->gone = 0;
        hash_copy(above->child, children[0]);
        return 0;
    }
    if (adytumfs_tree_branch_pack(tree_node, total, keys, children)) return -1;
    above->gone = 0;
    key_from_entry(tree_node, total - 1u, 1, &above->child_max);
    return tree_store(device, super, store, tree_node, above->child);
}

// Removal is copy on write like insert: only the path to the key is rewritten
// and the result is a new root, so the old root still names a complete tree.
// Underfull nodes are not rebalanced, the way ZFS does not rebalance either;
// the exception is the root, because the height lives there and a tree that
// grew deep and then shrank would otherwise walk the empty levels forever.
static int tree_remove(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                       const struct adytumfs_tree_key *key,
                       u8 new_root[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!device || !super || !store || !root || !key || !new_root) return -1;
    if (adytumfs_tree_root_empty(root)) return -1;
    static struct adytumfs_tree_step path[ADYTUMFS_TREE_DEPTH_MAX];
    u32 depth = 0;
    int found = -1;
    if (tree_descend(device, super, store, root, key, path, &depth, &found))
        return -1;
    // An absent key is an error rather than a no op: every caller removes an
    // extent it believes is there, and a silent nothing would hide the
    // disagreement between the caller's picture and the tree.
    if (found < 0) return -1;
    struct adytumfs_tree_shrink below;
    struct adytumfs_tree_shrink above;
    static u8 node_copy[ADYTUMFS_BLOCK_SIZE];
    if (tree_fetch(device, super, store, path[depth - 1u].hash, tree_node))
        return -1;
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        node_copy[index] = tree_node[index];
    if (leaf_remove(device, super, store, node_copy, (u32)found, &below))
        return -1;
    for (u32 step = depth - 1u; step > 0; step--) {
        if (tree_fetch(device, super, store, path[step - 1u].hash, tree_node))
            return -1;
        for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
            node_copy[index] = tree_node[index];
        if (branch_remove(device, super, store, node_copy,
                          path[step - 1u].index, step == 1u, &below, &above))
            return -1;
        below = above;
    }
    if (below.gone) {
        for (u32 index = 0; index < ADYTUMFS_CAS_HASH_SIZE; index++)
            new_root[index] = 0;
        return 0;
    }
    hash_copy(new_root, below.child);
    return 0;
}

// Find the entry that covers a byte offset. The key is the exclusive end, so
// the covering entry is the first one whose end is above the offset, which is
// the lower bound the descent already lands on. The extra start check is what
// separates "covered" from "in a hole": a file with a gap has entries on both
// sides of it, and the lower bound of an offset inside the gap is the entry
// after the gap.
static int tree_find(struct kernel_object *device,
                     struct adytumfs_superblock *super,
                     struct adytumfs_cas *store,
                     const u8 root[ADYTUMFS_CAS_HASH_SIZE], u64 offset,
                     struct adytumfs_tree_span *span) {
    if (!device || !super || !store || !root || !span) return -1;
    if (adytumfs_tree_root_empty(root)) return -1;
    if (offset + 1u == 0) return -1;
    struct adytumfs_tree_key probe;
    probe.end = offset + 1u;
    static struct adytumfs_tree_step path[ADYTUMFS_TREE_DEPTH_MAX];
    u32 depth = 0;
    int found = -1;
    if (tree_descend(device, super, store, root, &probe, path, &depth, &found))
        return -1;
    if (tree_fetch(device, super, store, path[depth - 1u].hash, tree_node))
        return -1;
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_LEAF_MAX];
    static struct adytumfs_tree_value values[ADYTUMFS_TREE_LEAF_MAX];
    u32 count = 0;
    if (adytumfs_tree_leaf_unpack(tree_node, &count, keys, values)) return -1;
    u32 at = path[depth - 1u].index;
    if (at >= count) return -1;
    if (keys[at].end - values[at].length > offset) return -1;
    span->start = keys[at].end - values[at].length;
    span->end = keys[at].end;
    for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
        span->hash[byte] = values[at].hash[byte];
    return 0;
}

// Drop every entry at or above a byte offset and shorten the one that
// straddles it. Only a suffix goes, so the entries that survive are a prefix
// of the leaf and the last of them is the only one whose length can change.
static int leaf_truncate(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store, const u8 *node, u64 at,
                         struct adytumfs_tree_shrink *below) {
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_LEAF_MAX];
    static struct adytumfs_tree_value values[ADYTUMFS_TREE_LEAF_MAX];
    u32 count = 0;
    if (adytumfs_tree_leaf_unpack(node, &count, keys, values)) return -1;
    u32 keep = count;
    for (u32 index = 0; index < count; index++) {
        if (keys[index].end < at) continue;
        u64 start = keys[index].end - values[index].length;
        if (keys[index].end == at || start < at) {
            // The straddler keeps the part below the cut, so both of its
            // fields move: the end becomes the cut and the length is what is
            // left below it. Leaving the end alone would keep the entry
            // structurally valid and silently point it at the wrong blocks.
            keys[index].end = at;
            values[index].length = at - start;
            keep = index + 1u;
        } else {
            keep = index;
        }
        break;
    }
    if (!keep) {
        below->gone = 1;
        return 0;
    }
    if (adytumfs_tree_leaf_pack(tree_node, keep, keys, values)) return -1;
    below->gone = 0;
    key_from_entry(tree_node, keep - 1u, 0, &below->child_max);
    return tree_store(device, super, store, tree_node, below->child);
}

// Rewrite one branch on the way up from a truncation. Everything after the
// descended child goes with it: the descent picked the first child whose
// separator reaches the cut, so every child past that one holds keys strictly
// above it and has nothing left to keep. The dropped subtrees are not freed
// here, they simply stop being reachable and the collection walk takes them.
static int branch_truncate(struct kernel_object *device,
                           struct adytumfs_superblock *super,
                           struct adytumfs_cas *store, const u8 *node,
                           u32 at, int is_root,
                           const struct adytumfs_tree_shrink *below,
                           struct adytumfs_tree_shrink *above) {
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_BRANCH_MAX];
    static u8 children[ADYTUMFS_TREE_BRANCH_MAX][ADYTUMFS_CAS_HASH_SIZE];
    u32 count = 0;
    if (adytumfs_tree_branch_unpack(node, &count, keys, children)) return -1;
    if (at >= count) return -1;
    u32 total = at;
    if (!below->gone) {
        keys[at] = below->child_max;
        hash_copy(children[at], below->child);
        total = at + 1u;
    }
    if (!total) {
        above->gone = 1;
        return 0;
    }
    // A root left with one child is a level the tree no longer needs, and it is
    // dropped before the store for the same reason a removal drops it: a one
    // entry branch written first would be reachable from nothing afterwards.
    if (is_root && total == 1u) {
        above->gone = 0;
        hash_copy(above->child, children[0]);
        return 0;
    }
    if (adytumfs_tree_branch_pack(tree_node, total, keys, children)) return -1;
    above->gone = 0;
    key_from_entry(tree_node, total - 1u, 1, &above->child_max);
    return tree_store(device, super, store, tree_node, above->child);
}

static int tree_truncate(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_CAS_HASH_SIZE], u64 at,
                         u8 new_root[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!device || !super || !store || !root || !new_root) return -1;
    if (at & (ADYTUMFS_BLOCK_SIZE - 1u)) return -1;
    for (u32 index = 0; index < ADYTUMFS_CAS_HASH_SIZE; index++)
        new_root[index] = 0;
    if (adytumfs_tree_root_empty(root)) return 0;
    struct adytumfs_tree_key probe;
    probe.end = at;
    static struct adytumfs_tree_step path[ADYTUMFS_TREE_DEPTH_MAX];
    u32 depth = 0;
    int found = -1;
    if (tree_descend(device, super, store, root, &probe, path, &depth, &found))
        return -1;
    struct adytumfs_tree_shrink below;
    struct adytumfs_tree_shrink above;
    static u8 node_copy[ADYTUMFS_BLOCK_SIZE];
    if (tree_fetch(device, super, store, path[depth - 1u].hash, tree_node))
        return -1;
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        node_copy[index] = tree_node[index];
    if (leaf_truncate(device, super, store, node_copy, at, &below)) return -1;
    for (u32 step = depth - 1u; step > 0; step--) {
        if (tree_fetch(device, super, store, path[step - 1u].hash, tree_node))
            return -1;
        for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
            node_copy[index] = tree_node[index];
        if (branch_truncate(device, super, store, node_copy,
                            path[step - 1u].index, step == 1u, &below, &above))
            return -1;
        below = above;
    }
    if (below.gone) return 0;
    hash_copy(new_root, below.child);
    return 0;
}

struct adytumfs_tree_discard_item {
    u8 hash[ADYTUMFS_CAS_HASH_SIZE];
    u32 depth;
};

// Depth first over an explicit stack, because the walk is as deep as the tree
// and a recursive one would put that depth on the kernel stack. The bound is
// the worst case for depth first: every level leaves its other children
// pending while one of them is descended into.
#define ADYTUMFS_TREE_DISCARD_STACK \
    (ADYTUMFS_TREE_DEPTH_MAX * ADYTUMFS_TREE_BRANCH_MAX)

static struct adytumfs_tree_discard_item
    discard_stack[ADYTUMFS_TREE_DISCARD_STACK];
static u32 discard_top;

static int discard_run(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u32 budget,
                       u32 *remaining) {
    static u8 children[ADYTUMFS_TREE_BRANCH_MAX][ADYTUMFS_CAS_HASH_SIZE];
    u32 spent = 0;
    while (discard_top && spent < budget) {
        discard_top--;
        u8 hash[ADYTUMFS_CAS_HASH_SIZE];
        hash_copy(hash, discard_stack[discard_top].hash);
        u32 depth = discard_stack[discard_top].depth;
        u32 refs = 0;
        if (adytumfs_cas_refs(device, super, store, hash, &refs)) return -1;
        if (!refs) return -1;
        if (tree_fetch(device, super, store, hash, tree_node)) return -1;
        u32 level = adytumfs_read_le32(tree_node + 4);
        if (level > 1u) return -1;
        if (adytumfs_tree_node_check(tree_node, level)) return -1;
        u32 count = adytumfs_read_le32(tree_node + 8);
        // Children are copied out before the release, because dropping the
        // last reference hands the block back to the allocator and the next
        // allocation is free to overwrite it.
        if (level) {
            for (u32 index = 0; index < count; index++)
                hash_copy(children[index],
                          tree_node + ADYTUMFS_TREE_HEADER_SIZE +
                              index * ADYTUMFS_TREE_BRANCH_ENTRY_SIZE +
                              ADYTUMFS_TREE_KEY_SIZE);
        }
        if (adytumfs_cas_release(device, super, store, hash)) return -1;
        spent++;
        // Only a node whose last reference just went takes its children with
        // it. One still held elsewhere belongs to that holder, and a later
        // pass over it will see refs reach one and descend then.
        if (refs != 1u || !level) continue;
        for (u32 index = 0; index < count; index++) {
            if (discard_top >= ADYTUMFS_TREE_DISCARD_STACK) return -1;
            if (depth + 1u > ADYTUMFS_TREE_DEPTH_MAX) return -1;
            hash_copy(discard_stack[discard_top].hash, children[index]);
            discard_stack[discard_top].depth = depth + 1u;
            discard_top++;
        }
    }
    *remaining = discard_top;
    return 0;
}

int adytumfs_tree_find(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_CAS_HASH_SIZE], u64 offset,
                       struct adytumfs_tree_span *span) {
    return tree_find(device, super, store, root, offset, span);
}

int adytumfs_tree_truncate(struct kernel_object *device,
                           struct adytumfs_superblock *super,
                           struct adytumfs_cas *store,
                           const u8 root[ADYTUMFS_CAS_HASH_SIZE], u64 at,
                           u8 new_root[ADYTUMFS_CAS_HASH_SIZE]) {
    if (tree_truncate(device, super, store, root, at, new_root)) return -1;
    if (adytumfs_tree_root_empty(new_root)) return 0;
    return adytumfs_cas_retain(device, super, store, new_root);
}

int adytumfs_tree_discard(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store,
                          const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                          u32 budget, u32 *remaining) {
    if (!device || !super || !store || !root || !remaining || !budget)
        return -1;
    // A walk already in flight owns the stack. Starting a second one would
    // drop the first half finished and leak everything it had not reached.
    if (discard_top) return -1;
    if (adytumfs_tree_root_empty(root)) {
        *remaining = 0;
        return 0;
    }
    hash_copy(discard_stack[0].hash, root);
    discard_stack[0].depth = 1u;
    discard_top = 1u;
    return discard_run(device, super, store, budget, remaining);
}

int adytumfs_tree_discard_resume(struct kernel_object *device,
                                 struct adytumfs_superblock *super,
                                 struct adytumfs_cas *store,
                                 u32 budget, u32 *remaining) {
    if (!device || !super || !store || !remaining || !budget) return -1;
    return discard_run(device, super, store, budget, remaining);
}

int adytumfs_tree_remove(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                         const struct adytumfs_tree_key *key,
                         u8 new_root[ADYTUMFS_CAS_HASH_SIZE]) {
    if (tree_remove(device, super, store, root, key, new_root)) return -1;
    if (adytumfs_tree_root_empty(new_root)) return 0;
    return adytumfs_cas_retain(device, super, store, new_root);
}

int adytumfs_tree_insert(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                         const struct adytumfs_tree_key *key,
                         const struct adytumfs_tree_value *value,
                         u8 new_root[ADYTUMFS_CAS_HASH_SIZE]) {
    if (tree_insert(device, super, store, root, key, value, new_root))
        return -1;
    // Every other node is reached through its parent, and the root's parent is
    // whoever commits it, so the caller is handed a reference and drops it by
    // discarding that root once a later one is committed. Without this the
    // root would have no parent at all and the first discard would free the
    // whole tree out from under whoever is holding it.
    return adytumfs_cas_retain(device, super, store, new_root);
}
