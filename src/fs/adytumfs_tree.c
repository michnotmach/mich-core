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

static int key_less(const struct adytumfs_tree_key *left,
                    const struct adytumfs_tree_key *right) {
    if (left->object_id != right->object_id)
        return left->object_id < right->object_id;
    return left->offset < right->offset;
}

static void write_key(u8 *entry, const struct adytumfs_tree_key *key) {
    adytumfs_write_le64(entry, key->object_id);
    adytumfs_write_le64(entry + 8, key->offset);
}

static void read_key(const u8 *entry, struct adytumfs_tree_key *key) {
    key->object_id = adytumfs_read_le64(entry);
    key->offset = adytumfs_read_le64(entry + 8);
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
    if (node_pack(block, 0, count, keys)) return -1;
    for (u32 index = 0; index < count; index++) {
        u8 *entry = block + ADYTUMFS_TREE_HEADER_SIZE +
            index * ADYTUMFS_TREE_LEAF_ENTRY_SIZE + ADYTUMFS_TREE_KEY_SIZE;
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            entry[byte] = values[index].hash[byte];
        adytumfs_write_le32(entry + ADYTUMFS_CAS_HASH_SIZE,
                            values[index].length);
        adytumfs_write_le32(entry + ADYTUMFS_CAS_HASH_SIZE + 4,
                            values[index].flags);
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
        values[index].length = adytumfs_read_le32(value + ADYTUMFS_CAS_HASH_SIZE);
        values[index].flags =
            adytumfs_read_le32(value + ADYTUMFS_CAS_HASH_SIZE + 4);
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
