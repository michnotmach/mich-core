#include "types.h"
#include "blake2b.h"
#include "crypto.h"
#include "adytumfs_tree.h"

static struct adytumfs_tree_key key_at(u64 object, u64 offset) {
    struct adytumfs_tree_key key;
    key.object_id = object;
    key.offset = offset;
    return key;
}

// Deterministic filler so a round trip that drops or reorders a byte shows up
// as a mismatch rather than as two matching zero pages.
static void value_at(u32 index, struct adytumfs_tree_value *value) {
    u8 seed[4];
    for (u32 byte = 0; byte < 4; byte++)
        seed[byte] = (u8)(index >> (byte * 8));
    blake2b(value->hash, ADYTUMFS_CAS_HASH_SIZE, seed, 4);
    value->length = index + 1u;
    value->flags = index * 3u;
}

int test_adytumfs_tree64(void) {
    static u8 node[ADYTUMFS_BLOCK_SIZE];
    static u8 left[ADYTUMFS_BLOCK_SIZE];
    static u8 right[ADYTUMFS_BLOCK_SIZE];
    static u8 other[ADYTUMFS_BLOCK_SIZE];
    // Key arrays are sized by the branch capacity because it is the larger of
    // the two, and the branch cases fill them to that bound.
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_BRANCH_MAX];
    static struct adytumfs_tree_value values[ADYTUMFS_TREE_LEAF_MAX];
    static struct adytumfs_tree_key keys_back[ADYTUMFS_TREE_BRANCH_MAX];
    static struct adytumfs_tree_value values_back[ADYTUMFS_TREE_LEAF_MAX];
    static u8 children[ADYTUMFS_TREE_BRANCH_MAX][ADYTUMFS_CAS_HASH_SIZE];
    static u8 children_back[ADYTUMFS_TREE_BRANCH_MAX][ADYTUMFS_CAS_HASH_SIZE];

    const u32 count = ADYTUMFS_TREE_LEAF_MAX;
    for (u32 index = 0; index < count; index++) {
        keys[index] = key_at(1, index * 4096u);
        value_at(index, &values[index]);
    }

    int valid = adytumfs_tree_leaf_pack(node, count, keys, values) == 0 &&
        adytumfs_tree_node_check(node, 0) == 0;

    u32 got = 0;
    valid = valid &&
        adytumfs_tree_leaf_unpack(node, &got, keys_back, values_back) == 0 &&
        got == count;
    for (u32 index = 0; valid && index < count; index++) {
        valid = keys_back[index].object_id == keys[index].object_id &&
            keys_back[index].offset == keys[index].offset &&
            values_back[index].length == values[index].length &&
            values_back[index].flags == values[index].flags &&
            crypto_equal(values_back[index].hash, values[index].hash,
                         ADYTUMFS_CAS_HASH_SIZE);
    }

    // The node hash covers the whole packed block, so one changed byte in one
    // entry has to move it. This is what makes the parent's promise about a
    // child worth anything.
    u8 hash[ADYTUMFS_CAS_HASH_SIZE];
    u8 hash2[ADYTUMFS_CAS_HASH_SIZE];
    valid = valid && adytumfs_tree_node_hash(node, hash) == 0 &&
        adytumfs_tree_node_hash(node, hash2) == 0 &&
        crypto_equal(hash, hash2, ADYTUMFS_CAS_HASH_SIZE);
    node[ADYTUMFS_TREE_HEADER_SIZE + 20] ^= 0xFFu;
    valid = valid && adytumfs_tree_node_hash(node, hash2) == 0 &&
        !crypto_equal(hash, hash2, ADYTUMFS_CAS_HASH_SIZE);
    node[ADYTUMFS_TREE_HEADER_SIZE + 20] ^= 0xFFu;

    // A node this filesystem did not write is refused, on every field that
    // carries meaning.
    u8 saved[4];
    for (u32 index = 0; index < 4; index++) saved[index] = node[index];
    node[0] ^= 0xFFu;
    valid = valid && adytumfs_tree_node_check(node, 0) != 0;
    node[0] = saved[0];
    valid = valid && adytumfs_tree_node_check(node, 1) != 0;
    node[9] = (u8)count;
    node[8] = 0;
    valid = valid && adytumfs_tree_node_check(node, 0) != 0;
    node[8] = (u8)count;
    node[9] = 0;
    valid = valid && adytumfs_tree_node_check(node, 0) == 0;
    // A repeated key would let the binary search step over a present entry.
    // Entry 1 holds offset 4096, whose low byte is already zero, so the whole
    // field has to be cleared to make it collide with entry 0.
    u8 *second_offset = node + ADYTUMFS_TREE_HEADER_SIZE +
        ADYTUMFS_TREE_LEAF_ENTRY_SIZE + 8;
    u8 saved_offset[8];
    for (u32 byte = 0; byte < 8; byte++) {
        saved_offset[byte] = second_offset[byte];
        second_offset[byte] = 0;
    }
    valid = valid && adytumfs_tree_node_check(node, 0) != 0;
    for (u32 byte = 0; byte < 8; byte++)
        second_offset[byte] = saved_offset[byte];
    valid = valid && adytumfs_tree_node_check(node, 0) == 0;

    // Search answers the first separator at or above the query, which in a
    // branch is the only subtree that can hold it.
    struct adytumfs_tree_key probe = key_at(1, 3 * 4096u);
    valid = valid && adytumfs_tree_node_search(node, &probe) == 3;
    probe = key_at(1, 3 * 4096u + 1u);
    valid = valid && adytumfs_tree_node_search(node, &probe) == 4;
    probe = key_at(1, 0);
    valid = valid && adytumfs_tree_node_search(node, &probe) == 0;
    probe = key_at(9, 0);
    valid = valid && adytumfs_tree_node_search(node, &probe) == -1;

    // Splitting a full leaf gives two valid halves, the separator is the left
    // half's greatest key, and no entry is lost or duplicated.
    struct adytumfs_tree_key split;
    valid = valid && adytumfs_tree_leaf_split(node, left, right, &split) == 0 &&
        adytumfs_tree_node_check(left, 0) == 0 &&
        adytumfs_tree_node_check(right, 0) == 0;
    u32 left_count = adytumfs_read_le32(left + 8);
    u32 right_count = adytumfs_read_le32(right + 8);
    valid = valid && left_count + right_count == count &&
        left_count == count / 2u &&
        split.object_id == keys[left_count - 1u].object_id &&
        split.offset == keys[left_count - 1u].offset;

    u32 left_got = 0;
    u32 right_got = 0;
    valid = valid &&
        adytumfs_tree_leaf_unpack(left, &left_got, keys_back,
                                  values_back) == 0 &&
        adytumfs_tree_leaf_unpack(right, &right_got, keys_back,
                                  values_back) == 0 &&
        left_got == left_count && right_got == right_count;

    // Every original key resolves in exactly one half, which is the property a
    // descent relies on: a key that answered in both would be read twice and a
    // key that answered in neither would be lost.
    for (u32 index = 0; valid && index < count; index++) {
        int in_left = adytumfs_tree_node_search(left, &keys[index]);
        int in_right = adytumfs_tree_node_search(right, &keys[index]);
        int hit_left = in_left >= 0 &&
            adytumfs_read_le64(left + ADYTUMFS_TREE_HEADER_SIZE +
                               (u32)in_left * ADYTUMFS_TREE_LEAF_ENTRY_SIZE) ==
                keys[index].object_id &&
            adytumfs_read_le64(left + ADYTUMFS_TREE_HEADER_SIZE +
                               (u32)in_left * ADYTUMFS_TREE_LEAF_ENTRY_SIZE +
                               8) == keys[index].offset;
        int hit_right = in_right >= 0 &&
            adytumfs_read_le64(right + ADYTUMFS_TREE_HEADER_SIZE +
                               (u32)in_right * ADYTUMFS_TREE_LEAF_ENTRY_SIZE) ==
                keys[index].object_id &&
            adytumfs_read_le64(right + ADYTUMFS_TREE_HEADER_SIZE +
                               (u32)in_right * ADYTUMFS_TREE_LEAF_ENTRY_SIZE +
                               8) == keys[index].offset;
        valid = (hit_left ? 1 : 0) + (hit_right ? 1 : 0) == 1;
    }

    // A branch splits by the same rule and its child hashes survive.
    for (u32 index = 0; index < ADYTUMFS_TREE_BRANCH_MAX; index++) {
        keys[index] = key_at(2, index);
        u8 seed[4];
        for (u32 byte = 0; byte < 4; byte++)
            seed[byte] = (u8)((index + 500u) >> (byte * 8));
        blake2b(children[index], ADYTUMFS_CAS_HASH_SIZE, seed, 4);
    }
    valid = valid &&
        adytumfs_tree_branch_pack(other, ADYTUMFS_TREE_BRANCH_MAX, keys,
                                  children) == 0 &&
        adytumfs_tree_node_check(other, 1) == 0 &&
        adytumfs_tree_branch_unpack(other, &got, keys_back,
                                    children_back) == 0 &&
        got == ADYTUMFS_TREE_BRANCH_MAX;
    for (u32 index = 0; valid && index < ADYTUMFS_TREE_BRANCH_MAX; index++)
        valid = crypto_equal(children_back[index], children[index],
                             ADYTUMFS_CAS_HASH_SIZE);
    valid = valid &&
        adytumfs_tree_branch_split(other, left, right, &split) == 0 &&
        adytumfs_tree_node_check(left, 1) == 0 &&
        adytumfs_tree_node_check(right, 1) == 0 &&
        adytumfs_read_le32(left + 8) == ADYTUMFS_TREE_BRANCH_MAX / 2u;

    // Packing refuses what it cannot represent, rather than writing a node
    // that check would later reject.
    valid = valid &&
        adytumfs_tree_leaf_pack(node, ADYTUMFS_TREE_LEAF_MAX + 1u, keys,
                                values) != 0 &&
        adytumfs_tree_leaf_pack(node, 0, keys, values) != 0;
    struct adytumfs_tree_key unsorted[2];
    unsorted[0] = key_at(5, 0);
    unsorted[1] = key_at(4, 0);
    valid = valid && adytumfs_tree_leaf_pack(node, 2, unsorted, values) != 0;

    return valid ? 0 : -1;
}
