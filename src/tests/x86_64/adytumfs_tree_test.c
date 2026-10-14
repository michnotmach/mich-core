#include "types.h"
#include "object.h"
#include "block.h"
#include "blake2b.h"
#include "crypto.h"
#include "adytumfs_tree.h"
#include "adytumfs_cas.h"

// A key is the exclusive end of an entry, and every entry here covers exactly
// one block, so entry index n ends at (n + 1) blocks and the run tiles the
// file with no hole and no overlap. Runs that used to be told apart by an
// object id are now told apart by where they sit: run two starts past run one.
static struct adytumfs_tree_key key_at(u64 index) {
    struct adytumfs_tree_key key;
    key.end = (index + 1u) * ADYTUMFS_BLOCK_SIZE;
    return key;
}

// A key the caller hands the tree rather than one it packs, so it may sit off
// a block boundary: that is exactly what a lookup for an absent offset does.
static struct adytumfs_tree_key key_end(u64 end) {
    struct adytumfs_tree_key key;
    key.end = end;
    return key;
}

// Deterministic filler so a round trip that drops or reorders a byte shows up
// as a mismatch rather than as two matching zero pages.
static void value_at(u32 index, struct adytumfs_tree_value *value) {
    u8 seed[4];
    for (u32 byte = 0; byte < 4; byte++)
        seed[byte] = (u8)(index >> (byte * 8));
    blake2b(value->hash, ADYTUMFS_CAS_HASH_SIZE, seed, 4);
    value->length = ADYTUMFS_BLOCK_SIZE;
}

// The tree resolves a node by hash, so it runs against the index mkfs
// reserved and recorded in the superblock. Nothing here allocates one, which
// is the point: a formatted volume arrives with a working index.
static int tree_index_empty(struct kernel_object *device,
                            const struct adytumfs_superblock *super,
                            struct adytumfs_cas *store) {
    struct adytumfs_index index;
    u64 live = 1;
    adytumfs_index_init(&index, super->index_start, super->index_blocks);
    if (adytumfs_index_live(device, super, &index, &live)) return -1;
    if (live) return -1;
    adytumfs_cas_open(store, super->index_start, super->index_blocks);
    return 0;
}

// A failure has to be distinguishable from a real zero, so it reads as
// something no live count can be.
static u64 tree_count(struct kernel_object *device,
                      const struct adytumfs_superblock *super,
                      struct adytumfs_cas *store) {
    u64 count = 0;
    if (adytumfs_cas_count(device, super, store, &count)) return (u64)-1;
    return count;
}

int test_adytumfs_tree64(void) {
    static u8 node[ADYTUMFS_BLOCK_SIZE];
    static u8 left[ADYTUMFS_BLOCK_SIZE];
    static u8 right[ADYTUMFS_BLOCK_SIZE];
    static u8 other[ADYTUMFS_BLOCK_SIZE];
    // Key arrays are sized by the branch capacity because it is the larger of
    // the two, and the branch cases fill them to that bound.
    static struct adytumfs_tree_key keys[ADYTUMFS_TREE_BRANCH_MAX];
    static struct adytumfs_tree_value values[ADYTUMFS_TREE_LEAF_MAX + 1u];
    static struct adytumfs_tree_key keys_back[ADYTUMFS_TREE_BRANCH_MAX];
    static struct adytumfs_tree_value values_back[ADYTUMFS_TREE_LEAF_MAX];
    static u8 children[ADYTUMFS_TREE_BRANCH_MAX][ADYTUMFS_CAS_HASH_SIZE];
    static u8 children_back[ADYTUMFS_TREE_BRANCH_MAX][ADYTUMFS_CAS_HASH_SIZE];

    const u32 count = ADYTUMFS_TREE_LEAF_MAX;
    for (u32 index = 0; index < count; index++) {
        keys[index] = key_at(index);
        value_at(index, &values[index]);
    }

    int valid = adytumfs_tree_leaf_pack(node, count, keys, values) == 0 &&
        adytumfs_tree_node_check(node, 0) == 0;

    u32 got = 0;
    valid = valid &&
        adytumfs_tree_leaf_unpack(node, &got, keys_back, values_back) == 0 &&
        got == count;
    for (u32 index = 0; valid && index < count; index++) {
        valid = keys_back[index].end == keys[index].end &&
            values_back[index].length == values[index].length &&
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
    // Entry 1 is handed entry 0's key byte for byte, because zeroing it would
    // only make it sort lower and would test the order check instead.
    u8 *first_key = node + ADYTUMFS_TREE_HEADER_SIZE;
    u8 *second_key = first_key + ADYTUMFS_TREE_LEAF_ENTRY_SIZE;
    u8 saved_key[ADYTUMFS_TREE_KEY_SIZE];
    for (u32 byte = 0; byte < ADYTUMFS_TREE_KEY_SIZE; byte++) {
        saved_key[byte] = second_key[byte];
        second_key[byte] = first_key[byte];
    }
    valid = valid && adytumfs_tree_node_check(node, 0) != 0;
    for (u32 byte = 0; byte < ADYTUMFS_TREE_KEY_SIZE; byte++)
        second_key[byte] = saved_key[byte];
    valid = valid && adytumfs_tree_node_check(node, 0) == 0;

    // Search answers the first separator at or above the query, which in a
    // branch is the only subtree that can hold it.
    struct adytumfs_tree_key probe = key_at(3);
    valid = valid && adytumfs_tree_node_search(node, &probe) == 3;
    probe = key_end(4u * ADYTUMFS_BLOCK_SIZE + 1u);
    valid = valid && adytumfs_tree_node_search(node, &probe) == 4;
    probe = key_at(0);
    valid = valid && adytumfs_tree_node_search(node, &probe) == 0;
    probe = key_at(9u * ADYTUMFS_TREE_LEAF_MAX);
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
        split.end == keys[left_count - 1u].end;

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
                keys[index].end;
        int hit_right = in_right >= 0 &&
            adytumfs_read_le64(right + ADYTUMFS_TREE_HEADER_SIZE +
                               (u32)in_right * ADYTUMFS_TREE_LEAF_ENTRY_SIZE) ==
                keys[index].end;
        valid = (hit_left ? 1 : 0) + (hit_right ? 1 : 0) == 1;
    }

    // A branch splits by the same rule and its child hashes survive.
    for (u32 index = 0; index < ADYTUMFS_TREE_BRANCH_MAX; index++) {
        keys[index] = key_at(index);
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
    // Every rule packing enforces needs a case that breaks exactly that rule,
    // because a check nothing exercises is decoration and will be the first
    // thing a later edit drops. Each case below differs from a valid run in
    // one field.
    static u8 probe_node[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_tree_key run[2];
    struct adytumfs_tree_value run_values[2];
    run[0] = key_at(1);
    run[1] = key_at(2);
    value_at(1, &run_values[0]);
    value_at(2, &run_values[1]);
    valid = valid &&
        adytumfs_tree_leaf_pack(probe_node, 2, run, run_values) == 0;

    struct adytumfs_tree_key bad_end = key_at(1);
    bad_end.end += 1;
    valid = valid &&
        adytumfs_tree_leaf_pack(probe_node, 1, &bad_end, run_values) != 0;

    struct adytumfs_tree_value bad_length = run_values[0];
    bad_length.length += 1;
    valid = valid &&
        adytumfs_tree_leaf_pack(probe_node, 1, run, &bad_length) != 0;

    struct adytumfs_tree_value no_length = run_values[0];
    no_length.length = 0;
    valid = valid &&
        adytumfs_tree_leaf_pack(probe_node, 1, run, &no_length) != 0;

    // Longer than the end itself, so the entry would start before the file.
    struct adytumfs_tree_value past_end = run_values[0];
    past_end.length = 3u * ADYTUMFS_BLOCK_SIZE;
    valid = valid &&
        adytumfs_tree_leaf_pack(probe_node, 1, run, &past_end) != 0;

    // Both entries are well formed on their own; together they claim the same
    // block twice, which is what the running start catches.
    struct adytumfs_tree_value overlap = run_values[1];
    overlap.length = 2u * ADYTUMFS_BLOCK_SIZE;
    valid = valid &&
        adytumfs_tree_leaf_pack(probe_node, 2, run, run_values) == 0;
    struct adytumfs_tree_value overlapped[2];
    overlapped[0] = run_values[0];
    overlapped[1] = overlap;
    valid = valid &&
        adytumfs_tree_leaf_pack(probe_node, 2, run, overlapped) != 0;

    // A length past 32 bits has to survive the round trip whole, or a file
    // larger than 4 GiB of one repeated block would come back truncated.
    struct adytumfs_tree_key wide_key;
    struct adytumfs_tree_value wide_value;
    wide_key.end = (u64)1 << 40;
    value_at(77, &wide_value);
    wide_value.length = (u64)1 << 40;
    struct adytumfs_tree_key wide_back;
    struct adytumfs_tree_value wide_back_value;
    u32 wide_got = 0;
    valid = valid &&
        adytumfs_tree_leaf_pack(probe_node, 1, &wide_key, &wide_value) == 0 &&
        adytumfs_tree_leaf_unpack(probe_node, &wide_got, &wide_back,
                                  &wide_back_value) == 0 &&
        wide_got == 1 && wide_back.end == wide_key.end &&
        wide_back_value.length == wide_value.length;

    // The one entry past capacity has to be a valid entry, or the refusal
    // would come from its length and say nothing about the capacity limit.
    keys[ADYTUMFS_TREE_LEAF_MAX] = key_at(ADYTUMFS_TREE_LEAF_MAX);
    value_at(ADYTUMFS_TREE_LEAF_MAX, &values[ADYTUMFS_TREE_LEAF_MAX]);
    valid = valid &&
        adytumfs_tree_leaf_pack(node, ADYTUMFS_TREE_LEAF_MAX + 1u, keys,
                                values) != 0 &&
        adytumfs_tree_leaf_pack(node, ADYTUMFS_TREE_LEAF_MAX, keys,
                                values) == 0 &&
        adytumfs_tree_leaf_pack(node, 0, keys, values) != 0;
    struct adytumfs_tree_key unsorted[2];
    unsorted[0] = key_at(5);
    unsorted[1] = key_at(4);
    valid = valid && adytumfs_tree_leaf_pack(node, 2, unsorted, values) != 0;

    return valid ? 0 : -1;
}

// Traversal against a real device, through the same location table the
// filesystem will use. Every insert is copy on write, so this also checks the
// property the design rests on: a root that was current a moment ago still
// names a complete tree.
int test_adytumfs_tree_traverse64(void) {
    static struct adytumfs_cas store;
    static u8 scratch[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    struct adytumfs_tree_key key;
    struct adytumfs_tree_value value;
    struct adytumfs_tree_value found;
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(4096, 0);
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, scratch) == 0 &&
        adytumfs_super_unpack(&super, scratch) == 0;
    valid = valid && tree_index_empty(dev, &super, &store) == 0;
    // The index is reserved out of the data region, so the free count has to
    // already exclude it. A count that still includes the reservation reports
    // space the allocator will never hand out.
    valid = valid && super.free_blocks + super.index_blocks <=
        super.data_checksum_region - super.data_start;

    u8 root[ADYTUMFS_CAS_HASH_SIZE];
    u8 next[ADYTUMFS_CAS_HASH_SIZE];
    u8 snapshot[ADYTUMFS_CAS_HASH_SIZE];

    // A fresh volume has no tree, and that is not a case the caller has to
    // special case before the first insert.
    crypto_zero(root, ADYTUMFS_CAS_HASH_SIZE);
    key = key_at(0);
    value_at(0, &value);
    valid = valid && adytumfs_tree_root_empty(root) == 1 &&
        adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                             next) == 0 &&
        adytumfs_tree_root_empty(next) == 0 &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) == 0 &&
        found.length == value.length &&         crypto_equal(found.hash, value.hash, ADYTUMFS_CAS_HASH_SIZE);

    // A key that is not there stays not there, on both sides of the one that is.
    key = key_at(1);
    valid = valid &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) != 0;
    key = key_end(0);
    valid = valid &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) != 0;

    // Filling past leaf capacity has to grow the tree, and every earlier key
    // has to survive the split that does it.
    for (u32 index = 1; index <= ADYTUMFS_TREE_LEAF_MAX; index++) {
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            root[byte] = next[byte];
        key = key_at(index);
        value_at(index, &value);
        valid = valid &&
            adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                                 next) == 0;
    }
    for (u32 index = 0; index <= ADYTUMFS_TREE_LEAF_MAX; index++) {
        key = key_at(index);
        value_at(index, &value);
        valid = valid &&
            adytumfs_tree_lookup(dev, &super, &store, next, &key,
                                 &found) == 0 &&
            found.length == value.length &&             crypto_equal(found.hash, value.hash, ADYTUMFS_CAS_HASH_SIZE);
    }

    // The split produced a branch root with two children, not a second leaf
    // hanging off nothing.
    u64 root_block = 0;
    valid = valid &&
        adytumfs_cas_lookup(dev, &super, &store, next, &root_block) == 0 &&
        adytumfs_data_read(dev, &super, root_block, scratch) == 0 &&
        adytumfs_read_le32(scratch + 4) == 1u &&
        adytumfs_read_le32(scratch + 8) == 2u;

    // Snapshot: the root from before the next insert still resolves, which is
    // what removes the need for a journal.
    for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++) {
        snapshot[byte] = next[byte];
        root[byte] = next[byte];
    }
    key = key_at(0);
    value_at(0, &value);
    valid = valid &&
        adytumfs_tree_insert(dev, &super, &store, snapshot, &key, &value,
                             next) == 0;
    key = key_at(9u * ADYTUMFS_TREE_LEAF_MAX);
    valid = valid &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) != 0;
    value_at(99, &value);
    valid = valid &&
        adytumfs_tree_insert(dev, &super, &store, next, &key, &value,
                             next) == 0 &&
        adytumfs_tree_lookup(dev, &super, &store, snapshot, &key,
                             &found) != 0 &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) == 0 &&
        found.length == value.length &&
        crypto_equal(found.hash, value.hash, ADYTUMFS_CAS_HASH_SIZE);

    // A second object spreads the tree over more than two leaves, so branch
    // entries past the first are exercised on the way down.
    for (u32 index = 0; index < ADYTUMFS_TREE_LEAF_MAX; index++) {
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            root[byte] = next[byte];
        key = key_at(ADYTUMFS_TREE_LEAF_MAX + index);
        value_at(index + 1000u, &value);
        valid = valid &&
            adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                                 next) == 0;
    }
    for (u32 index = 0; index < ADYTUMFS_TREE_LEAF_MAX; index++) {
        key = key_at(ADYTUMFS_TREE_LEAF_MAX + index);
        value_at(index + 1000u, &value);
        valid = valid &&
            adytumfs_tree_lookup(dev, &super, &store, next, &key,
                                 &found) == 0 &&
            found.length == value.length &&             crypto_equal(found.hash, value.hash, ADYTUMFS_CAS_HASH_SIZE);
    }

    // Replacing a key changes the value and leaves the key set alone.
    key = key_at(3u * ADYTUMFS_TREE_LEAF_MAX);
    value_at(1234, &value);
    valid = valid &&
        adytumfs_tree_insert(dev, &super, &store, next, &key, &value,
                             next) == 0 &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) == 0 &&
        found.length == value.length &&
        crypto_equal(found.hash, value.hash, ADYTUMFS_CAS_HASH_SIZE);
    key = key_at(3u * ADYTUMFS_TREE_LEAF_MAX + 1u);
    valid = valid &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) != 0;

    // One flipped byte in the root has to be refused. The parent promised this
    // hash, so a node that reads back different is not the node that was
    // written, and walking it would hand back another file's data.
    key = key_at(0);
    valid = valid &&
        adytumfs_cas_lookup(dev, &super, &store, next, &root_block) == 0 &&
        adytumfs_data_read(dev, &super, root_block, scratch) == 0;
    scratch[ADYTUMFS_TREE_HEADER_SIZE] ^= 0x01u;
    valid = valid &&
        adytumfs_data_write(dev, &super, root_block, scratch) == 0 &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) != 0 &&
        adytumfs_tree_insert(dev, &super, &store, next, &key, &value,
                             next) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

static void root_copy(u8 *to, const u8 *from) {
    for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
        to[byte] = from[byte];
}

int test_adytumfs_tree_gc64(void) {
    static struct adytumfs_cas store;
    static u8 scratch[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    struct adytumfs_tree_key key;
    struct adytumfs_tree_value value;
    struct adytumfs_tree_value found;
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(4096, 0);
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, scratch) == 0 &&
        adytumfs_super_unpack(&super, scratch) == 0;
    valid = valid && tree_index_empty(dev, &super, &store) == 0;

    u8 root[ADYTUMFS_CAS_HASH_SIZE];
    u8 next[ADYTUMFS_CAS_HASH_SIZE];
    u64 block = 0;
    u32 left = 1u;

    // An empty root has nothing to drop, and that is not an error the caller
    // has to check for before the first commit.
    crypto_zero(root, ADYTUMFS_CAS_HASH_SIZE);
    valid = valid &&
        adytumfs_tree_discard(dev, &super, &store, root, 64u, &left) == 0 &&
        left == 0;

    for (u32 index = 0; index < ADYTUMFS_TREE_LEAF_MAX; index++) {
        key = key_at(index);
        value_at(index, &value);
        valid = valid &&
            adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                                 next) == 0 &&
            adytumfs_tree_discard(dev, &super, &store, root, 64u,
                                  &left) == 0 &&
            left == 0;
        root_copy(root, next);
    }
    // One full leaf and nothing else. Every intermediate version of the way
    // here has been collected, which is what makes the count below a
    // statement about the tree rather than about its history.
    u64 steady = tree_count(dev, &super, &store);
    valid = valid && steady == 1u;

    // The point of the slice. Rewriting one key over and over has to leave the
    // table where it was. Without the discard every round leaked a node
    // version, and the table capped the whole tree at a few hundred writes.
    for (u32 round = 0; round < 60u; round++) {
        key = key_at(0);
        value_at(1000u + round, &value);
        valid = valid &&
            adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                                 next) == 0 &&
            tree_count(dev, &super, &store) == steady + 1u &&
            adytumfs_tree_discard(dev, &super, &store, root, 64u,
                                  &left) == 0 &&
            left == 0 && tree_count(dev, &super, &store) == steady;
        root_copy(root, next);
    }

    // Nothing that is still reachable went with the garbage.
    for (u32 index = 0; index < ADYTUMFS_TREE_LEAF_MAX; index++) {
        key = key_at(index);
        value_at(index ? index : 1059u, &value);
        valid = valid &&
            adytumfs_tree_lookup(dev, &super, &store, root, &key,
                                 &found) == 0 &&
            found.length == value.length &&             crypto_equal(found.hash, value.hash, ADYTUMFS_CAS_HASH_SIZE);
    }

    // A second object grows the tree a level, so the discard walks a branch
    // and has to leave the children the new root still points at alone.
    for (u32 index = 0; index < ADYTUMFS_TREE_LEAF_MAX; index++) {
        key = key_at(ADYTUMFS_TREE_LEAF_MAX + index);
        value_at(index + 2000u, &value);
        valid = valid &&
            adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                                 next) == 0 &&
            adytumfs_tree_discard(dev, &super, &store, root, 64u,
                                  &left) == 0 &&
            left == 0;
        root_copy(root, next);
    }
    // Splitting in half does not rebalance, so 102 keys land in four leaves
    // of 25, 25, 25 and 27 with the branch over them, and nothing else: every
    // intermediate version of the way down has been collected.
    u64 grown = tree_count(dev, &super, &store);
    valid = valid && grown == 5u;

    for (u32 round = 0; round < 20u; round++) {
        key = key_at(ADYTUMFS_TREE_LEAF_MAX);
        value_at(3000u + round, &value);
        valid = valid &&
            adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                                 next) == 0 &&
            adytumfs_tree_discard(dev, &super, &store, root, 64u,
                                  &left) == 0 &&
            left == 0 && tree_count(dev, &super, &store) == grown;
        root_copy(root, next);
    }

    // A budget that runs out stops the walk instead of finishing it, and a
    // second walk refuses rather than dropping the first one half done.
    key = key_at(ADYTUMFS_TREE_LEAF_MAX);
    value_at(4000u, &value);
    valid = valid &&
        adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                             next) == 0 &&
        adytumfs_tree_discard(dev, &super, &store, root, 1u, &left) == 0 &&
        left > 0 &&
        adytumfs_tree_discard(dev, &super, &store, next, 64u, &left) != 0;
    // The step is taken outside the short circuit: a walk that stops making
    // progress has to end the loop rather than spin on a stale count once
    // valid has already gone false.
    while (left) {
        u32 before = left;
        int stepped =
            adytumfs_tree_discard_resume(dev, &super, &store, 4u, &left) == 0 &&
            left < before;
        valid = valid && stepped;
        if (!stepped) break;
    }
    valid = valid && tree_count(dev, &super, &store) == grown;
    root_copy(root, next);

    // A held root is the snapshot case: while anything else references it,
    // dropping the tree's own reference frees nothing at all.
    u8 kept[ADYTUMFS_CAS_HASH_SIZE];
    root_copy(kept, root);
    valid = valid &&
        adytumfs_cas_acquire(dev, &super, &store, kept, &block) == 0;
    key = key_at(ADYTUMFS_TREE_LEAF_MAX + 1u);
    value_at(5000u, &value);
    valid = valid &&
        adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                             next) == 0;
    u64 with_both = tree_count(dev, &super, &store);
    valid = valid && with_both > grown &&
        adytumfs_tree_discard(dev, &super, &store, root, 64u, &left) == 0 &&
        left == 0 && tree_count(dev, &super, &store) == with_both;
    root_copy(root, next);
    // Letting go of the held root is what finally reclaims it, and only the
    // part of it the committed tree does not share.
    valid = valid &&
        adytumfs_tree_discard(dev, &super, &store, kept, 64u, &left) == 0 &&
        left == 0 && tree_count(dev, &super, &store) < with_both;

    // A node that no longer hashes to what its parent promised is refused on
    // the way out too, not only on the way in.
    key = key_at(ADYTUMFS_TREE_LEAF_MAX);
    value_at(6000u, &value);
    root_copy(kept, root);
    valid = valid &&
        adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                             next) == 0 &&
        adytumfs_cas_lookup(dev, &super, &store, kept, &block) == 0 &&
        adytumfs_data_read(dev, &super, block, scratch) == 0;
    scratch[ADYTUMFS_TREE_HEADER_SIZE] ^= 0x01u;
    valid = valid &&
        adytumfs_data_write(dev, &super, block, scratch) == 0 &&
        adytumfs_tree_discard(dev, &super, &store, kept, 64u, &left) != 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

// Read the level and entry count of whatever node a root names, so a test can
// see the shape of the tree and not only its contents.
static int root_shape(struct kernel_object *device,
                      const struct adytumfs_superblock *super,
                      struct adytumfs_cas *store,
                      const u8 root[ADYTUMFS_CAS_HASH_SIZE], u8 *scratch,
                      u32 *level, u32 *count) {
    u64 number = 0;
    if (adytumfs_cas_lookup(device, super, store, root, &number)) return -1;
    if (adytumfs_data_read(device, super, number, scratch)) return -1;
    *level = adytumfs_read_le32(scratch + 4);
    *count = adytumfs_read_le32(scratch + 8);
    return 0;
}

// Check the invariant the format states: every separator in a branch is
// exactly the greatest key of the child below it. Routing survives a stale
// separator, so only reading the nodes back can tell whether it was kept.
static int separators_exact(struct kernel_object *device,
                            const struct adytumfs_superblock *super,
                            struct adytumfs_cas *store,
                            const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                            u8 *scratch, u8 *child) {
    u64 number = 0;
    if (adytumfs_cas_lookup(device, super, store, root, &number)) return -1;
    if (adytumfs_data_read(device, super, number, scratch)) return -1;
    if (adytumfs_read_le32(scratch + 4) != 1u) return 1;
    u32 count = adytumfs_read_le32(scratch + 8);
    for (u32 index = 0; index < count; index++) {
        const u8 *entry = scratch + ADYTUMFS_TREE_HEADER_SIZE +
            index * ADYTUMFS_TREE_BRANCH_ENTRY_SIZE;
        u64 at = 0;
        if (adytumfs_cas_lookup(device, super, store,
                                entry + ADYTUMFS_TREE_KEY_SIZE, &at))
            return -1;
        if (adytumfs_data_read(device, super, at, child)) return -1;
        u32 entries = adytumfs_read_le32(child + 8);
        if (!entries) return 0;
        u32 stride = adytumfs_read_le32(child + 4)
            ? ADYTUMFS_TREE_BRANCH_ENTRY_SIZE
            : ADYTUMFS_TREE_LEAF_ENTRY_SIZE;
        const u8 *last = child + ADYTUMFS_TREE_HEADER_SIZE +
            (entries - 1u) * stride;
        if (adytumfs_read_le64(last) != adytumfs_read_le64(entry)) return 0;
    }
    return 1;
}

int test_adytumfs_tree_remove64(void) {
    static struct adytumfs_cas store;
    static u8 scratch[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    struct adytumfs_tree_key key;
    struct adytumfs_tree_value value;
    struct adytumfs_tree_value found;
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(4096, 0);
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, scratch) == 0 &&
        adytumfs_super_unpack(&super, scratch) == 0;
    valid = valid && tree_index_empty(dev, &super, &store) == 0;

    u8 root[ADYTUMFS_CAS_HASH_SIZE];
    u8 next[ADYTUMFS_CAS_HASH_SIZE];
    crypto_zero(root, ADYTUMFS_CAS_HASH_SIZE);

    // Nothing to remove is a refusal, not a success: a caller removing an
    // extent it believes is there has to hear that the tree disagrees.
    key = key_at(0);
    valid = valid &&
        adytumfs_tree_remove(dev, &super, &store, root, &key, next) != 0;

    // One key in, one key out, and the tree is empty again rather than holding
    // a node nothing can reach.
    value_at(0, &value);
    valid = valid &&
        adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                             next) == 0;
    for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
        root[byte] = next[byte];
    valid = valid &&
        adytumfs_tree_remove(dev, &super, &store, root, &key, next) == 0 &&
        adytumfs_tree_root_empty(next) == 1 &&
        adytumfs_tree_lookup(dev, &super, &store, next, &key, &found) != 0;

    // The empty root still takes an insert, so removing everything is not a
    // one way trip.
    valid = valid &&
        adytumfs_tree_remove(dev, &super, &store, next, &key, root) != 0 &&
        adytumfs_tree_insert(dev, &super, &store, next, &key, &value,
                             root) == 0;

    // Past leaf capacity, so the tree has a branch root and the removals below
    // have separators to get wrong.
    const u32 keys_total = ADYTUMFS_TREE_LEAF_MAX + 1u;
    for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
        next[byte] = root[byte];
    for (u32 index = 1; index < keys_total; index++) {
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            root[byte] = next[byte];
        key = key_at(index);
        value_at(index, &value);
        valid = valid &&
            adytumfs_tree_insert(dev, &super, &store, root, &key, &value,
                                 next) == 0;
    }
    u32 level = 0;
    u32 entries = 0;
    valid = valid &&
        root_shape(dev, &super, &store, next, scratch, &level, &entries) == 0 &&
        level == 1u && entries == 2u;

    // Removing the greatest key is the case that moves a separator: the parent
    // stores the largest key of each subtree, so the entry above the one that
    // went has to be rewritten or later lookups route into the wrong child.
    u32 live = keys_total;
    for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
        root[byte] = next[byte];
    key = key_at(keys_total - 1u);
    valid = valid &&
        adytumfs_tree_remove(dev, &super, &store, root, &key, next) == 0;
    live--;
    // That key was the greatest in its subtree, so its parent's separator is
    // the one entry a removal can leave behind stale.
    static u8 child_node[ADYTUMFS_BLOCK_SIZE];
    valid = valid &&
        separators_exact(dev, &super, &store, next, scratch, child_node) == 1;
    for (u32 index = 0; index < keys_total; index++) {
        int gone = index == keys_total - 1u;
        key = key_at(index);
        value_at(index, &value);
        int hit = adytumfs_tree_lookup(dev, &super, &store, next, &key,
                                       &found);
        valid = valid && (gone ? hit != 0 : hit == 0) &&
            (gone || (found.length == value.length &&
                                            crypto_equal(found.hash, value.hash,
                                   ADYTUMFS_CAS_HASH_SIZE)));
    }

    // A key that was never there is still refused now that the tree has depth,
    // and the refusal leaves the root alone.
    u8 before[ADYTUMFS_CAS_HASH_SIZE];
    for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
        before[byte] = next[byte];
    key = key_end(7u * ADYTUMFS_BLOCK_SIZE + 1u);
    valid = valid &&
        adytumfs_tree_remove(dev, &super, &store, next, &key, root) != 0 &&
        crypto_equal(root, before, ADYTUMFS_CAS_HASH_SIZE) == 0;

    // Empty the whole of one subtree. The branch loses an entry, and a root
    // left with a single child drops the level instead of keeping a branch
    // that names one thing.
    for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
        root[byte] = next[byte];
    for (u32 index = 0; index + 1u < live; index++) {
        key = key_at(index);
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            next[byte] = root[byte];
        valid = valid &&
            adytumfs_tree_remove(dev, &super, &store, root, &key, next) == 0;
        for (u32 byte = 0; byte < ADYTUMFS_CAS_HASH_SIZE; byte++)
            root[byte] = next[byte];
        valid = valid &&
            separators_exact(dev, &super, &store, next, scratch,
                             child_node) == 1;
    }
    live = 1;
    key = key_at(keys_total - 2u);
    valid = valid &&
        adytumfs_tree_lookup(dev, &super, &store, root, &key, &found) == 0 &&
        root_shape(dev, &super, &store, root, scratch, &level, &entries) == 0 &&
        level == 0u;

    // The last key goes and the tree is empty, which is what a truncate to
    // zero leaves behind.
    valid = valid &&
        adytumfs_tree_remove(dev, &super, &store, root, &key, next) == 0 &&
        adytumfs_tree_root_empty(next) == 1;

    // Dropping the superseded roots has to give every block back: nothing in a
    // removed tree is reachable any more.
    u64 held = tree_count(dev, &super, &store);
    u32 remaining = 0;
    valid = valid && held != (u64)-1 &&
        adytumfs_tree_discard(dev, &super, &store, before, 512u,
                              &remaining) == 0 &&
        remaining == 0;
    while (!remaining && held) {
        u64 now = tree_count(dev, &super, &store);
        if (now == held || now == (u64)-1) break;
        held = now;
    }

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
