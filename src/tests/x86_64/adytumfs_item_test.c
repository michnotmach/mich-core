#include "types.h"
#include "object.h"
#include "block.h"
#include "blake2b.h"
#include "crypto.h"
#include "adytumfs_item.h"
#include "adytumfs_cas.h"

static struct adytumfs_item_key item_key(u64 objectid, u32 type, u64 offset) {
    struct adytumfs_item_key key;
    key.objectid = objectid;
    key.type = type;
    key.offset = offset;
    key.spare = 0;
    return key;
}

// Deterministic filler, so a round trip that drops, shifts or reorders a byte
// shows up as a mismatch rather than as two matching zero buffers. The size
// varies by index on purpose: equal sizes would let a packing bug that moves
// every item by one slot still land on a plausible offset.
static void payload_at(u32 index, u8 *buffer, u32 size) {
    for (u32 byte = 0; byte < size; byte++)
        buffer[byte] = (u8)(index * 31u + byte * 7u + 1u);
}

static u32 payload_size(u32 index) {
    return 16u + (index % 5u) * 12u;
}

static int leaf_pack_run(u8 *block, u32 count) {
    static struct adytumfs_item_key keys[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static u8 items[ADYTUMFS_ITEM_LEAF_SLOT_MAX][80];
    static const u8 *pointers[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    static u32 sizes[ADYTUMFS_ITEM_LEAF_SLOT_MAX];
    if (count > ADYTUMFS_ITEM_LEAF_SLOT_MAX) return -1;
    for (u32 index = 0; index < count; index++) {
        keys[index] = item_key(index + 1u, ADYTUMFS_ITEM_INODE, 0);
        sizes[index] = payload_size(index);
        payload_at(index, items[index], sizes[index]);
        pointers[index] = items[index];
    }
    return adytumfs_item_leaf_pack(block, count, keys, pointers, sizes);
}

// Place a packed node in the location table the way a real insert does: hash
// the packed block, ask the table for a block, write it. Placement takes no
// reference, so the caller that wants to keep the node acquires one.
static int node_place(struct kernel_object *dev,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store, const u8 *block,
                      u8 hash[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (adytumfs_item_node_hash(block, hash)) return -1;
    u64 number = 0;
    if (adytumfs_cas_place(dev, super, store, hash, &number)) return -1;
    if (adytumfs_block_write(dev, number, block)) return -1;
    u64 placed = 0;
    return adytumfs_cas_acquire(dev, super, store, hash, &placed);
}

// The node format is the whole deliverable of this slice, so the checks that
// it refuses a node this filesystem did not write matter as much as the round
// trip. Each corruption below is one byte or one word, and each must be
// caught: a validator that passes a tampered node turns the tree from self
// checking into decoration.
static int format_rejects(void) {
    static u8 good[ADYTUMFS_BLOCK_SIZE];
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    if (leaf_pack_run(good, 8)) return -1;
    if (adytumfs_item_node_check(good, 0)) return -1;

    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    block[0] ^= 0x1u;
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    block[4] ^= 0x1u;
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    // Level is checked against the caller's expectation, so a leaf offered as
    // a branch is refused even though every other word is intact.
    if (adytumfs_item_node_check(good, 1) == 0) return -1;

    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    adytumfs_write_le32(block + 12, 0);
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    adytumfs_write_le32(block + 12, ADYTUMFS_ITEM_LEAF_SLOT_MAX + 1u);
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    adytumfs_write_le32(block + 20, 1u);
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    // The spare word inside a key, which is a different field from the header
    // spare and has to be checked on its own.
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    adytumfs_write_le32(block + ADYTUMFS_ITEM_HEADER_SIZE + 20, 1u);
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    // Items are packed downward with no gap, so moving one item's offset down
    // by a byte leaves a hole the validator has to notice.
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    adytumfs_write_le32(
        block + ADYTUMFS_ITEM_HEADER_SIZE + ADYTUMFS_ITEM_KEY_SIZE,
        adytumfs_read_le32(block + ADYTUMFS_ITEM_HEADER_SIZE +
                           ADYTUMFS_ITEM_KEY_SIZE) -
            1u);
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    // A data_start that the items do not reach is a node claiming space its
    // own contents contradict.
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    adytumfs_write_le32(block + 16, adytumfs_read_le32(block + 16) - 8u);
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    // Unsorted keys break the search, so a node whose slots are out of order
    // is refused rather than searched incorrectly.
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        block[byte] = good[byte];
    adytumfs_write_le64(block + ADYTUMFS_ITEM_HEADER_SIZE, 9u);
    if (adytumfs_item_node_check(block, 0) == 0) return -1;

    // Packing refuses the same things the validator does, because a node that
    // could not be read back is a node that should never have been written.
    static struct adytumfs_item_key bad_keys[3];
    static u8 items[3][32];
    static const u8 *pointers[3];
    static u32 sizes[3];
    for (u32 index = 0; index < 3; index++) {
        sizes[index] = 32u;
        payload_at(index, items[index], sizes[index]);
        pointers[index] = items[index];
    }
    // Out of order on objectid, on type and on offset in turn.
    bad_keys[0] = item_key(5u, ADYTUMFS_ITEM_INODE, 0);
    bad_keys[1] = item_key(3u, ADYTUMFS_ITEM_INODE, 0);
    bad_keys[2] = item_key(9u, ADYTUMFS_ITEM_INODE, 0);
    if (adytumfs_item_leaf_pack(block, 3, bad_keys, pointers, sizes) == 0)
        return -1;
    bad_keys[0] = item_key(3u, ADYTUMFS_ITEM_INODE, 0);
    bad_keys[1] = item_key(3u, ADYTUMFS_ITEM_INODE, 0);
    bad_keys[2] = item_key(9u, ADYTUMFS_ITEM_INODE, 0);
    if (adytumfs_item_leaf_pack(block, 3, bad_keys, pointers, sizes) == 0)
        return -1;
    bad_keys[0] = item_key(3u, 4u, 0);
    bad_keys[1] = item_key(3u, 2u, 0);
    bad_keys[2] = item_key(9u, ADYTUMFS_ITEM_INODE, 0);
    if (adytumfs_item_leaf_pack(block, 3, bad_keys, pointers, sizes) == 0)
        return -1;
    bad_keys[0] = item_key(3u, ADYTUMFS_ITEM_INODE, 8u);
    bad_keys[1] = item_key(3u, ADYTUMFS_ITEM_INODE, 4u);
    bad_keys[2] = item_key(9u, ADYTUMFS_ITEM_INODE, 0);
    if (adytumfs_item_leaf_pack(block, 3, bad_keys, pointers, sizes) == 0)
        return -1;

    // A zero length item is unrepresentable on purpose: an item that covers no
    // bytes cannot be found by a search and would sit in the node forever.
    bad_keys[0] = item_key(3u, ADYTUMFS_ITEM_INODE, 0);
    bad_keys[1] = item_key(5u, ADYTUMFS_ITEM_INODE, 0);
    bad_keys[2] = item_key(9u, ADYTUMFS_ITEM_INODE, 0);
    sizes[1] = 0;
    if (adytumfs_item_leaf_pack(block, 3, bad_keys, pointers, sizes) == 0)
        return -1;
    sizes[1] = 32u;

    // Count zero, and a count past what one block holds.
    if (adytumfs_item_leaf_pack(block, 0, bad_keys, pointers, sizes) == 0)
        return -1;
    if (adytumfs_item_leaf_pack(block, ADYTUMFS_ITEM_LEAF_SLOT_MAX + 1u,
                                bad_keys, pointers, sizes) == 0)
        return -1;

    // Items whose bytes do not all fit beside their slots.
    static u32 big[3];
    for (u32 index = 0; index < 3; index++)
        big[index] = ADYTUMFS_BLOCK_SIZE / 2u;
    static u8 large[8];
    static const u8 *large_pointers[3];
    for (u32 index = 0; index < 3; index++) large_pointers[index] = large;
    if (adytumfs_item_leaf_pack(block, 3, bad_keys, large_pointers, big) == 0)
        return -1;
    return 0;
}

static int branch_checks(void) {
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    static struct adytumfs_item_key keys[3];
    static u8 children[3][ADYTUMFS_ITEM_CHILD_SIZE];
    for (u32 index = 0; index < 3; index++) {
        keys[index] = item_key(index + 1u, ADYTUMFS_ITEM_INODE, 0);
        for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
            children[index][byte] = (u8)(index * 13u + byte);
    }
    if (adytumfs_item_branch_pack(block, 3, keys, children)) return -1;
    if (adytumfs_item_node_check(block, 1)) return -1;
    if (adytumfs_item_node_check(block, 0) == 0) return -1;
    for (u32 index = 0; index < 3; index++) {
        struct adytumfs_item_key found;
        u8 child[ADYTUMFS_ITEM_CHILD_SIZE];
        if (adytumfs_item_branch_get(block, index, &found, child)) return -1;
        if (found.objectid != keys[index].objectid) return -1;
        for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++)
            if (child[byte] != children[index][byte]) return -1;
    }
    // A branch has no data area, so a data_start below the end of the block
    // means it was not packed here.
    adytumfs_write_le32(block + 16, ADYTUMFS_BLOCK_SIZE - 4u);
    if (adytumfs_item_node_check(block, 1) == 0) return -1;
    return 0;
}

static int search_checks(void) {
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    if (leaf_pack_run(block, 8)) return -1;
    // Every packed key is found at its own index.
    for (u32 index = 0; index < 8; index++) {
        struct adytumfs_item_key query =
            item_key(index + 1u, ADYTUMFS_ITEM_INODE, 0);
        int found = adytumfs_item_node_search(block, &query);
        if (found != (int)index) return -1;
    }
    // A key between two slots lands on the higher one, which is the lower
    // bound the descent needs.
    struct adytumfs_item_key between = item_key(4u, ADYTUMFS_ITEM_INODE, 1u);
    if (adytumfs_item_node_search(block, &between) != 4) return -1;
    // Type orders after objectid, so a later type on the same object is above
    // the inode item rather than inside it.
    struct adytumfs_item_key later_type = item_key(4u, 2u, 0);
    if (adytumfs_item_node_search(block, &later_type) != 4) return -1;
    // A key above every slot has nowhere to go.
    struct adytumfs_item_key past = item_key(100u, ADYTUMFS_ITEM_INODE, 0);
    if (adytumfs_item_node_search(block, &past) != -1) return -1;
    return 0;
}

// Where the walk leaves its keys, so the callback can prove the order it was
// called in. Static because the visitor gets no storage of its own beyond the
// context pointer, and the harness has no allocator to hand it one.
static struct adytumfs_item_key walked[24];
static u32 walked_count;
static int walk_stop;

// Both leaves are packed from the same payload series, so the bytes expected
// for an item come from where it sits in its own leaf rather than from the
// position the walk happens to be at.
static u32 payload_index_for(u64 objectid) {
    return objectid <= 6u ? (u32)(objectid - 1u) : (u32)(objectid - 10u);
}

static int walk_record(const struct adytumfs_item_key *key, const u8 *data,
                       u32 size, void *context) {
    u32 *expected = context;
    if (walked_count >= 24) return -1;
    walked[walked_count] = *key;
    u32 which = payload_index_for(key->objectid);
    // The bytes come back too, so checking one proves the data area survived
    // the round trip through the location table and not just the slots.
    if (size != payload_size(which)) return -1;
    for (u32 byte = 0; byte < size; byte++) {
        u8 want = (u8)(which * 31u + byte * 7u + 1u);
        if (data[byte] != want) return -1;
    }
    walked_count++;
    (*expected)++;
    if (walk_stop && walked_count == 3u) return 7;
    return 0;
}

int test_adytumfs_item64(void) {
    static struct adytumfs_cas store;
    static u8 scratch[ADYTUMFS_BLOCK_SIZE];
    static u8 leaf_a[ADYTUMFS_BLOCK_SIZE];
    static u8 leaf_b[ADYTUMFS_BLOCK_SIZE];
    static u8 branch[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    u32 objects = object_active_count();
    u32 devices = block_active_count();

    int valid = format_rejects() == 0 && branch_checks() == 0 &&
        search_checks() == 0;

    struct kernel_object *dev = block_create(4096, 0);
    valid = valid && dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, scratch) == 0 &&
        adytumfs_super_unpack(&super, scratch) == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    // Two leaves under one branch, with the second leaf's first key above the
    // first leaf's last, so a lookup either side of the boundary has to cross
    // the branch and a walk has to come back for the second subtree.
    u8 hash_a[ADYTUMFS_ITEM_CHILD_SIZE];
    u8 hash_b[ADYTUMFS_ITEM_CHILD_SIZE];
    u8 root[ADYTUMFS_ITEM_CHILD_SIZE];
    valid = valid && leaf_pack_run(leaf_a, 6) == 0;
    if (valid) {
        static struct adytumfs_item_key keys[6];
        static u8 items[6][80];
        static const u8 *pointers[6];
        static u32 sizes[6];
        for (u32 index = 0; index < 6; index++) {
            keys[index] = item_key(index + 10u, ADYTUMFS_ITEM_INODE, 0);
            sizes[index] = payload_size(index);
            payload_at(index, items[index], sizes[index]);
            pointers[index] = items[index];
        }
        valid = adytumfs_item_leaf_pack(leaf_b, 6, keys, pointers,
                                        sizes) == 0;
    }
    valid = valid && node_place(dev, &super, &store, leaf_a, hash_a) == 0 &&
        node_place(dev, &super, &store, leaf_b, hash_b) == 0;
    if (valid) {
        struct adytumfs_item_key separators[2];
        u8 children[2][ADYTUMFS_ITEM_CHILD_SIZE];
        // A separator carries the greatest key of the child below it, so the
        // first is leaf A's last item and the second leaf B's.
        separators[0] = item_key(6u, ADYTUMFS_ITEM_INODE, 0);
        separators[1] = item_key(15u, ADYTUMFS_ITEM_INODE, 0);
        for (u32 byte = 0; byte < ADYTUMFS_ITEM_CHILD_SIZE; byte++) {
            children[0][byte] = hash_a[byte];
            children[1][byte] = hash_b[byte];
        }
        valid = adytumfs_item_branch_pack(branch, 2, separators,
                                          children) == 0 &&
            adytumfs_item_node_check(branch, 1) == 0 &&
            node_place(dev, &super, &store, branch, root) == 0;
    }

    // Lookup below the boundary, above it, and on a key that is in neither
    // leaf. The last one must fail rather than return a neighbour.
    static u8 buffer[80];
    u32 size = 0;
    struct adytumfs_item_key query = item_key(3u, ADYTUMFS_ITEM_INODE, 0);
    valid = valid &&
        adytumfs_item_lookup(dev, &super, &store, root, &query, buffer,
                             sizeof(buffer), &size) == 0 &&
        size == payload_size(2u);
    query = item_key(12u, ADYTUMFS_ITEM_INODE, 0);
    valid = valid &&
        adytumfs_item_lookup(dev, &super, &store, root, &query, buffer,
                             sizeof(buffer), &size) == 0 &&
        size == payload_size(2u);
    query = item_key(500u, ADYTUMFS_ITEM_INODE, 0);
    valid = valid &&
        adytumfs_item_lookup(dev, &super, &store, root, &query, buffer,
                             sizeof(buffer), &size) != 0;

    // An empty root is an empty tree, not an error, so a fresh volume needs no
    // special case anywhere above this call.
    u8 empty[ADYTUMFS_ITEM_CHILD_SIZE];
    crypto_zero(empty, ADYTUMFS_ITEM_CHILD_SIZE);
    valid = valid && adytumfs_item_root_empty(empty) == 1 &&
        adytumfs_item_lookup(dev, &super, &store, empty, &query, buffer,
                             sizeof(buffer), &size) != 0;

    // The walk must visit all twelve items in ascending key order across the
    // branch, which is the property an audit comparing against a sorted
    // rebuild depends on.
    walked_count = 0;
    walk_stop = 0;
    u32 expected = 0;
    valid = valid &&
        adytumfs_item_walk(dev, &super, &store, root, walk_record,
                           &expected) == 0 &&
        expected == 12u && walked_count == 12u;
    if (valid) {
        for (u32 index = 1; index < walked_count; index++) {
            struct adytumfs_item_key previous = walked[index - 1];
            if (previous.objectid >= walked[index].objectid) {
                valid = 0;
                break;
            }
        }
    }

    // A visitor that stops early is how a rebuild quits once it has what it
    // needs, and its value has to reach the caller unchanged.
    walked_count = 0;
    walk_stop = 1;
    expected = 0;
    valid = valid &&
        adytumfs_item_walk(dev, &super, &store, root, walk_record,
                           &expected) == 7 &&
        expected == 3u;

    // Releasing what the test placed leaves the volume as it found it, which
    // is also the check that placement really did take a reference each time.
    valid = valid && adytumfs_cas_release(dev, &super, &store, root) == 0 &&
        adytumfs_cas_release(dev, &super, &store, hash_a) == 0 &&
        adytumfs_cas_release(dev, &super, &store, hash_b) == 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
