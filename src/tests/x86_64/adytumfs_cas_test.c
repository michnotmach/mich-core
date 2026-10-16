#include "types.h"
#include "object.h"
#include "block.h"
#include "blake2b.h"
#include "crypto.h"
#include "adytumfs_cas.h"

// More mappings than the cache has slots. The point of the slice is that this
// number is no longer a limit on anything: the cache is allowed to be smaller
// than the volume, and was the ceiling on it before.
#define CAS_TEST_MANY 300u

// A distinct key per index, derived with the same hash the filesystem uses, so
// the cache is exercised on real digests rather than on hand written byte
// patterns that could accidentally collide.
//
// A key is the digest of the block image it names, because a read now checks
// the bytes against the hash that found them. Hashing anything shorter would
// produce a key no block can satisfy and the check would fail instead of
// testing.
static void cas_image(u32 index, u8 *block) {
    u32 state = index * 2654435761u + 1u;
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++) {
        state = state * 1103515245u + 12345u;
        block[byte] = (u8)(state >> 16);
    }
}

static void cas_key(u32 index, u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    static u8 image[ADYTUMFS_BLOCK_SIZE];
    cas_image(index, image);
    blake2b(hash, ADYTUMFS_CAS_HASH_SIZE, image, ADYTUMFS_BLOCK_SIZE);
}

static u64 cas_live(struct kernel_object *device,
                    const struct adytumfs_superblock *super,
                    struct adytumfs_cas *store) {
    u64 count = 0;
    if (adytumfs_cas_count(device, super, store, &count)) return (u64)-1;
    return count;
}

int test_adytumfs_cas64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(4096, 0);

    static struct adytumfs_cas store;
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    static u8 readback[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0;

    // The index is the one mkfs reserved, not one the test carved out, and a
    // fresh volume has to start with it empty.
    struct adytumfs_index layout;
    u64 fresh = 1;
    adytumfs_index_init(&layout, super.index_start, super.index_blocks);
    valid = valid && super.index_blocks > 1 &&
        adytumfs_index_live(dev, &layout, &fresh) == 0 && fresh == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    u8 key_a[ADYTUMFS_CAS_HASH_SIZE];
    u8 key_b[ADYTUMFS_CAS_HASH_SIZE];
    cas_key(1, key_a);
    cas_key(2, key_b);

    u64 unknown = 0;
    valid = valid &&
        adytumfs_cas_lookup(dev, &super, &store, key_a, &unknown) != 0 &&
        cas_live(dev, &super, &store) == 0;

    u64 free0 = super.free_blocks;
    u64 block_a = 0;
    u64 block_a_again = 0;
    u64 block_b = 0;

    // The first acquire costs exactly one block.
    valid = valid &&
        adytumfs_cas_acquire(dev, &super, &store, key_a, &block_a) == 0 &&
        super.free_blocks == free0 - 1 && cas_live(dev, &super, &store) == 1;

    // The second acquire of the same content costs nothing and lands on the
    // same block. This is the assertion the whole design rests on: sharing is
    // real, not a coincidence of the allocator handing back the same number.
    valid = valid &&
        adytumfs_cas_acquire(dev, &super, &store, key_a, &block_a_again) == 0 &&
        block_a_again == block_a && super.free_blocks == free0 - 1 &&
        cas_live(dev, &super, &store) == 1;

    // Different content is a different block.
    valid = valid &&
        adytumfs_cas_acquire(dev, &super, &store, key_b, &block_b) == 0 &&
        block_b != block_a && super.free_blocks == free0 - 2 &&
        cas_live(dev, &super, &store) == 2;

    cas_image(1, block);
    valid = valid && adytumfs_block_write(dev, block_a, block) == 0;

    // Relocation moves the content and repoints the index. The key is an
    // input, never rewritten: the same hash still finds the block, now at a
    // new address, and the old address is back in the free count.
    u64 moved = 0;
    valid = valid &&
        adytumfs_cas_relocate(dev, &super, &store, key_a, &moved) == 0 &&
        moved != block_a && super.free_blocks == free0 - 2;
    u64 found = 0;
    valid = valid &&
        adytumfs_cas_lookup(dev, &super, &store, key_a, &found) == 0 &&
        found == moved &&
        adytumfs_block_read(dev, moved, readback) == 0;
    for (u32 index = 0; valid && index < ADYTUMFS_BLOCK_SIZE; index++)
        valid = readback[index] == block[index];

    // Refcounting: the first release only drops a reference, the second frees
    // the block exactly once.
    valid = valid &&
        adytumfs_cas_release(dev, &super, &store, key_a) == 0 &&
        super.free_blocks == free0 - 2 && cas_live(dev, &super, &store) == 2;
    valid = valid &&
        adytumfs_cas_release(dev, &super, &store, key_a) == 0 &&
        super.free_blocks == free0 - 1 && cas_live(dev, &super, &store) == 1;
    valid = valid &&
        adytumfs_cas_lookup(dev, &super, &store, key_a, &found) != 0 &&
        adytumfs_cas_release(dev, &super, &store, key_a) != 0;

    valid = valid &&
        adytumfs_cas_release(dev, &super, &store, key_b) == 0 &&
        super.free_blocks == free0 && cas_live(dev, &super, &store) == 0;

    // More mappings than there are cache slots. Under the old table this loop
    // could not run at all: it stopped at the size of the array and refused
    // the rest, which capped the filesystem at a few hundred blocks.
    u8 key[ADYTUMFS_CAS_HASH_SIZE];
    u64 spare = 0;
    for (u32 index = 0; index < CAS_TEST_MANY; index++) {
        cas_key(index + 100u, key);
        valid = valid &&
            adytumfs_cas_place(dev, &super, &store, key, &spare) == 0;
    }
    valid = valid && cas_live(dev, &super, &store) == CAS_TEST_MANY;

    // Every one of them still resolves, including the ones the cache had to
    // throw away to make room. A miss has to cost a read of the index and
    // nothing else.
    for (u32 index = 0; index < CAS_TEST_MANY; index++) {
        u64 where = 0;
        cas_key(index + 100u, key);
        valid = valid &&
            adytumfs_cas_lookup(dev, &super, &store, key, &where) == 0 &&
            where != 0;
    }

    // Dropping the cache entirely is the strongest form of the same claim:
    // nothing lives in memory that the index does not also hold.
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);
    valid = valid && cas_live(dev, &super, &store) == CAS_TEST_MANY;
    for (u32 index = 0; index < CAS_TEST_MANY; index++) {
        u64 where = 0;
        u32 refs = 9u;
        cas_key(index + 100u, key);
        valid = valid &&
            adytumfs_cas_lookup(dev, &super, &store, key, &where) == 0 &&
            adytumfs_cas_refs(dev, &super, &store, key, &refs) == 0 &&
            refs == 0;
    }

    // A slot given back is reusable, and taking it again does not disturb the
    // rest of the index.
    cas_key(100u, key);
    valid = valid &&
        adytumfs_cas_retain(dev, &super, &store, key) == 0 &&
        adytumfs_cas_release(dev, &super, &store, key) == 0 &&
        adytumfs_cas_lookup(dev, &super, &store, key, &found) != 0 &&
        cas_live(dev, &super, &store) == CAS_TEST_MANY - 1u;
    valid = valid &&
        adytumfs_cas_acquire(dev, &super, &store, key, &spare) == 0 &&
        cas_live(dev, &super, &store) == CAS_TEST_MANY;
    for (u32 index = 0; index < CAS_TEST_MANY; index++) {
        u64 where = 0;
        cas_key(index + 100u, key);
        valid = valid &&
            adytumfs_cas_lookup(dev, &super, &store, key, &where) == 0;
    }

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
