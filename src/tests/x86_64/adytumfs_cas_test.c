#include "types.h"
#include "object.h"
#include "block.h"
#include "blake2b.h"
#include "adytumfs_cas.h"

// A distinct key per index, derived with the same hash the filesystem will
// use, so the table is exercised on real digests rather than on hand written
// byte patterns that could accidentally collide.
static void cas_key(u32 index, u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    u8 seed[4];
    for (u32 byte = 0; byte < 4; byte++)
        seed[byte] = (u8)(index >> (byte * 8));
    blake2b(hash, ADYTUMFS_CAS_HASH_SIZE, seed, 4);
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

    adytumfs_cas_reset(&store);
    u8 key_a[ADYTUMFS_CAS_HASH_SIZE];
    u8 key_b[ADYTUMFS_CAS_HASH_SIZE];
    cas_key(1, key_a);
    cas_key(2, key_b);

    u64 unknown = 0;
    valid = valid && adytumfs_cas_lookup(&store, key_a, &unknown) != 0 &&
        adytumfs_cas_count(&store) == 0;

    u64 free0 = super.free_blocks;
    u64 block_a = 0;
    u64 block_a_again = 0;
    u64 block_b = 0;

    // The first acquire costs exactly one block.
    valid = valid && adytumfs_cas_acquire(dev, &super, &store, key_a,
                                          &block_a) == 0 &&
        super.free_blocks == free0 - 1 && adytumfs_cas_count(&store) == 1;

    // The second acquire of the same content costs nothing and lands on the
    // same block. This is the assertion the whole design rests on: sharing is
    // real, not a coincidence of the allocator handing back the same number.
    valid = valid && adytumfs_cas_acquire(dev, &super, &store, key_a,
                                          &block_a_again) == 0 &&
        block_a_again == block_a && super.free_blocks == free0 - 1 &&
        adytumfs_cas_count(&store) == 1;

    // Different content is a different block.
    valid = valid && adytumfs_cas_acquire(dev, &super, &store, key_b,
                                          &block_b) == 0 &&
        block_b != block_a && super.free_blocks == free0 - 2 &&
        adytumfs_cas_count(&store) == 2;

    // Put recognisable content in the shared block so relocation has
    // something to move.
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        block[index] = (u8)(index * 7u + 3u);
    valid = valid && adytumfs_data_write(dev, &super, block_a, block) == 0;

    // Relocation moves the content and repoints the table. The key is an
    // input, never rewritten: the same hash still finds the block, now at a
    // new address, and the old address is back in the free count.
    u64 moved = 0;
    valid = valid && adytumfs_cas_relocate(dev, &super, &store, key_a,
                                           &moved) == 0 &&
        moved != block_a && super.free_blocks == free0 - 2;
    u64 found = 0;
    valid = valid && adytumfs_cas_lookup(&store, key_a, &found) == 0 &&
        found == moved &&
        adytumfs_data_read(dev, &super, moved, readback) == 0;
    for (u32 index = 0; valid && index < ADYTUMFS_BLOCK_SIZE; index++)
        valid = readback[index] == (u8)(index * 7u + 3u);

    // Refcounting: the first release only drops a reference, the second frees
    // the block exactly once.
    valid = valid && adytumfs_cas_release(dev, &super, &store, key_a) == 0 &&
        super.free_blocks == free0 - 2 && adytumfs_cas_count(&store) == 2;
    valid = valid && adytumfs_cas_release(dev, &super, &store, key_a) == 0 &&
        super.free_blocks == free0 - 1 && adytumfs_cas_count(&store) == 1;
    valid = valid && adytumfs_cas_lookup(&store, key_a, &found) != 0 &&
        adytumfs_cas_release(dev, &super, &store, key_a) != 0;

    valid = valid && adytumfs_cas_release(dev, &super, &store, key_b) == 0 &&
        super.free_blocks == free0 && adytumfs_cas_count(&store) == 0;

    // A full table refuses rather than silently losing the sharing it exists
    // to provide, and a slot freed afterwards is reusable, which is what a
    // tombstone in an open addressed table has to earn.
    u8 key[ADYTUMFS_CAS_HASH_SIZE];
    u64 spare = 0;
    u32 filled = 0;
    for (u32 index = 0; index < ADYTUMFS_CAS_SLOTS; index++) {
        cas_key(index + 100u, key);
        if (adytumfs_cas_acquire(dev, &super, &store, key, &spare)) break;
        filled++;
    }
    valid = valid && filled == ADYTUMFS_CAS_SLOTS &&
        adytumfs_cas_count(&store) == ADYTUMFS_CAS_SLOTS;
    cas_key(ADYTUMFS_CAS_SLOTS + 100u, key);
    valid = valid && adytumfs_cas_acquire(dev, &super, &store, key,
                                          &spare) != 0 &&
        adytumfs_cas_count(&store) == ADYTUMFS_CAS_SLOTS;

    cas_key(100u, key);
    valid = valid && adytumfs_cas_release(dev, &super, &store, key) == 0 &&
        adytumfs_cas_acquire(dev, &super, &store, key, &spare) == 0;

    // Every entry still resolves after the churn, which is the probe staying
    // correct across tombstones rather than merely not crashing.
    for (u32 index = 0; valid && index < ADYTUMFS_CAS_SLOTS; index++) {
        cas_key(index + 100u, key);
        valid = adytumfs_cas_lookup(&store, key, &spare) == 0;
    }

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
