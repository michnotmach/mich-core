#include "types.h"
#include "object.h"
#include "block.h"
#include "blake2b.h"
#include "crypto.h"
#include "adytumfs_index.h"

#define INDEX_TEST_ENTRIES 80u

// Deterministic filler, so a lookup that hands back the wrong entry shows up
// as a mismatch rather than as two matching zero hashes.
static void hash_at(u32 index, u8 hash[ADYTUMFS_INDEX_HASH_SIZE]) {
    u8 seed[4];
    for (u32 byte = 0; byte < 4; byte++)
        seed[byte] = (u8)(index >> (byte * 8));
    blake2b(hash, ADYTUMFS_INDEX_HASH_SIZE, seed, 4);
}

// Count the mappings that should still be there and are not. Rounds 10 to 20
// were released on purpose, so they are skipped: without that, a failure here
// could be a mapping the test itself dropped and the check would pass no
// matter what happened to the blocks.
static u32 index_missing(struct kernel_object *device,
                         const struct adytumfs_superblock *super,
                         const struct adytumfs_index *index) {
    u8 hash[ADYTUMFS_INDEX_HASH_SIZE];
    u64 number = 0;
    u32 missing = 0;
    for (u32 round = 0; round < INDEX_TEST_ENTRIES + 10u; round++) {
        if (round >= 10u && round <= 20u) continue;
        hash_at(round, hash);
        if (adytumfs_index_lookup(device, super, index, hash, &number))
            missing++;
    }
    return missing;
}

int test_adytumfs_index64(void) {
    static u8 scratch[ADYTUMFS_BLOCK_SIZE];
    static u8 hash[ADYTUMFS_INDEX_HASH_SIZE];
    static u64 placed[INDEX_TEST_ENTRIES];
    struct adytumfs_superblock super;
    struct adytumfs_index index;
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(4096, 0);
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, scratch) == 0 &&
        adytumfs_super_unpack(&super, scratch) == 0;

    // Three blocks: one header and two of entries, which is 102 slots for 80
    // mappings. A table that loose would never make a probe leave the block it
    // started in, and the block to block wrap would go untested.
    u64 start = 0;
    valid = valid && adytumfs_alloc_run(dev, &super, 3, &start) == 0;
    adytumfs_index_init(&index, start, 3);
    valid = valid && index.capacity == 2u * ADYTUMFS_INDEX_PER_BLOCK;

    // Before format there is nothing to read, and that has to be a refusal
    // rather than a run of zeroes that happens to look like an empty table.
    u64 live = 1u;
    valid = valid && adytumfs_index_live(dev, &super, &index, &live) != 0;
    valid = valid && adytumfs_index_format(dev, &super, &index) == 0 &&
        adytumfs_index_live(dev, &super, &index, &live) == 0 && live == 0;

    hash_at(0, hash);
    u64 number = 0;
    valid = valid &&
        adytumfs_index_lookup(dev, &super, &index, hash, &number) != 0;

    // Every mapping points at a block the allocator really handed out, because
    // release gives the block back and a number that was never allocated would
    // corrupt the bitmap rather than test anything.
    for (u32 round = 0; round < INDEX_TEST_ENTRIES; round++) {
        hash_at(round, hash);
        valid = valid &&
            adytumfs_alloc_run(dev, &super, 1, &placed[round]) == 0 &&
            adytumfs_index_insert(dev, &super, &index, hash,
                                  placed[round]) == 0;
    }
    valid = valid && adytumfs_index_live(dev, &super, &index, &live) == 0 &&
        live == INDEX_TEST_ENTRIES;
    for (u32 round = 0; round < INDEX_TEST_ENTRIES; round++) {
        u32 refs = 9u;
        hash_at(round, hash);
        valid = valid &&
            adytumfs_index_lookup(dev, &super, &index, hash, &number) == 0 &&
            number == placed[round] &&
            adytumfs_index_refs(dev, &super, &index, hash, &refs) == 0 &&
            refs == 0;
    }

    // A second block claiming content that is already mapped is refused. Two
    // answers to one question is what this table exists to prevent.
    hash_at(7, hash);
    valid = valid &&
        adytumfs_index_insert(dev, &super, &index, hash, start) != 0;

    u32 refs = 0;
    valid = valid &&
        adytumfs_index_retain(dev, &super, &index, hash) == 0 &&
        adytumfs_index_retain(dev, &super, &index, hash) == 0 &&
        adytumfs_index_refs(dev, &super, &index, hash, &refs) == 0 &&
        refs == 2u;

    // Not the last reference, so the block stays claimed and the mapping
    // stays live.
    u64 freed = 1u;
    valid = valid &&
        adytumfs_index_release(dev, &super, &index, hash, &freed) == 0 &&
        freed == 0 &&
        adytumfs_index_refs(dev, &super, &index, hash, &refs) == 0 &&
        refs == 1u &&
        adytumfs_index_live(dev, &super, &index, &live) == 0 &&
        live == INDEX_TEST_ENTRIES;

    valid = valid &&
        adytumfs_index_release(dev, &super, &index, hash, &freed) == 0 &&
        freed == placed[7] &&
        adytumfs_index_lookup(dev, &super, &index, hash, &number) != 0 &&
        adytumfs_index_live(dev, &super, &index, &live) == 0 &&
        live == INDEX_TEST_ENTRIES - 1u;
    valid = valid &&
        adytumfs_index_release(dev, &super, &index, hash, &freed) != 0 &&
        adytumfs_index_retain(dev, &super, &index, hash) != 0;

    // The tombstone is reusable and the freed block is allocatable again, so
    // freeing makes room rather than leaving a hole the table fills around.
    u64 again = 0;
    valid = valid && adytumfs_alloc_run(dev, &super, 1, &again) == 0 &&
        adytumfs_index_insert(dev, &super, &index, hash, again) == 0 &&
        adytumfs_index_lookup(dev, &super, &index, hash, &number) == 0 &&
        number == again &&
        adytumfs_index_live(dev, &super, &index, &live) == 0 &&
        live == INDEX_TEST_ENTRIES;
    for (u32 round = INDEX_TEST_ENTRIES; round < INDEX_TEST_ENTRIES + 10u;
         round++) {
        hash_at(round, hash);
        valid = valid &&
            adytumfs_alloc_run(dev, &super, 1, &again) == 0 &&
            adytumfs_index_insert(dev, &super, &index, hash, again) == 0;
    }
    valid = valid && adytumfs_index_live(dev, &super, &index, &live) == 0 &&
        live == INDEX_TEST_ENTRIES + 10u;

    // Freeing an entry leaves a tombstone ahead of everything that was pushed
    // past it, and from then on a duplicate of those entries has a reusable
    // slot waiting before the live one. Refusing it is what keeps one content
    // from ending up mapped twice, so every live entry is offered again.
    for (u32 round = 10u; round < 20u; round++) {
        hash_at(round, hash);
        valid = valid &&
            adytumfs_index_retain(dev, &super, &index, hash) == 0 &&
            adytumfs_index_release(dev, &super, &index, hash, &freed) == 0 &&
            freed == placed[round];
    }
    valid = valid && adytumfs_index_live(dev, &super, &index, &live) == 0 &&
        live == INDEX_TEST_ENTRIES;
    for (u32 round = 20u; round < INDEX_TEST_ENTRIES + 10u; round++) {
        hash_at(round, hash);
        valid = valid &&
            adytumfs_index_insert(dev, &super, &index, hash, start) != 0 &&
            adytumfs_index_live(dev, &super, &index, &live) == 0 &&
            live == INDEX_TEST_ENTRIES;
    }
    // And a single release still removes a mapping entirely, which is what
    // fails first if a duplicate ever gets in.
    hash_at(20, hash);
    valid = valid &&
        adytumfs_index_retain(dev, &super, &index, hash) == 0 &&
        adytumfs_index_release(dev, &super, &index, hash, &freed) == 0 &&
        adytumfs_index_lookup(dev, &super, &index, hash, &number) != 0;

    // Everything that should be reachable is, before anything is damaged.
    // Without this the counts below could pass by finding nothing at all.
    static u8 pristine[ADYTUMFS_BLOCK_SIZE];
    valid = valid && index_missing(dev, &super, &index) == 0;

    // A block that no longer carries the index magic is refused, so a never
    // written or overwritten block is not read as an index block.
    valid = valid &&
        adytumfs_data_read(dev, &super, start + 1, scratch) == 0;
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        pristine[byte] = scratch[byte];
    scratch[0] ^= 0x01u;
    valid = valid &&
        adytumfs_data_write(dev, &super, start + 1, scratch) == 0 &&
        index_missing(dev, &super, &index) > 0 &&
        adytumfs_data_write(dev, &super, start + 1, pristine) == 0 &&
        index_missing(dev, &super, &index) == 0;

    // Now only the position field is wrong. The magic is right and every entry
    // is untouched, so nothing but the position can give away that this is not
    // the block it is sitting in.
    valid = valid &&
        adytumfs_data_read(dev, &super, start + 2, scratch) == 0;
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        pristine[byte] = scratch[byte];
    adytumfs_write_le32(scratch + 4, 1u);
    valid = valid &&
        adytumfs_data_write(dev, &super, start + 2, scratch) == 0 &&
        index_missing(dev, &super, &index) > 0 &&
        adytumfs_data_write(dev, &super, start + 2, pristine) == 0 &&
        index_missing(dev, &super, &index) == 0;

    // A header describing a run of some other size is refused rather than
    // probed against the wrong capacity, which would read entries out of
    // blocks that were never part of this index.
    valid = valid && adytumfs_data_read(dev, &super, start, scratch) == 0;
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        pristine[byte] = scratch[byte];
    adytumfs_write_le64(scratch + 8, index.capacity + 1u);
    valid = valid &&
        adytumfs_data_write(dev, &super, start, scratch) == 0 &&
        adytumfs_index_live(dev, &super, &index, &live) != 0 &&
        adytumfs_data_write(dev, &super, start, pristine) == 0 &&
        adytumfs_index_live(dev, &super, &index, &live) == 0;

    // A header from another version of the format is refused instead of read
    // with this one's layout.
    valid = valid && adytumfs_data_read(dev, &super, start, scratch) == 0;
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        pristine[byte] = scratch[byte];
    adytumfs_write_le32(scratch + 4, ADYTUMFS_INDEX_VERSION + 1u);
    valid = valid &&
        adytumfs_data_write(dev, &super, start, scratch) == 0 &&
        adytumfs_index_live(dev, &super, &index, &live) != 0 &&
        adytumfs_data_write(dev, &super, start, pristine) == 0 &&
        adytumfs_index_live(dev, &super, &index, &live) == 0;

    // The spare bytes of an entry block stay zero, so anything writing into
    // them shows up rather than sitting there until it overlaps an entry.
    valid = valid &&
        adytumfs_data_read(dev, &super, start + 1, scratch) == 0;
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++)
        pristine[byte] = scratch[byte];
    adytumfs_write_le64(scratch + 8, 1u);
    valid = valid &&
        adytumfs_data_write(dev, &super, start + 1, scratch) == 0 &&
        index_missing(dev, &super, &index) > 0 &&
        adytumfs_data_write(dev, &super, start + 1, pristine) == 0 &&
        index_missing(dev, &super, &index) == 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
