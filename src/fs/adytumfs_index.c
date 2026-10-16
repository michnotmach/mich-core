#include "adytumfs_index.h"
#include "crc32c.h"
#include "crypto.h"

// The index is the one structure no parent hash vouches for, so every block
// carries its own crc32c in the header. The field reads as zero while the
// value over the block is computed, and the spare word behind it stays zero.
static void index_seal(u8 *block, u32 at) {
    adytumfs_write_le32(block + at, 0);
    adytumfs_write_le32(block + at, crc32c(block, ADYTUMFS_BLOCK_SIZE));
}

// The field has to read as zero while the block is hashed, so it is cleared
// in the caller's buffer and put back rather than copied to a scratch block.
static int index_verify(u8 *block, u32 at) {
    u32 stored = adytumfs_read_le32(block + at);
    adytumfs_write_le32(block + at, 0);
    u32 actual = crc32c(block, ADYTUMFS_BLOCK_SIZE);
    adytumfs_write_le32(block + at, stored);
    return actual == stored ? 0 : -1;
}

_Static_assert(ADYTUMFS_INDEX_ENTRY_SIZE * ADYTUMFS_INDEX_PER_BLOCK +
                   ADYTUMFS_INDEX_HEADER_SIZE <=
               ADYTUMFS_BLOCK_SIZE,
               "index entries must fit one block without straddling");

// The key is already a BLAKE2b digest, so its leading bytes are uniform and
// index the table directly. Hashing a hash would only add a second function
// that could disagree with the first.
static u64 index_bucket(const struct adytumfs_index *index,
                        const u8 hash[ADYTUMFS_INDEX_HASH_SIZE]) {
    u64 value = 0;
    for (u32 byte = 0; byte < 8; byte++)
        value |= (u64)hash[byte] << (byte * 8);
    return value % index->capacity;
}

static u64 index_entry_block(u64 entry) {
    return 1u + entry / ADYTUMFS_INDEX_PER_BLOCK;
}

static u32 index_entry_offset(u64 entry) {
    return ADYTUMFS_INDEX_HEADER_SIZE +
           (u32)(entry % ADYTUMFS_INDEX_PER_BLOCK) *
               ADYTUMFS_INDEX_ENTRY_SIZE;
}

static u32 index_entry_live(const u8 *entry) {
    return adytumfs_read_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 12);
}

static u32 index_entry_refs(const u8 *entry) {
    return adytumfs_read_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 8);
}

static u64 index_entry_number(const u8 *entry) {
    return adytumfs_read_le64(entry + ADYTUMFS_INDEX_HASH_SIZE);
}

void adytumfs_index_init(struct adytumfs_index *index, u64 start,
                         u64 blocks) {
    index->start = start;
    index->blocks = blocks;
    index->capacity =
        blocks > 1u ? (blocks - 1u) * ADYTUMFS_INDEX_PER_BLOCK : 0;
}

int adytumfs_index_format(struct kernel_object *device,
                          const struct adytumfs_index *index) {
    if (!device || !index) return -1;
    if (!index->capacity) return -1;
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++) block[byte] = 0;
    for (u64 which = 1; which < index->blocks; which++) {
        adytumfs_write_le32(block, ADYTUMFS_INDEX_MAGIC);
        adytumfs_write_le32(block + 4, (u32)which);
        index_seal(block, ADYTUMFS_INDEX_CRC_ENTRY);
        if (adytumfs_block_write(device, index->start + which, block))
            return -1;
    }
    for (u32 byte = 0; byte < ADYTUMFS_BLOCK_SIZE; byte++) block[byte] = 0;
    adytumfs_write_le32(block, ADYTUMFS_INDEX_SUPER_MAGIC);
    adytumfs_write_le32(block + 4, ADYTUMFS_INDEX_VERSION);
    adytumfs_write_le64(block + 8, index->capacity);
    adytumfs_write_le64(block + 16, 0);
    index_seal(block, ADYTUMFS_INDEX_CRC_SUPER);
    // The header goes last: a mount that finds it knows the entry blocks
    // behind it are already there, and one that does not finds nothing at all
    // rather than a header pointing at unwritten blocks.
    return adytumfs_block_write(device, index->start, block);
}

static int index_super_read(struct kernel_object *device,
                            const struct adytumfs_index *index, u8 *block) {
    if (!index->capacity) return -1;
    if (adytumfs_block_read(device, index->start, block)) return -1;
    if (index_verify(block, ADYTUMFS_INDEX_CRC_SUPER)) return -1;
    if (adytumfs_read_le32(block) != ADYTUMFS_INDEX_SUPER_MAGIC) return -1;
    if (adytumfs_read_le32(block + 4) != ADYTUMFS_INDEX_VERSION) return -1;
    if (adytumfs_read_le64(block + 8) != index->capacity) return -1;
    return 0;
}

static int index_live_set(struct kernel_object *device,
                          const struct adytumfs_index *index, u64 live) {
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    if (index_super_read(device, index, block)) return -1;
    adytumfs_write_le64(block + 16, live);
    index_seal(block, ADYTUMFS_INDEX_CRC_SUPER);
    return adytumfs_block_write(device, index->start, block);
}

int adytumfs_index_live(struct kernel_object *device,
                        const struct adytumfs_index *index, u64 *live) {
    if (!device || !index || !live) return -1;
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    if (index_super_read(device, index, block)) return -1;
    *live = adytumfs_read_le64(block + 16);
    return 0;
}

static int index_block_read(struct kernel_object *device,
                            const struct adytumfs_index *index, u64 which,
                            u8 *block) {
    if (which < 1u || which >= index->blocks) return -1;
    if (adytumfs_block_read(device, index->start + which, block))
        return -1;
    if (adytumfs_read_le32(block) != ADYTUMFS_INDEX_MAGIC) return -1;
    // The position is part of what is checked, so a block that reached the
    // wrong place in the run is refused instead of read as its neighbour.
    if (adytumfs_read_le32(block + 4) != (u32)which) return -1;
    if (index_verify(block, ADYTUMFS_INDEX_CRC_ENTRY)) return -1;
    if (adytumfs_read_le32(block + 12)) return -1;
    return 0;
}

// Linear probing. A tombstone is reusable but never ends a probe, because a
// live entry may sit behind it and stopping at the hole would orphan it.
static int index_probe(struct kernel_object *device,
                       const struct adytumfs_index *index,
                       const u8 hash[ADYTUMFS_INDEX_HASH_SIZE], u64 *slot,
                       int *found, u64 *reuse, u8 *entry_out) {
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    u64 entry = index_bucket(index, hash);
    u64 cached = index->blocks;
    *reuse = index->capacity;
    *found = 0;
    *slot = 0;
    for (u64 spin = 0; spin < index->capacity; spin++) {
        u64 which = index_entry_block(entry);
        if (which != cached) {
            if (index_block_read(device, index, which, block))
                return -1;
            cached = which;
        }
        const u8 *at = block + index_entry_offset(entry);
        u32 live = index_entry_live(at);
        if (live == ADYTUMFS_INDEX_LIVE &&
            crypto_equal(at, hash, ADYTUMFS_INDEX_HASH_SIZE)) {
            for (u32 byte = 0; byte < ADYTUMFS_INDEX_ENTRY_SIZE; byte++)
                entry_out[byte] = at[byte];
            *slot = entry;
            *found = 1;
            return 0;
        }
        if (live != ADYTUMFS_INDEX_LIVE && *reuse == index->capacity)
            *reuse = entry;
        entry = (entry + 1u) % index->capacity;
    }
    return 0;
}

static int index_entry_write(struct kernel_object *device,
                             const struct adytumfs_index *index, u64 slot,
                             const u8 *entry) {
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    u64 which = index_entry_block(slot);
    if (index_block_read(device, index, which, block)) return -1;
    u8 *at = block + index_entry_offset(slot);
    for (u32 byte = 0; byte < ADYTUMFS_INDEX_ENTRY_SIZE; byte++)
        at[byte] = entry[byte];
    index_seal(block, ADYTUMFS_INDEX_CRC_ENTRY);
    return adytumfs_block_write(device, index->start + which, block);
}

static int index_entry_fetch(struct kernel_object *device,
                             const struct adytumfs_index *index,
                             const u8 hash[ADYTUMFS_INDEX_HASH_SIZE],
                             u8 *entry) {
    u64 slot = 0;
    u64 reuse = 0;
    int found = 0;
    if (index_probe(device, index, hash, &slot, &found, &reuse, entry))
        return -1;
    if (!found) return -1;
    return 0;
}

int adytumfs_index_lookup(struct kernel_object *device,
                          const struct adytumfs_index *index,
                          const u8 hash[ADYTUMFS_INDEX_HASH_SIZE],
                          u64 *block) {
    if (!device || !index || !hash || !block) return -1;
    u8 entry[ADYTUMFS_INDEX_ENTRY_SIZE];
    if (index_entry_fetch(device, index, hash, entry)) return -1;
    *block = index_entry_number(entry);
    return 0;
}

int adytumfs_index_fetch(struct kernel_object *device,
                         const struct adytumfs_index *index,
                         const u8 hash[ADYTUMFS_INDEX_HASH_SIZE], u64 *block,
                         u32 *refs) {
    if (!device || !index || !hash || !block || !refs) return -1;
    u8 entry[ADYTUMFS_INDEX_ENTRY_SIZE];
    if (index_entry_fetch(device, index, hash, entry)) return -1;
    *block = index_entry_number(entry);
    *refs = index_entry_refs(entry);
    return 0;
}

int adytumfs_index_repoint(struct kernel_object *device,
                           const struct adytumfs_index *index,
                           const u8 hash[ADYTUMFS_INDEX_HASH_SIZE],
                           u64 block) {
    if (!device || !index || !hash) return -1;
    u64 slot = 0;
    u64 reuse = 0;
    int found = 0;
    u8 entry[ADYTUMFS_INDEX_ENTRY_SIZE];
    if (index_probe(device, index, hash, &slot, &found, &reuse, entry))
        return -1;
    if (!found) return -1;
    adytumfs_write_le64(entry + ADYTUMFS_INDEX_HASH_SIZE, block);
    return index_entry_write(device, index, slot, entry);
}

int adytumfs_index_refs(struct kernel_object *device,
                        const struct adytumfs_index *index,
                        const u8 hash[ADYTUMFS_INDEX_HASH_SIZE], u32 *refs) {
    if (!device || !index || !hash || !refs) return -1;
    u8 entry[ADYTUMFS_INDEX_ENTRY_SIZE];
    if (index_entry_fetch(device, index, hash, entry)) return -1;
    *refs = index_entry_refs(entry);
    return 0;
}

int adytumfs_index_insert(struct kernel_object *device,
                          const struct adytumfs_index *index,
                          const u8 hash[ADYTUMFS_INDEX_HASH_SIZE],
                          u64 block) {
    if (!device || !index || !hash) return -1;
    u64 slot = 0;
    u64 reuse = 0;
    int found = 0;
    u8 entry[ADYTUMFS_INDEX_ENTRY_SIZE];
    if (index_probe(device, index, hash, &slot, &found, &reuse, entry))
        return -1;
    if (found) return -1;
    if (reuse >= index->capacity) return -1;
    u64 live = 0;
    if (adytumfs_index_live(device, index, &live)) return -1;
    for (u32 byte = 0; byte < ADYTUMFS_INDEX_HASH_SIZE; byte++)
        entry[byte] = hash[byte];
    adytumfs_write_le64(entry + ADYTUMFS_INDEX_HASH_SIZE, block);
    adytumfs_write_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 8, 0);
    adytumfs_write_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 12,
                        ADYTUMFS_INDEX_LIVE);
    if (index_entry_write(device, index, reuse, entry)) return -1;
    return index_live_set(device, index, live + 1u);
}

int adytumfs_index_retain(struct kernel_object *device,
                          const struct adytumfs_index *index,
                          const u8 hash[ADYTUMFS_INDEX_HASH_SIZE]) {
    if (!device || !index || !hash) return -1;
    u64 slot = 0;
    u64 reuse = 0;
    int found = 0;
    u8 entry[ADYTUMFS_INDEX_ENTRY_SIZE];
    if (index_probe(device, index, hash, &slot, &found, &reuse, entry))
        return -1;
    if (!found) return -1;
    adytumfs_write_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 8,
                        index_entry_refs(entry) + 1u);
    return index_entry_write(device, index, slot, entry);
}

int adytumfs_index_release(struct kernel_object *device,
                           struct adytumfs_superblock *super,
                           const struct adytumfs_index *index,
                           const u8 hash[ADYTUMFS_INDEX_HASH_SIZE],
                           u64 *freed_block) {
    if (!device || !super || !index || !hash || !freed_block) return -1;
    u64 slot = 0;
    u64 reuse = 0;
    int found = 0;
    u8 entry[ADYTUMFS_INDEX_ENTRY_SIZE];
    if (index_probe(device, index, hash, &slot, &found, &reuse, entry))
        return -1;
    if (!found) return -1;
    *freed_block = 0;
    u32 refs = index_entry_refs(entry);
    if (!refs) return -1;
    if (refs > 1u) {
        adytumfs_write_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 8, refs - 1u);
        return index_entry_write(device, index, slot, entry);
    }
    // The block is handed back before the entry is buried, so an interrupted
    // release leaves a live entry pointing at a free block rather than a
    // tombstone hiding a block nobody will ever reach again.
    u64 number = index_entry_number(entry);
    if (adytumfs_free_run(device, super, number, 1)) return -1;
    *freed_block = number;
    adytumfs_write_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 8, 0);
    adytumfs_write_le32(entry + ADYTUMFS_INDEX_HASH_SIZE + 12,
                        ADYTUMFS_INDEX_DEAD);
    if (index_entry_write(device, index, slot, entry)) return -1;
    u64 live = 0;
    if (adytumfs_index_live(device, index, &live)) return -1;
    if (!live) return -1;
    return index_live_set(device, index, live - 1u);
}
