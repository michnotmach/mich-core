#include "adytumfs_cas.h"
#include "crypto.h"

_Static_assert((ADYTUMFS_CAS_SLOTS & (ADYTUMFS_CAS_SLOTS - 1u)) == 0u,
               "ADYTUMFS_CAS_SLOTS must be a power of two for masking");

// The key is already a BLAKE2b digest, so its leading bytes are uniform and
// index the table directly. Hashing a hash would only add a second function
// that could disagree with the first.
static u32 cas_bucket(const u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    u64 value = 0;
    for (u32 index = 0; index < 8; index++)
        value |= (u64)hash[index] << (index * 8);
    return (u32)(value & (u64)(ADYTUMFS_CAS_SLOTS - 1u));
}

// Linear probing. A tombstone is reusable but never ends a probe, because a
// live entry may sit behind it; deleting without leaving one would orphan
// everything past the hole.
static u32 cas_slot(const struct adytumfs_cas *store,
                    const u8 hash[ADYTUMFS_CAS_HASH_SIZE], int *found) {
    u32 index = cas_bucket(hash);
    u32 reuse = ADYTUMFS_CAS_SLOTS;
    for (u32 spin = 0; spin < ADYTUMFS_CAS_SLOTS; spin++) {
        const struct adytumfs_cas_entry *entry = &store->entries[index];
        if (entry->live == ADYTUMFS_CAS_LIVE &&
            crypto_equal(entry->hash, hash, ADYTUMFS_CAS_HASH_SIZE)) {
            *found = 1;
            return index;
        }
        if (entry->live != ADYTUMFS_CAS_LIVE && reuse == ADYTUMFS_CAS_SLOTS)
            reuse = index;
        if (entry->live == ADYTUMFS_CAS_EMPTY) break;
        index = (index + 1u) & (ADYTUMFS_CAS_SLOTS - 1u);
    }
    *found = 0;
    return reuse;
}

void adytumfs_cas_reset(struct adytumfs_cas *store) {
    if (!store) return;
    for (u32 index = 0; index < ADYTUMFS_CAS_SLOTS; index++) {
        struct adytumfs_cas_entry *entry = &store->entries[index];
        crypto_zero(entry->hash, ADYTUMFS_CAS_HASH_SIZE);
        entry->block = 0;
        entry->refs = 0;
        entry->live = ADYTUMFS_CAS_EMPTY;
    }
    store->count = 0;
}

u32 adytumfs_cas_count(const struct adytumfs_cas *store) {
    return store ? store->count : 0u;
}

int adytumfs_cas_lookup(const struct adytumfs_cas *store,
                        const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block) {
    if (!store || !hash || !block) return -1;
    int found = 0;
    u32 index = cas_slot(store, hash, &found);
    if (!found) return -1;
    *block = store->entries[index].block;
    return 0;
}

int adytumfs_cas_acquire(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block) {
    if (!device || !super || !store || !hash || !block) return -1;
    int found = 0;
    u32 index = cas_slot(store, hash, &found);
    if (found) {
        struct adytumfs_cas_entry *entry = &store->entries[index];
        entry->refs++;
        *block = entry->block;
        return 0;
    }
    if (index >= ADYTUMFS_CAS_SLOTS) return -1;
    u64 start = 0;
    if (adytumfs_alloc_run(device, super, 1, &start)) return -1;
    struct adytumfs_cas_entry *entry = &store->entries[index];
    for (u32 offset = 0; offset < ADYTUMFS_CAS_HASH_SIZE; offset++)
        entry->hash[offset] = hash[offset];
    entry->block = start;
    entry->refs = 1u;
    entry->live = ADYTUMFS_CAS_LIVE;
    store->count++;
    *block = start;
    return 0;
}

int adytumfs_cas_release(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!device || !super || !store || !hash) return -1;
    int found = 0;
    u32 index = cas_slot(store, hash, &found);
    if (!found) return -1;
    struct adytumfs_cas_entry *entry = &store->entries[index];
    if (!entry->refs) return -1;
    entry->refs--;
    if (entry->refs) return 0;
    u64 start = entry->block;
    entry->block = 0;
    entry->live = ADYTUMFS_CAS_DEAD;
    store->count--;
    return adytumfs_free_run(device, super, start, 1);
}

// A block is too large for a modest stack and this file is reached under the
// filesystem lock, so the copy stages in one shared block, the way the bitmap
// staging buffer in adytumfs_volume.c does.
static u8 cas_copy_scratch[ADYTUMFS_BLOCK_SIZE];

int adytumfs_cas_relocate(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store,
                          const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block) {
    if (!device || !super || !store || !hash || !block) return -1;
    int found = 0;
    u32 index = cas_slot(store, hash, &found);
    if (!found) return -1;
    u64 from = store->entries[index].block;
    u64 to = 0;
    if (adytumfs_alloc_run(device, super, 1, &to)) return -1;
    if (adytumfs_data_read(device, super, from, cas_copy_scratch) ||
        adytumfs_data_write(device, super, to, cas_copy_scratch)) {
        adytumfs_free_run(device, super, to, 1);
        return -1;
    }
    struct adytumfs_cas_entry *entry = &store->entries[index];
    entry->block = to;
    if (adytumfs_free_run(device, super, from, 1)) return -1;
    *block = to;
    return 0;
}
