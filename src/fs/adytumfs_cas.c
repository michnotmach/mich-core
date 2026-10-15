#include "adytumfs_cas.h"
#include "blake2b.h"
#include "crypto.h"

_Static_assert((ADYTUMFS_CAS_SLOTS & (ADYTUMFS_CAS_SLOTS - 1u)) == 0u,
               "ADYTUMFS_CAS_SLOTS must be a power of two for masking");

// The key is already a BLAKE2b digest, so its leading bytes are uniform and
// index the cache directly. Hashing a hash would only add a second function
// that could disagree with the first.
static u32 cas_bucket(const u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    u64 value = 0;
    for (u32 index = 0; index < 8; index++)
        value |= (u64)hash[index] << (index * 8);
    return (u32)(value & (u64)(ADYTUMFS_CAS_SLOTS - 1u));
}

static void cas_install(struct adytumfs_cas *store,
                        const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 block,
                        u32 refs) {
    struct adytumfs_cas_entry *entry = &store->entries[cas_bucket(hash)];
    for (u32 offset = 0; offset < ADYTUMFS_CAS_HASH_SIZE; offset++)
        entry->hash[offset] = hash[offset];
    entry->block = block;
    entry->refs = refs;
    entry->live = ADYTUMFS_CAS_LIVE;
}

static int cas_hit(const struct adytumfs_cas *store,
                   const u8 hash[ADYTUMFS_CAS_HASH_SIZE],
                   struct adytumfs_cas_entry *out) {
    const struct adytumfs_cas_entry *entry = &store->entries[cas_bucket(hash)];
    if (entry->live != ADYTUMFS_CAS_LIVE) return -1;
    if (!crypto_equal(entry->hash, hash, ADYTUMFS_CAS_HASH_SIZE)) return -1;
    *out = *entry;
    return 0;
}

static void cas_drop(struct adytumfs_cas *store,
                     const u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    struct adytumfs_cas_entry *entry = &store->entries[cas_bucket(hash)];
    if (entry->live != ADYTUMFS_CAS_LIVE) return;
    if (!crypto_equal(entry->hash, hash, ADYTUMFS_CAS_HASH_SIZE)) return;
    crypto_zero(entry->hash, ADYTUMFS_CAS_HASH_SIZE);
    entry->block = 0;
    entry->refs = 0;
    entry->live = ADYTUMFS_CAS_EMPTY;
}

void adytumfs_cas_open(struct adytumfs_cas *store, u64 start, u64 blocks) {
    if (!store) return;
    adytumfs_index_init(&store->index, start, blocks);
    for (u32 index = 0; index < ADYTUMFS_CAS_SLOTS; index++) {
        struct adytumfs_cas_entry *entry = &store->entries[index];
        crypto_zero(entry->hash, ADYTUMFS_CAS_HASH_SIZE);
        entry->block = 0;
        entry->refs = 0;
        entry->live = ADYTUMFS_CAS_EMPTY;
    }
}

int adytumfs_cas_count(struct kernel_object *device,
                       const struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u64 *count) {
    if (!device || !super || !store || !count) return -1;
    return adytumfs_index_live(device, super, &store->index, count);
}

int adytumfs_cas_lookup(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block) {
    if (!device || !super || !store || !hash || !block) return -1;
    struct adytumfs_cas_entry hit;
    if (cas_hit(store, hash, &hit) == 0) {
        *block = hit.block;
        return 0;
    }
    u64 number = 0;
    u32 refs = 0;
    if (adytumfs_index_fetch(device, super, &store->index, hash, &number,
                             &refs))
        return -1;
    cas_install(store, hash, number, refs);
    *block = number;
    return 0;
}

int adytumfs_cas_read(struct kernel_object *device,
                      const struct adytumfs_superblock *super,
                      struct adytumfs_cas *store,
                      const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u8 *buffer) {
    if (!buffer) return -1;
    u64 number = 0;
    if (adytumfs_cas_lookup(device, super, store, hash, &number)) return -1;
    if (adytumfs_block_read(device, number, buffer)) return -1;
    return adytumfs_cas_verify(hash, buffer);
}

int adytumfs_cas_verify(const u8 hash[ADYTUMFS_CAS_HASH_SIZE],
                        const u8 *buffer) {
    if (!hash || !buffer) return -1;
    u8 check[ADYTUMFS_CAS_HASH_SIZE];
    if (blake2b(check, ADYTUMFS_CAS_HASH_SIZE, buffer, ADYTUMFS_BLOCK_SIZE))
        return -1;
    for (u32 index = 0; index < ADYTUMFS_CAS_HASH_SIZE; index++)
        if (check[index] != hash[index]) return -1;
    return 0;
}

int adytumfs_cas_refs(struct kernel_object *device,
                      const struct adytumfs_superblock *super,
                      struct adytumfs_cas *store,
                      const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u32 *refs) {
    if (!device || !super || !store || !hash || !refs) return -1;
    struct adytumfs_cas_entry hit;
    if (cas_hit(store, hash, &hit) == 0) {
        *refs = hit.refs;
        return 0;
    }
    u64 number = 0;
    u32 index_refs = 0;
    if (adytumfs_index_fetch(device, super, &store->index, hash, &number,
                             &index_refs))
        return -1;
    cas_install(store, hash, number, index_refs);
    *refs = index_refs;
    return 0;
}

int adytumfs_cas_place(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block) {
    if (!device || !super || !store || !hash || !block) return -1;
    u64 number = 0;
    u32 refs = 0;
    if (adytumfs_index_fetch(device, super, &store->index, hash, &number,
                             &refs) == 0) {
        cas_install(store, hash, number, refs);
        *block = number;
        return 0;
    }
    u64 start = 0;
    if (adytumfs_alloc_run(device, super, 1, &start)) return -1;
    if (adytumfs_index_insert(device, super, &store->index, hash, start)) {
        adytumfs_free_run(device, super, start, 1);
        return -1;
    }
    cas_install(store, hash, start, 0);
    *block = start;
    return 0;
}

int adytumfs_cas_acquire(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block) {
    if (adytumfs_cas_place(device, super, store, hash, block)) return -1;
    return adytumfs_cas_retain(device, super, store, hash);
}

int adytumfs_cas_retain(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        const u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!device || !super || !store || !hash) return -1;
    if (adytumfs_index_retain(device, super, &store->index, hash)) return -1;
    u64 number = 0;
    u32 refs = 0;
    if (adytumfs_index_fetch(device, super, &store->index, hash, &number,
                             &refs))
        return -1;
    cas_install(store, hash, number, refs);
    return 0;
}

int adytumfs_cas_release(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 hash[ADYTUMFS_CAS_HASH_SIZE]) {
    if (!device || !super || !store || !hash) return -1;
    u64 freed = 0;
    if (adytumfs_index_release(device, super, &store->index, hash, &freed))
        return -1;
    if (freed) {
        cas_drop(store, hash);
        return 0;
    }
    u64 number = 0;
    u32 refs = 0;
    if (adytumfs_index_fetch(device, super, &store->index, hash, &number,
                             &refs))
        return -1;
    cas_install(store, hash, number, refs);
    return 0;
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
    u64 from = 0;
    u32 refs = 0;
    if (adytumfs_index_fetch(device, super, &store->index, hash, &from, &refs))
        return -1;
    u64 to = 0;
    if (adytumfs_alloc_run(device, super, 1, &to)) return -1;
    if (adytumfs_cas_read(device, super, store, hash, cas_copy_scratch) ||
        adytumfs_data_write(device, super, to, cas_copy_scratch)) {
        adytumfs_free_run(device, super, to, 1);
        return -1;
    }
    // The entry is repointed before the old block goes back, so a failure
    // here leaks a block rather than leaving a live mapping aimed at one the
    // allocator has already handed to somebody else.
    if (adytumfs_index_repoint(device, super, &store->index, hash, to)) {
        adytumfs_free_run(device, super, to, 1);
        return -1;
    }
    cas_drop(store, hash);
    if (adytumfs_free_run(device, super, from, 1)) return -1;
    *block = to;
    return 0;
}
