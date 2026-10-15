#ifndef ADYTUMFS_CAS_H
#define ADYTUMFS_CAS_H

#include "types.h"
#include "object.h"
#include "adytumfs_format.h"
#include "adytumfs_index.h"

#define ADYTUMFS_CAS_HASH_SIZE ADYTUMFS_INDEX_HASH_SIZE
#define ADYTUMFS_CAS_SLOTS 256u

// In memory cache in front of the on disk index.
//
// This used to be the table itself, and that made it the ceiling on the whole
// filesystem: a mapping that did not fit in the array did not exist, so the
// volume was capped at the size of the array. The authority is now
// adytumfs_index. This holds what is being used, and a miss costs a read of
// the index instead of a refusal.
//
// The cache is direct mapped, one entry per bucket, and deliberately not open
// addressed. Open addressing and eviction fight each other, because dropping
// an entry from the middle of a probe chain orphans everything behind it, and
// there is no reason to fight here: correctness never depends on the cache, so
// a bucket is simply overwritten and the index answers the next question.
//
// Writes go through. Every mutation reaches the index before this is touched,
// so losing the whole cache at any moment costs reads and nothing else.
enum {
    ADYTUMFS_CAS_EMPTY = 0u,
    ADYTUMFS_CAS_LIVE = 1u
};

struct adytumfs_cas_entry {
    u8 hash[ADYTUMFS_CAS_HASH_SIZE];
    u64 block;
    u32 refs;
    u32 live;
};

struct adytumfs_cas {
    struct adytumfs_index index;
    struct adytumfs_cas_entry entries[ADYTUMFS_CAS_SLOTS];
};

// Bind a cache to an index run and drop whatever it was holding. The index has
// to be formatted already; this never touches the device.
void adytumfs_cas_open(struct adytumfs_cas *store, u64 start, u64 blocks);

// How many mappings exist, which belongs to the index and not to whatever
// happens to be cached.
int adytumfs_cas_count(struct kernel_object *device,
                       const struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u64 *count);

int adytumfs_cas_lookup(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block);

int adytumfs_cas_refs(struct kernel_object *device,
                      const struct adytumfs_superblock *super,
                      struct adytumfs_cas *store,
                      const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u32 *refs);

// Give this content a block without taking a reference on it, allocating only
// the first time. The reference is taken by whoever links the content, so a
// node's count stays equal to the number of things that reach it.
int adytumfs_cas_place(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block);

// Place and hold. This is what a snapshot does to a root: the content stays
// where it is and simply gains a reason not to be collected.
int adytumfs_cas_acquire(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block);

int adytumfs_cas_retain(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        const u8 hash[ADYTUMFS_CAS_HASH_SIZE]);

// Drop one reference. The block goes back to the allocator when the last one
// goes, which is the only moment anything is actually reclaimed.
int adytumfs_cas_release(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 hash[ADYTUMFS_CAS_HASH_SIZE]);

// Move the content to a fresh block and repoint the index at it. The hash is
// an input and an invariant here: nothing that identifies the content is
// rewritten, which is the property the whole tree depends on.
int adytumfs_cas_relocate(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store,
                          const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block);

// Resolve a hash and read the block it names, checking the bytes against that
// hash on the way in. The parent promised the hash and nothing else covers the
// block once the checksum region is gone, so the check lives here rather than
// at each reader, where one could route around it by accident.
int adytumfs_cas_read(struct kernel_object *device,
                      const struct adytumfs_superblock *super,
                      struct adytumfs_cas *store,
                      const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u8 *buffer);

// Check bytes already in memory against the hash that named them. The page
// cache transfers straight into the page it faulted, so it cannot go through
// the read that carries this check with it.
int adytumfs_cas_verify(const u8 hash[ADYTUMFS_CAS_HASH_SIZE],
                        const u8 *buffer);

#endif
