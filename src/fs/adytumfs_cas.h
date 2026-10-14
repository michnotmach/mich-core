#ifndef ADYTUMFS_CAS_H
#define ADYTUMFS_CAS_H

#include "types.h"
#include "object.h"
#include "adytumfs_format.h"

#define ADYTUMFS_CAS_HASH_SIZE 64u
#define ADYTUMFS_CAS_SLOTS 256u

// Content addressed block location, the piece of AdytumFS v3 that can be built
// and checked before the format changes.
//
// The point is the split between what a block contains and where it lives. A
// v2 extent carries a physical block number, so the integrity of the tree is
// tied to the layout on disk, and moving a block means rewriting every pointer
// that reaches it. ZFS has exactly this problem and calls it BP rewrite. Here
// the caller holds the content hash and this table holds the location, so
// relocation touches one entry and no hash changes.
//
// Deduplication falls out of the same split: identical content hashes to the
// same key and shares one physical block, counted by refs.
//
// The table is in memory and rebuildable by scanning the volume, because the
// v2 format carries no hashes to persist it into. It is the dedup working set,
// not a cap on the volume: a full table refuses a new entry rather than
// silently dropping the sharing it is supposed to provide.
enum {
    ADYTUMFS_CAS_EMPTY = 0u,
    ADYTUMFS_CAS_LIVE = 1u,
    ADYTUMFS_CAS_DEAD = 2u
};

struct adytumfs_cas_entry {
    u8 hash[ADYTUMFS_CAS_HASH_SIZE];
    u64 block;
    u32 refs;
    u32 live;
};

struct adytumfs_cas {
    struct adytumfs_cas_entry entries[ADYTUMFS_CAS_SLOTS];
    u32 count;
};

void adytumfs_cas_reset(struct adytumfs_cas *store);
u32 adytumfs_cas_count(const struct adytumfs_cas *store);
int adytumfs_cas_lookup(const struct adytumfs_cas *store,
                        const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block);

// Report how many references this content has. A discard walk has to know
// whether the reference it is about to drop is the last one, because only a
// node that actually dies takes its children down with it.
int adytumfs_cas_refs(const struct adytumfs_cas *store,
                      const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u32 *refs);

// Return the block holding this content, allocating one only the first time.
// A repeat acquire of the same hash costs no block from the allocator.
int adytumfs_cas_acquire(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block);

// Give this content a block without taking a reference on it. The tree writes
// a node through this and the reference is taken by the parent that links it,
// which keeps a node's count equal to the number of parents that reach it and
// nothing else. acquire counts the caller as a holder, which is right for a
// caller that means to keep the content itself and wrong for a node that is
// only ever reached through its parent.
int adytumfs_cas_place(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block);

// Take a reference on content that is already there, and fail if it is not.
// This is not acquire: a parent linking a child must never be the thing that
// allocates the child's block, because then a stale pointer would silently
// register an empty block under a hash that promises content.
int adytumfs_cas_retain(struct adytumfs_cas *store,
                        const u8 hash[ADYTUMFS_CAS_HASH_SIZE]);

// Drop one reference and free the block when the last one goes.
int adytumfs_cas_release(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 hash[ADYTUMFS_CAS_HASH_SIZE]);

// Move the content to a fresh block and repoint the table at it. The hash is
// an input and an invariant here: nothing that identifies the content is
// rewritten, which is the property the v3 tree depends on.
int adytumfs_cas_relocate(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store,
                          const u8 hash[ADYTUMFS_CAS_HASH_SIZE], u64 *block);

#endif
