#ifndef ADYTUMFS_INDEX_H
#define ADYTUMFS_INDEX_H

#include "types.h"
#include "object.h"
#include "adytumfs_format.h"

#define ADYTUMFS_INDEX_SUPER_MAGIC 0x49445853u
#define ADYTUMFS_INDEX_MAGIC 0x49445831u
#define ADYTUMFS_INDEX_VERSION 1u
#define ADYTUMFS_INDEX_HASH_SIZE ADYTUMFS_HASH_SIZE
#define ADYTUMFS_INDEX_HEADER_SIZE 16u
// Where each block keeps its own crc32c. Entry blocks carry magic and their
// position in the first two words, the superblock carries magic, version,
// capacity, and the live count, so the two offsets differ.
#define ADYTUMFS_INDEX_CRC_ENTRY 8u
#define ADYTUMFS_INDEX_CRC_SUPER 24u
#define ADYTUMFS_INDEX_ENTRY_SIZE (ADYTUMFS_INDEX_HASH_SIZE + 16u)
#define ADYTUMFS_INDEX_PER_BLOCK \
    ((ADYTUMFS_BLOCK_SIZE - ADYTUMFS_INDEX_HEADER_SIZE) / \
     ADYTUMFS_INDEX_ENTRY_SIZE)

// On disk location index: content hash to physical block, with the reference
// count the tree's collection walk needs.
//
// The in memory table this replaces was the ceiling on the whole filesystem,
// because a table that has to fit in RAM caps the volume at its own size.
// Here the mapping lives in a run of data blocks and grows with the volume.
//
// This is the one structure that is deliberately not content addressed. It has
// to be readable before anything else is, because the tree resolves a child by
// the hash its parent promised and only this knows where that hash lives, so a
// content addressed index would need an index to read. It is addressed the
// ordinary way, by position, and the mount records its first block.
//
// The ordering that follows is the reason it is safe to keep this out of the
// atomic commit. An entry exists before the tree root that names it is
// committed, because copy on write writes children before parents. So an
// interrupted commit can leave entries nothing reaches, which is garbage to
// collect, but never a root that names a block this cannot find.
enum {
    ADYTUMFS_INDEX_EMPTY = 0u,
    ADYTUMFS_INDEX_LIVE = 1u,
    ADYTUMFS_INDEX_DEAD = 2u
};

struct adytumfs_index {
    u64 start;
    u64 blocks;
    u64 capacity;
};

// Describe an index over a run of blocks. The first block holds the header and
// the rest hold entries, so capacity is what is left over.
void adytumfs_index_init(struct adytumfs_index *index, u64 start, u64 blocks);

// Wipe the run and write an empty header.
int adytumfs_index_format(struct kernel_object *device,
                          const struct adytumfs_index *index);

// How many mappings are live, read from the header rather than counted by
// walking, because the walk is the thing this exists to avoid.
int adytumfs_index_live(struct kernel_object *device,
                        const struct adytumfs_index *index, u64 *live);

int adytumfs_index_lookup(struct kernel_object *device,
                          const struct adytumfs_index *index,
                          const u8 hash[ADYTUMFS_INDEX_HASH_SIZE],
                          u64 *block);

// Both halves of an entry in one probe. The cache in front of this asks for
// the location and the reference count together, and two lookups would walk
// the same chain twice over the device.
int adytumfs_index_fetch(struct kernel_object *device,
                         const struct adytumfs_index *index,
                         const u8 hash[ADYTUMFS_INDEX_HASH_SIZE], u64 *block,
                         u32 *refs);

// Aim an existing mapping at a different block without disturbing its
// reference count. This is the whole reason the location lives apart from the
// content: moving a block is one entry here and no hash changes, so nothing
// that points at the content has to be rewritten.
int adytumfs_index_repoint(struct kernel_object *device,
                           const struct adytumfs_index *index,
                           const u8 hash[ADYTUMFS_INDEX_HASH_SIZE], u64 block);

int adytumfs_index_refs(struct kernel_object *device,
                        const struct adytumfs_index *index,
                        const u8 hash[ADYTUMFS_INDEX_HASH_SIZE], u32 *refs);

// Record where content lives, starting at zero references: the caller that
// links it takes the first one. Inserting a hash that is already there is
// refused rather than silently repointed, because two blocks claiming one
// content is exactly the disagreement this table is supposed to settle.
int adytumfs_index_insert(struct kernel_object *device,
                          const struct adytumfs_index *index,
                          const u8 hash[ADYTUMFS_INDEX_HASH_SIZE], u64 block);

int adytumfs_index_retain(struct kernel_object *device,
                          const struct adytumfs_index *index,
                          const u8 hash[ADYTUMFS_INDEX_HASH_SIZE]);

// Drop one reference. freed says whether the last one went and the block is
// now unclaimed, so the caller can hand it back to the allocator.
int adytumfs_index_release(struct kernel_object *device,
                           struct adytumfs_superblock *super,
                           const struct adytumfs_index *index,
                           const u8 hash[ADYTUMFS_INDEX_HASH_SIZE],
                           u64 *freed_block);

#endif
