#ifndef ADYTUMFS_TREE_H
#define ADYTUMFS_TREE_H

#include "types.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"

#define ADYTUMFS_TREE_MAGIC 0x54524533u
#define ADYTUMFS_TREE_HEADER_SIZE 16u
#define ADYTUMFS_TREE_KEY_SIZE 16u
#define ADYTUMFS_TREE_CHILD_SIZE ADYTUMFS_CAS_HASH_SIZE
#define ADYTUMFS_TREE_VALUE_SIZE (ADYTUMFS_CAS_HASH_SIZE + 8u)
#define ADYTUMFS_TREE_LEAF_ENTRY_SIZE \
    (ADYTUMFS_TREE_KEY_SIZE + ADYTUMFS_TREE_VALUE_SIZE)
#define ADYTUMFS_TREE_BRANCH_ENTRY_SIZE \
    (ADYTUMFS_TREE_KEY_SIZE + ADYTUMFS_TREE_CHILD_SIZE)
#define ADYTUMFS_TREE_LEAF_MAX \
    ((ADYTUMFS_BLOCK_SIZE - ADYTUMFS_TREE_HEADER_SIZE) / \
     ADYTUMFS_TREE_LEAF_ENTRY_SIZE)
#define ADYTUMFS_TREE_BRANCH_MAX \
    ((ADYTUMFS_BLOCK_SIZE - ADYTUMFS_TREE_HEADER_SIZE) / \
     ADYTUMFS_TREE_BRANCH_ENTRY_SIZE)

// One CoW B-tree replaces the v2 inode table, the indirect fields and the
// directory blocks. The key is (object, offset), so inodes are allocated
// dynamically with no ceiling set at format time and a file reaches 2^64
// without separate indirect levels.
//
// Nothing in a node holds a physical block number. A branch entry names its
// child by content hash and the location table resolves that hash to a block,
// which is what lets a block move without rewriting the tree above it. It also
// makes the tree self verifying: the parent promised the hash, so a child that
// reads back different is corrupt, with no separate checksum region to consult.
//
// The value carries a content hash rather than a block for the same reason.
// Length is how many consecutive file blocks the entry covers, so a run of
// identical blocks, in practice a run of zeroes, costs one entry.
struct adytumfs_tree_key {
    u64 object_id;
    u64 offset;
};

struct adytumfs_tree_value {
    u8 hash[ADYTUMFS_CAS_HASH_SIZE];
    u32 length;
    u32 flags;
};

// Pack and unpack one node. Packing is the only writer of the on-disk shape,
// so the layout lives in one place instead of being open coded at each site.
int adytumfs_tree_leaf_pack(u8 *block, u32 count,
                            const struct adytumfs_tree_key *keys,
                            const struct adytumfs_tree_value *values);
int adytumfs_tree_leaf_unpack(const u8 *block, u32 *count,
                              struct adytumfs_tree_key *keys,
                              struct adytumfs_tree_value *values);
int adytumfs_tree_branch_pack(u8 *block, u32 count,
                              const struct adytumfs_tree_key *keys,
                              const u8 (*children)[ADYTUMFS_CAS_HASH_SIZE]);
int adytumfs_tree_branch_unpack(const u8 *block, u32 *count,
                                struct adytumfs_tree_key *keys,
                                u8 (*children)[ADYTUMFS_CAS_HASH_SIZE]);

// The hash a parent stores for this child. It covers the whole packed node, so
// any change to any entry changes it.
int adytumfs_tree_node_hash(const u8 *block, u8 hash[ADYTUMFS_CAS_HASH_SIZE]);

// Validate a node read back from the device: magic, level, count against the
// level's capacity, and strictly increasing keys. A node that fails any of
// these is not a node this filesystem wrote.
int adytumfs_tree_node_check(const u8 *block, u32 level);

// The first entry whose key is not below key, or -1 when key sorts above every
// entry. In a branch that index is the child to descend into, because entry i
// carries the greatest key in child i, so the first separator at or above the
// query is the subtree that can hold it. In a leaf it is the entry that holds
// the offset, when one does.
int adytumfs_tree_node_search(const u8 *block,
                              const struct adytumfs_tree_key *key);

// Split a full node in half and report the greatest key of the left half,
// which the parent inserts as the separator for that half. The separator the
// parent already holds stays as the right half's, so a split never rewrites an
// existing entry. Both halves are valid nodes on their own.
int adytumfs_tree_leaf_split(const u8 *full, u8 *left, u8 *right,
                             struct adytumfs_tree_key *split_key);
int adytumfs_tree_branch_split(const u8 *full, u8 *left, u8 *right,
                               struct adytumfs_tree_key *split_key);

// Traversal lives here rather than in the caller because the descent has to
// verify each node against the hash its parent promised, and doing that once
// is the difference between a self checking tree and one that trusts the disk.
//
// A zero root is an empty tree, so inserting into a fresh volume needs no
// special case and node_check stays strict about count.
#define ADYTUMFS_TREE_DEPTH_MAX 12u

int adytumfs_tree_root_empty(const u8 root[ADYTUMFS_CAS_HASH_SIZE]);

int adytumfs_tree_lookup(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                         const struct adytumfs_tree_key *key,
                         struct adytumfs_tree_value *value);

// Insert or replace, copy on write. Only the nodes on the path to the key are
// rewritten, every other subtree keeps its hash and therefore its block, and
// the result is a new root hash. The caller commits by recording that hash,
// which is atomic in the only sense that matters here: the old root still
// names a complete, valid tree, so a reader that started before the commit
// finishes against the tree as it was.
int adytumfs_tree_insert(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                         const struct adytumfs_tree_key *key,
                         const struct adytumfs_tree_value *value,
                         u8 new_root[ADYTUMFS_CAS_HASH_SIZE]);

// Remove one key, copy on write, and hand back the new root the same way
// insert does. Removing a key that is not there fails rather than succeeding
// quietly. Removing the last key leaves the zero root that means empty.
int adytumfs_tree_remove(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                         const struct adytumfs_tree_key *key,
                         u8 new_root[ADYTUMFS_CAS_HASH_SIZE]);

// Drop every version that this root is the only reason to keep, which is what
// makes a commit collect its own garbage instead of leaking a node per write.
// budget caps the nodes one call touches, so dropping a large subtree cannot
// stall a machine that is serving requests; remaining says what is left and
// adytumfs_tree_discard_resume finishes the walk. A root held by a snapshot
// simply has more than one reference, and then nothing below it dies.
int adytumfs_tree_discard(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store,
                          const u8 root[ADYTUMFS_CAS_HASH_SIZE],
                          u32 budget, u32 *remaining);
int adytumfs_tree_discard_resume(struct kernel_object *device,
                                 struct adytumfs_superblock *super,
                                 struct adytumfs_cas *store,
                                 u32 budget, u32 *remaining);

#endif
