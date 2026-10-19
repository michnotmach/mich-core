#ifndef ADYTUMFS_ITEM_H
#define ADYTUMFS_ITEM_H

#include "types.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"

#define ADYTUMFS_ITEM_MAGIC 0x54524535u
#define ADYTUMFS_ITEM_VERSION 1u
#define ADYTUMFS_ITEM_HEADER_SIZE 24u
#define ADYTUMFS_ITEM_KEY_SIZE 24u
#define ADYTUMFS_ITEM_CHILD_SIZE ADYTUMFS_CAS_HASH_SIZE
// A leaf slot names a run of bytes in the node's own data area, a branch slot
// names a child by content hash. The payloads differ, so the capacities do.
#define ADYTUMFS_ITEM_LEAF_SLOT_SIZE (ADYTUMFS_ITEM_KEY_SIZE + 8u)
#define ADYTUMFS_ITEM_BRANCH_SLOT_SIZE \
    (ADYTUMFS_ITEM_KEY_SIZE + ADYTUMFS_ITEM_CHILD_SIZE)
#define ADYTUMFS_ITEM_LEAF_SLOT_MAX \
    ((ADYTUMFS_BLOCK_SIZE - ADYTUMFS_ITEM_HEADER_SIZE) / \
     ADYTUMFS_ITEM_LEAF_SLOT_SIZE)
#define ADYTUMFS_ITEM_BRANCH_SLOT_MAX \
    ((ADYTUMFS_BLOCK_SIZE - ADYTUMFS_ITEM_HEADER_SIZE) / \
     ADYTUMFS_ITEM_BRANCH_SLOT_SIZE)
#define ADYTUMFS_ITEM_DEPTH_MAX 12u

#define ADYTUMFS_ITEM_INODE 1u
#define ADYTUMFS_ITEM_DIR 2u

// One B+tree holds every metadata item in the volume, replacing the fixed
// inode table. The key is composite so that different kinds of item share a
// tree and stay ordered among themselves: an inode, its extents and the
// entries of a directory are neighbours in one ordering rather than three
// structures that have to agree. The type field is what makes that possible,
// so it is in the key from the start; adding it later would mean breaking the
// on-disk format again.
//
// Sort order is objectid, then type, then offset. Objectid first groups every
// item belonging to one file together, which is the access pattern both an
// inode fetch and a directory walk want. Type second keeps an inode item
// ahead of the items describing it. Offset last orders extents by file
// position, which is the order a sequential read asks for.
//
// Items are variable size and leaves are slotted pages: slot descriptors grow
// up from the header, item bytes grow down from the end of the block, and the
// node is full when they meet. A fixed record size would waste most of a
// 256-byte inode slot on a file that needs none of it.
//
// A node carries no hash of its own. The hash covers the whole packed node and
// is stored by the parent, so reading a child through the location table
// verifies it by construction and a node that reads back different from what
// its parent promised is caught without a second checksum to consult. The root
// has no parent, so the superblock holds its hash in its place.
struct adytumfs_item_key {
    u64 objectid;
    u64 offset;
    u32 type;
    u32 spare;
};

// Pack and unpack one node. Packing is the only writer of the on-disk shape,
// so the layout lives here instead of being open coded at each call site.
int adytumfs_item_leaf_pack(u8 *block, u32 count,
                            const struct adytumfs_item_key *keys,
                            const u8 *const *data, const u32 *sizes);
// The level is a parameter rather than a constant because the tree has to grow
// past two levels: a branch over branches is level two, and a format that can
// only say level one caps every tree at one branchful of leaves.
int adytumfs_item_branch_pack(u8 *block, u32 level, u32 count,
                              const struct adytumfs_item_key *keys,
                              const u8 (*children)[ADYTUMFS_ITEM_CHILD_SIZE]);

// Read one slot back out of an already validated node. Leaf slots yield a
// pointer into the block, so the caller must not write through it.
int adytumfs_item_leaf_get(const u8 *block, u32 index,
                           struct adytumfs_item_key *key, const u8 **data,
                           u32 *size);
int adytumfs_item_branch_get(const u8 *block, u32 index,
                             struct adytumfs_item_key *key,
                             u8 child[ADYTUMFS_ITEM_CHILD_SIZE]);
int adytumfs_item_node_count(const u8 *block, u32 *count);

// The hash a parent stores for this child. It covers the whole packed node, so
// any change to any slot or any item byte changes it.
int adytumfs_item_node_hash(const u8 *block,
                            u8 hash[ADYTUMFS_ITEM_CHILD_SIZE]);

// Validate a node read back from the device: magic, version, level, count
// against the level's capacity, slot and data bounds, ordering, and the hash.
// A node that fails any of these is not one this filesystem wrote.
int adytumfs_item_node_check(const u8 *block, u32 level);

// The first slot whose key is not below key, or -1 when key sorts above every
// slot. In a branch that index is the child to descend into, because slot i
// carries the greatest key in child i. In a leaf it is the slot that holds the
// item, when one does.
int adytumfs_item_node_search(const u8 *block,
                              const struct adytumfs_item_key *key);

// Traversal lives here rather than in the caller because the descent has to
// verify each node against the hash its parent promised, and doing that once
// is the difference between a self checking tree and one that trusts the disk.
//
// A zero root is an empty tree, so a fresh volume needs no special case.
int adytumfs_item_root_empty(const u8 root[ADYTUMFS_ITEM_CHILD_SIZE]);

// Insert or replace, copy on write. Only the nodes on the path to the key are
// rewritten, and the caller gets the new root back because the old one may
// still be committed and in use. A node names its children by hash, so the
// rewrite above a changed child is what moves the change up to the root.
int adytumfs_item_insert(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                         const struct adytumfs_item_key *key, const u8 *data,
                         u32 size,
                         u8 new_root[ADYTUMFS_ITEM_CHILD_SIZE]);

// Remove one key, copy on write, and hand back the new root the same way an
// insert does. A key that is not there is an error rather than a no-op, so a
// caller asking for one named item hears when it is absent.
//
// Nothing merges on the way back up. A leaf keeps whatever items it is left
// with, so removing from a full tree spends space it does not give back, which
// is the trade the format accepts to keep a removal to one pass down and back.
// Removing every item leaves the zero root, and no empty node is ever stored.
int adytumfs_item_remove(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                         const struct adytumfs_item_key *key,
                         u8 new_root[ADYTUMFS_ITEM_CHILD_SIZE]);

int adytumfs_item_lookup(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                         const struct adytumfs_item_key *key, u8 *buffer,
                         u32 buffer_size, u32 *size);

// Drop a root the caller is finished with and everything only it reached.
// Insert is copy on write, so superseding a root leaves the old one whole, and
// nothing reclaims it until this runs. A node still named by another root keeps
// its block and its subtree, which is what lets two committed roots coexist.
//
// Releasing the root's own entry directly instead frees one block and quietly
// abandons the rest: the children it named stay allocated with nobody able to
// reach them, and the children it shared with the new root stay held once too
// often, so even this walk cannot finish reclaiming the survivor afterwards.
int adytumfs_item_drop(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_ITEM_CHILD_SIZE]);

// Walk every item in the tree in key order. The callback returns 0 to carry
// on and anything else to stop, and that value is what the walk returns. A
// rebuild needs the whole tree and so does an audit, and neither wants a
// second traversal implementation.
int adytumfs_item_walk(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const u8 root[ADYTUMFS_ITEM_CHILD_SIZE],
                       int (*visit)(const struct adytumfs_item_key *key,
                                    const u8 *data, u32 size, void *context),
                       void *context);

#endif
