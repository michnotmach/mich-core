#ifndef ADYTUMFS_FORMAT_H
#define ADYTUMFS_FORMAT_H

#include "types.h"

// The content store an inode's extent tree resolves through. Declared here
// rather than included because the store is built on top of this header.
struct adytumfs_cas;

// AdytumFS on-disk integers are little-endian and are read and written only
// through these helpers, so the big-endian s390x port reads images correctly.
// See mich-notes/adytumfs-format.md for the full layout.

static inline u16 adytumfs_read_le16(const u8 *p) {
    return (u16)((u16)p[0] | ((u16)p[1] << 8));
}

static inline u32 adytumfs_read_le32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static inline u64 adytumfs_read_le64(const u8 *p) {
    return (u64)adytumfs_read_le32(p) | ((u64)adytumfs_read_le32(p + 4) << 32);
}

static inline void adytumfs_write_le16(u8 *p, u16 value) {
    p[0] = (u8)value;
    p[1] = (u8)(value >> 8);
}

static inline void adytumfs_write_le32(u8 *p, u32 value) {
    p[0] = (u8)value;
    p[1] = (u8)(value >> 8);
    p[2] = (u8)(value >> 16);
    p[3] = (u8)(value >> 24);
}

static inline void adytumfs_write_le64(u8 *p, u64 value) {
    adytumfs_write_le32(p, (u32)value);
    adytumfs_write_le32(p + 4, (u32)(value >> 32));
}

#define ADYTUMFS_BLOCK_SIZE 4096u
#define ADYTUMFS_SECTORS_PER_BLOCK 8u
#define ADYTUMFS_INODE_SIZE 256u
#define ADYTUMFS_INODES_PER_BLOCK 16u
#define ADYTUMFS_NAME_MAX 255u
// One hash space for the whole format: tree nodes, index entries and the
// extent root an inode names are all BLAKE2b-512 over a block, so a node and
// a block of file data can never be told apart by their hash alone and the
// index needs no type field.
#define ADYTUMFS_HASH_SIZE 64u
#define ADYTUMFS_FORMAT_VERSION 3u
#define ADYTUMFS_ROOT_INODE 1u
// v1 bounds the inode table at sixteen blocks (256 inodes at sixteen per
// block); the formatter caps at the same value, so a bigger table is a volume
// this format never wrote.
#define ADYTUMFS_INODE_TABLE_BLOCKS_MAX 16u
// One u32 crc32c per data block lives in the checksum region, so a 4 KiB
// region block covers 1024 data blocks.
#define ADYTUMFS_CHECKSUMS_PER_BLOCK (ADYTUMFS_BLOCK_SIZE / 4u)
// The whole layout is one incompatible package, and an exact mask match is
// required, so a volume carrying bits this build never wrote is refused rather
// than half interpreted. V2 is the data checksum region plus the shadow
// metadata tail. V3 adds the on disk location index the content addressed tree
// resolves through, and nothing reads a v2 volume: there is no migration path,
// so a v2 mask is simply a volume this build formats over.
#define ADYTUMFS_FEATURE_INCOMPAT_V2 0x1u
#define ADYTUMFS_FEATURE_INCOMPAT_V3 0x3u

// The superblock lives in block 0 (a backup copy in the last block). Its
// checksum is the last field and covers every byte before it, so it never has
// to hash itself.
#define ADYTUMFS_SIGNATURE "AdytumFS"
#define ADYTUMFS_SIGNATURE_SIZE 8u
#define ADYTUMFS_SUPER_CHECKSUM_OFFSET 4092u

// v2 volume layout. The prefix grows as in v1: superblock, block bitmap,
// inode table, then the data region. The tail grows backwards from the last
// block: the shadow superblock, the shadow bitmap, the shadow inode table,
// then the data checksum region, which ends exactly where the data region
// ends. Every block from the region start to the end of the volume is
// metadata: the allocator hands out nothing at or past data_checksum_region.
//
// The shadow tail is a full second copy of the metadata (superblock, bitmap,
// inode table) that the commit protocol writes while the active copy stays
// untouched: a window stages its bitmap and table edits in memory, the commit
// lands them in the inactive set, and the inactive superblock, written last
// with generation plus one, names the set the next mount reads. A crash can
// therefore leave either the old generation or the new one on the device, but
// never a mix of both under one superblock.
struct adytumfs_superblock {
    u32 format_version;
    u32 block_size;
    u64 total_blocks;
    u64 block_bitmap_start;
    u64 block_bitmap_blocks;
    u64 inode_table_start;
    u64 inode_table_blocks;
    u64 inode_count;
    u64 root_inode;
    u64 data_start;
    u64 free_blocks;
    u64 free_inodes;
    u64 generation;
    u64 feature_compat;
    u64 feature_incompat;
    u64 feature_ro_compat;
    u64 data_checksum_region;
    // Where the on disk location index lives. It is reserved at format time and
    // never handed to the allocator, because the tree cannot be read without
    // it: a volume that lost these blocks lost every hash to location mapping
    // it had.
    u64 index_start;
    u64 index_blocks;
    // Which superblock slot this copy came from: 0 is block 0, 1 is the tail
    // copy in the last block. Runtime state only, never serialised; the
    // reader defaults it to the primary slot and the mount picker overrides
    // it when the tail copy wins on generation.
    u8 active_slot;
};

// Serialise a superblock into a 4 KiB block (little-endian, checksum computed).
void adytumfs_super_pack(u8 *block, const struct adytumfs_superblock *super);
// Parse a 4 KiB block: verifies signature, version, block size, and checksum.
int adytumfs_super_unpack(struct adytumfs_superblock *super, const u8 *block);
// Check that the region layout is internally consistent and fits device_blocks.
int adytumfs_super_valid(const struct adytumfs_superblock *super,
                         u64 device_blocks);

// Inode type bits, laid over the low permission bits inside mode (POSIX
// style). The symlink keeps its own bit rather than the POSIX S_IFLNK
// value, because that value shares a bit with S_IFREG and every existing
// mode test reads a single bit.
#define ADYTUMFS_MODE_DIR 0x4000u
#define ADYTUMFS_MODE_REG 0x8000u
#define ADYTUMFS_MODE_LNK 0x2000u
#define ADYTUMFS_INODE_CHECKSUM_OFFSET 252u

struct adytumfs_inode {
    u16 mode;
    u16 links;
    u32 uid;
    u32 gid;
    u32 flags;
    u64 size;
    u64 blocks;
    u64 atime;
    u64 mtime;
    u64 ctime;
    u64 generation;
    // Root of this file's extent tree. All zero is the empty tree, which is
    // what a fresh inode and a truncated to nothing file both hold, so no
    // separate "has extents" flag is needed. The root is a content hash and
    // not a block number, so writing a file never rewrites the inode to point
    // somewhere new until the root itself changes.
    u8 extent_root[ADYTUMFS_HASH_SIZE];
    // Nanoseconds inside the seconds fields above, kept where v2 had them so
    // the checksum offset does not move.
    u32 atime_nsec;
    u32 mtime_nsec;
    u32 ctime_nsec;
};

// Serialise an inode into its 256-byte table slot (little-endian, checksum set).
void adytumfs_inode_pack(u8 *slot, const struct adytumfs_inode *inode);
// Parse an inode slot. A free slot (mode 0) carries no checksum and always
// parses; an in-use inode with a bad checksum is rejected.
int adytumfs_inode_unpack(struct adytumfs_inode *inode, const u8 *slot);

struct kernel_object;

// Pick the newest structurally valid superblock of the generation pair and
// set its runtime slot. This reads without judging the tree: the mount adds
// the verify pass, and repair tooling may want to see a broken winner.
int adytumfs_super_read(struct kernel_object *device,
                        struct adytumfs_superblock *super);

// Land the open window: copy the staged bitmap and inode table blocks into
// the inactive metadata set, flush, then write the inactive superblock with
// generation plus one and flush again. The superblock write is the flip, so
// a crash before it leaves the old generation intact and a crash during it
// leaves a checksum-failed superblock the mount picker refuses. On failure
// the staging and the in-memory superblock stay untouched, so the commit can
// simply be retried. A window with nothing staged commits nothing.
int adytumfs_commit(struct kernel_object *device,
                    struct adytumfs_superblock *super);
// Drop the staged metadata for a device without landing it, the in-memory
// equivalent of a crash inside the window: the device keeps the last
// committed generation. The mount path calls this defensively before it reads,
// and crash-recovery tooling uses it to simulate a torn window.
void adytumfs_window_discard(struct kernel_object *device);

// Read or write one 4 KiB filesystem block (eight device sectors) by block
// number, through the block cache.
int adytumfs_block_read(struct kernel_object *device, u64 block, u8 *buffer);
int adytumfs_block_write(struct kernel_object *device, u64 block,
                         const u8 *buffer);
// Zero one 4 KiB block with direct device I/O, bypassing the cache, and drop
// any cached copy first. File data moves through direct page transfers, so a
// cached zero would be flushed over the real bytes later, and a reallocated
// block must not resurrect its previous owner's cached content either. The
// zero image is sealed into the checksum region, because a grown hole must
// read back as zeroes through the verified path too.
int adytumfs_block_zero(struct kernel_object *device,
                        const struct adytumfs_superblock *super, u64 block);
// Read or write one data block through its checksum region entry: a read
// hands back only bytes the region vouches for, and a write seals the new
// crc32c alongside the data. Metadata blocks (super, bitmap, table, and the
// region itself) go through the raw block calls above.
int adytumfs_data_read(struct kernel_object *device,
                       const struct adytumfs_superblock *super,
                       u64 block, u8 *buffer);
int adytumfs_data_write(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        u64 block, const u8 *buffer);
// Compare a data block's bytes against its region entry, or seal new bytes
// into it. The page-cache paths move file data with direct transfers into
// pages, so they verify and seal without a staging block.
int adytumfs_data_check(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        u64 block, const u8 *bytes);
int adytumfs_data_seal(struct kernel_object *device,
                       const struct adytumfs_superblock *super,
                       u64 block, const u8 *bytes);
// Format a device: lay out the regions and write the superblock (and its
// backup), the block bitmap, and an empty root directory.
int adytumfs_make(struct kernel_object *device);

// The device location of one bitmap or inode table block of the active
// metadata set, so callers never hardcode the primary prefix against a
// generation pair that may have flipped to the tail copy.
u64 adytumfs_superblock_block(const struct adytumfs_superblock *super);
u64 adytumfs_bitmap_block(const struct adytumfs_superblock *super, u32 index);
u64 adytumfs_table_block(const struct adytumfs_superblock *super, u32 index);
// Read one inode table block of the active metadata set, passing through the
// open window's staging, or stage one into the window. The device copy of a
// staged table block belongs to the committed generation until the commit
// replaces the whole set.
int adytumfs_table_read(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        u32 index, u8 *buffer);
int adytumfs_table_stage(struct kernel_object *device,
                         const struct adytumfs_superblock *super,
                         u32 index, const u8 *buffer);

// Allocate a contiguous run of length data blocks (first-fit) and return its
// start block, or free a previously allocated run. Data blocks live in
// [data_start, data_checksum_region); the metadata prefix and tail are never
// handed out. Bitmap edits stage in the open window: the committed generation
// on the device keeps every block the current window freed, so the allocator
// skips a block that reads free in the staging but allocated in the committed
// bitmap. super->free_blocks is kept up to date in memory and lands on the
// device at commit.
int adytumfs_alloc_run(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       u64 length, u64 *start);
int adytumfs_free_run(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      u64 start, u64 length);

// Read or write one inode by number from the inode table. Reads pass through
// the open window's staging first; writes read-modify-write the 4 KiB table
// block into the staging, so the committed table on the device is only ever
// replaced by the whole committed generation at commit time.
int adytumfs_inode_read(struct kernel_object *device,
                        const struct adytumfs_superblock *super,
                        u64 inode_num, struct adytumfs_inode *out);
int adytumfs_inode_write(struct kernel_object *device,
                         const struct adytumfs_superblock *super,
                         u64 inode_num, const struct adytumfs_inode *in);
// Allocate the first free inode slot, initialised with mode and link count 1 and
// a bumped generation, or free an inode. super->free_inodes is kept current.
int adytumfs_inode_alloc(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         u16 mode, u64 *inode_num);
int adytumfs_inode_free(struct kernel_object *device,
                        struct adytumfs_superblock *super, u64 inode_num);

// Mount time audit of the allocation state: every used inode's extents must
// stay inside the data region, no two extents may share a block, the bitmap
// must agree with the extents exactly, and the superblock counters must match
// what a full scan of the table and the bitmap finds. Returns 0 only when the
// three views of the volume agree.
// The hash of the block of zeroes every hole names. One block serves every
// hole on the volume, so a sparse file costs nothing per hole and a read of
// one resolves through the tree like any other mapping.
int adytumfs_zero_hash(u8 hash[ADYTUMFS_HASH_SIZE]);

int adytumfs_verify(struct kernel_object *device,
                    struct adytumfs_superblock *super);

// Map a logical file block to its physical block. The inode names the root of
// its extent tree, the tree resolves the block to a content hash, and the
// store resolves the hash to a block number, so no physical address is ever
// recorded in the inode.
int adytumfs_inode_map(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store,
                       const struct adytumfs_inode *inode, u64 logical_block,
                       u64 *physical_block);
// Replace one block of a file. The new content lands in a block of its own, is
// hashed, and is inserted into the tree; whatever the entry named before loses
// the tree's reference and returns to the pool when nothing else names it. The
// old root stays valid until the new one reaches the inode, so a later boot
// reads either the old tree or the new one and never a mix. That is the whole
// of the atomicity argument, which is why the two-phase redirect this replaces
// is gone.
int adytumfs_inode_remap(struct kernel_object *device,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store,
                         struct adytumfs_inode *inode, u64 inode_num,
                         u64 logical, const u8 *content);
// Grow the file to new_blocks mapped blocks, or truncate it down. Every new
// block gets the sealed zero content, so a hole costs one shared block for the
// whole file rather than one per block, and a read of a hole needs no special
// case.
int adytumfs_inode_grow(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store,
                        struct adytumfs_inode *inode, u64 inode_num,
                        u64 new_blocks);
int adytumfs_inode_truncate(struct kernel_object *device,
                            struct adytumfs_superblock *super,
                            struct adytumfs_cas *store,
                            struct adytumfs_inode *inode, u64 inode_num,
                            u64 new_blocks);

// Directory entries live in the directory's data blocks: an 8-byte target inode,
// a 2-byte record length, a 1-byte name length, a 1-byte type, then the name.
// inode 0 marks a free record. Records never cross a 4 KiB block boundary.
#define ADYTUMFS_DIR_HEADER 12u
#define ADYTUMFS_DTYPE_REG 1u
#define ADYTUMFS_DTYPE_DIR 2u
#define ADYTUMFS_DTYPE_LNK 3u

int adytumfs_dir_lookup(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 dir_inode,
                        const char *name, u32 name_len, u64 *out_inode);
int adytumfs_dir_add(struct kernel_object *device,
                     struct adytumfs_superblock *super,
                     struct adytumfs_cas *store, u64 dir_inode,
                     const char *name, u32 name_len, u64 target_inode, u8 type);
int adytumfs_dir_remove(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 dir_inode,
                        const char *name, u32 name_len);
// Iterate directory entries: start with *cursor = 0, get one used entry per call
// (name needs an ADYTUMFS_NAME_MAX + 1 buffer, it comes back NUL-terminated)
// plus its length, inode, and type, and an advanced cursor; returns 0 for an
// entry, 1 at the end, -1 on error.
int adytumfs_dir_iter(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store, u64 dir_inode,
                      u64 *cursor, char *name, u32 *name_len, u64 *inode_out,
                      u8 *type_out);

// Read or write a byte range of a regular file through its extents. A write past
// the current end grows the file (allocating blocks); size is updated. Returns 0
// with the transferred count, or -1 on error.
int adytumfs_file_read(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u64 inode_num,
                       u64 offset, void *buffer, u64 length, u64 *out_read);
int adytumfs_file_write(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 inode_num,
                        u64 offset, const void *buffer, u64 length,
                        u64 *out_written);

// Resolve an absolute path to its inode by walking directory entries from the
// root. Create a named child (a fresh inode plus a directory entry) under a
// parent directory, or unlink a regular file (reclaiming its data).
int adytumfs_path_resolve(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store, const char *path,
                          u64 *out_inode);
int adytumfs_create_at(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u64 parent_inode,
                       const char *name, u32 name_len, u16 mode,
                       u64 *out_inode);
int adytumfs_unlink_at(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u64 parent_inode,
                       const char *name, u32 name_len);

#endif
