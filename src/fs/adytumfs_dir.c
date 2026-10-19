#include "adytumfs_format.h"
#include "adytumfs_item.h"
#include "adytumfs_tree.h"
#include "blake2b.h"
#include "rtc64.h"

// One staging block for directory data; the single-CPU filesystem reads,
// modifies, and writes it in place.
static u8 adytumfs_dir_scratch[ADYTUMFS_BLOCK_SIZE];

// Inserting or removing an entry is a metadata change to the directory
// itself, so every path that lands an edit stamps the parent's mtime and
// ctime right before the remap or write that persists the inode.
static void adytumfs_dir_touch(struct adytumfs_inode *dir) {
    u64 now = rtc64_wall_clock();
    dir->mtime = now;
    dir->ctime = now;
}

static int adytumfs_name_equal(const u8 *stored, const char *name, u32 length) {
    for (u32 index = 0; index < length; index++)
        if (stored[index] != (u8)name[index]) return 0;
    return 1;
}

// Directory entries are items in the item tree, keyed by the directory and
// the hash of the name.
//
// The key is fixed width, so two names that hash alike cannot be two keys:
// one item holds every entry in the directory whose names hash alike, and a
// lookup is a search for the bucket followed by a comparison inside it. With a
// 64 bit hash a bucket holding two is rarer than a disk that silently loses a
// block, so the comparison is the price of being correct rather than a second
// lookup path that has to be kept in step with the first.
//
// A bucket is capped because the tree cannot split one item: an item larger
// than an empty leaf's data budget has nowhere to go. Eight entries of the
// longest name a directory accepts stay well inside that budget, and the cap
// turns a corruption that would otherwise fail deep in the packer into a
// refusal here.
#define ADYTUMFS_DIRENT_HEADER 12u
#define ADYTUMFS_DIRENT_MAX (ADYTUMFS_DIRENT_HEADER + ADYTUMFS_NAME_MAX)
#define ADYTUMFS_DIR_BUCKET_MAX 8u
#define ADYTUMFS_DIR_BUCKET_SIZE (ADYTUMFS_DIR_BUCKET_MAX * ADYTUMFS_DIRENT_MAX)

// The hash a name is keyed under. BLAKE2b with a 64 bit output rather than a
// truncation of the 512 bit digest, because the output length is part of the
// parameter block: asking for eight bytes is one pass over a shorter digest
// rather than eight passes over a longer one.
int adytumfs_dir_name_hash(const char *name, u32 name_len, u64 *hash) {
    if (!name || !hash || !name_len || name_len > ADYTUMFS_NAME_MAX) return -1;
    u8 digest[8];
    if (blake2b(digest, 8, name, name_len)) return -1;
    *hash = adytumfs_read_le64(digest);
    return 0;
}

// Pack one entry. The length prefixes the name, so a bucket is a list that
// describes itself and needs no count that could disagree with it.
int adytumfs_dirent_pack(u8 *out, u32 out_size, u64 inode, u8 type,
                         const char *name, u32 name_len) {
    if (!out || !name || !inode) return -1;
    if (!name_len || name_len > ADYTUMFS_NAME_MAX) return -1;
    if (out_size < ADYTUMFS_DIRENT_HEADER + name_len) return -1;
    adytumfs_write_le64(out, inode);
    adytumfs_write_le16(out + 8, (u16)name_len);
    out[10] = type;
    out[11] = 0;
    for (u32 index = 0; index < name_len; index++)
        out[ADYTUMFS_DIRENT_HEADER + index] = (u8)name[index];
    return 0;
}

// Read the header of the entry at a known offset. The name follows it and is
// name_len bytes long and not terminated, because the caller already has a
// buffer and a length, and copying would add a second bound to get wrong.
int adytumfs_dirent_read(const u8 *data, u32 size, u32 at, u64 *inode,
                         u8 *type, u32 *name_len) {
    if (!data || !inode || !type || !name_len) return -1;
    if (at + ADYTUMFS_DIRENT_HEADER > size) return -1;
    u32 length = adytumfs_read_le16(data + at + 8);
    if (!length || length > ADYTUMFS_NAME_MAX) return -1;
    if (at + ADYTUMFS_DIRENT_HEADER + length > size) return -1;
    *inode = adytumfs_read_le64(data + at);
    *type = data[at + 10];
    *name_len = length;
    return 0;
}

// Locate a name in a bucket. A bucket that does not hold it answers the same
// way an absent bucket does, which is what a hash collision looks like from
// outside: the key matched and the bytes did not.
int adytumfs_dirent_find(const u8 *data, u32 size, const char *name,
                         u32 name_len, u32 *at) {
    if (!data || !name || !at) return -1;
    if (!name_len || name_len > ADYTUMFS_NAME_MAX) return -1;
    u32 offset = 0;
    while (offset + ADYTUMFS_DIRENT_HEADER <= size) {
        u64 inode = 0;
        u8 type = 0;
        u32 length = 0;
        if (adytumfs_dirent_read(data, size, offset, &inode, &type, &length))
            return -1;
        if (length == name_len &&
            adytumfs_name_equal(data + offset + ADYTUMFS_DIRENT_HEADER, name,
                                length)) {
            *at = offset;
            return 0;
        }
        offset += ADYTUMFS_DIRENT_HEADER + length;
    }
    return -1;
}

static void dirent_key(struct adytumfs_item_key *key, u64 dir, u64 hash) {
    key->objectid = dir;
    key->offset = hash;
    key->type = ADYTUMFS_ITEM_DIR;
    key->spare = 0;
}

// Add one name to a directory, copy on write through the item tree. The entry
// joins the bucket its name hashes to, creating it when the directory has no
// entry by that hash yet.
//
// A name already in the bucket is refused rather than replaced. Whether a
// second name overwrites or fails is a question about the directory above, and
// answering it here would leave that layer unable to express either.
int adytumfs_dir_item_add(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store,
                          const u8 root[ADYTUMFS_ITEM_CHILD_SIZE], u64 dir,
                          const char *name, u32 name_len, u64 target, u8 type,
                          u8 new_root[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!device || !super || !store || !root || !name || !new_root) return -1;
    if (!dir || !target) return -1;
    u64 hash = 0;
    if (adytumfs_dir_name_hash(name, name_len, &hash)) return -1;
    static u8 bucket[ADYTUMFS_DIR_BUCKET_SIZE];
    u32 used = 0;
    struct adytumfs_item_key key;
    dirent_key(&key, dir, hash);
    if (!adytumfs_item_lookup(device, super, store, root, &key, bucket,
                              sizeof bucket, &used)) {
        u32 at = 0;
        if (!adytumfs_dirent_find(bucket, used, name, name_len, &at)) return -1;
        if (used + ADYTUMFS_DIRENT_HEADER + name_len > sizeof bucket) return -1;
    }
    if (adytumfs_dirent_pack(bucket + used, (u32)sizeof bucket - used, target,
                             type, name, name_len))
        return -1;
    used += ADYTUMFS_DIRENT_HEADER + name_len;
    return adytumfs_item_insert(device, super, store, root, &key, bucket, used,
                                new_root);
}

// Resolve one name. The type comes back with the target because a walk has to
// know whether what it found is a directory before it descends into it, and a
// second lookup to answer that would search the same bucket twice.
int adytumfs_dir_item_find(struct kernel_object *device,
                           struct adytumfs_superblock *super,
                           struct adytumfs_cas *store,
                           const u8 root[ADYTUMFS_ITEM_CHILD_SIZE], u64 dir,
                           const char *name, u32 name_len, u64 *target,
                           u8 *type) {
    if (!device || !super || !store || !root || !name || !target || !type)
        return -1;
    u64 hash = 0;
    if (adytumfs_dir_name_hash(name, name_len, &hash)) return -1;
    static u8 bucket[ADYTUMFS_DIR_BUCKET_SIZE];
    u32 size = 0;
    struct adytumfs_item_key key;
    dirent_key(&key, dir, hash);
    if (adytumfs_item_lookup(device, super, store, root, &key, bucket,
                             sizeof bucket, &size))
        return -1;
    u32 at = 0;
    if (adytumfs_dirent_find(bucket, size, name, name_len, &at)) return -1;
    u32 length = 0;
    return adytumfs_dirent_read(bucket, size, at, target, type, &length);
}

// Take one name out of a directory. A bucket left empty is removed rather
// than stored empty, because the tree holds no empty item and a zero length
// insert is one the packer refuses.
int adytumfs_dir_item_remove(struct kernel_object *device,
                             struct adytumfs_superblock *super,
                             struct adytumfs_cas *store,
                             const u8 root[ADYTUMFS_ITEM_CHILD_SIZE], u64 dir,
                             const char *name, u32 name_len,
                             u8 new_root[ADYTUMFS_ITEM_CHILD_SIZE]) {
    if (!device || !super || !store || !root || !name || !new_root) return -1;
    if (!dir) return -1;
    u64 hash = 0;
    if (adytumfs_dir_name_hash(name, name_len, &hash)) return -1;
    static u8 bucket[ADYTUMFS_DIR_BUCKET_SIZE];
    u32 size = 0;
    struct adytumfs_item_key key;
    dirent_key(&key, dir, hash);
    if (adytumfs_item_lookup(device, super, store, root, &key, bucket,
                             sizeof bucket, &size))
        return -1;
    u32 at = 0;
    if (adytumfs_dirent_find(bucket, size, name, name_len, &at)) return -1;
    u64 inode = 0;
    u8 type = 0;
    u32 length = 0;
    if (adytumfs_dirent_read(bucket, size, at, &inode, &type, &length))
        return -1;
    u32 entry = ADYTUMFS_DIRENT_HEADER + length;
    u32 used = size - entry;
    if (used) {
        for (u32 index = at + entry; index < size; index++)
            bucket[index - entry] = bucket[index];
        return adytumfs_item_insert(device, super, store, root, &key, bucket,
                                    used, new_root);
    }
    return adytumfs_item_remove(device, super, store, root, &key, new_root);
}

// Place a new record in a block that already holds a free record big enough,
// splitting the free space when the leftover can hold another record.
static int adytumfs_dir_place(u8 *block, const char *name, u32 name_len,
                              u64 target, u8 type, u32 needed) {
    u32 offset = 0;
    while (offset + ADYTUMFS_DIR_HEADER <= ADYTUMFS_BLOCK_SIZE) {
        u64 entry_inode = adytumfs_read_le64(block + offset);
        u16 rec_len = adytumfs_read_le16(block + offset + 8);
        if (rec_len < ADYTUMFS_DIR_HEADER ||
            offset + rec_len > ADYTUMFS_BLOCK_SIZE)
            return -1;
        if (entry_inode == 0 && rec_len >= needed) {
            u16 record = rec_len;
            if (rec_len - needed >= ADYTUMFS_DIR_HEADER + 4u) {
                record = (u16)needed;
                u32 rest = offset + needed;
                adytumfs_write_le64(block + rest, 0);
                adytumfs_write_le16(block + rest + 8, (u16)(rec_len - needed));
                block[rest + 10] = 0;
                block[rest + 11] = 0;
            }
            adytumfs_write_le64(block + offset, target);
            adytumfs_write_le16(block + offset + 8, record);
            block[offset + 10] = (u8)name_len;
            block[offset + 11] = type;
            for (u32 index = 0; index < name_len; index++)
                block[offset + 12 + index] = (u8)name[index];
            return 0;
        }
        offset += rec_len;
    }
    return -1;
}

int adytumfs_dir_lookup(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 dir_inode,
                        const char *name, u32 name_len, u64 *out_inode) {
    if (name_len == 0 || name_len > ADYTUMFS_NAME_MAX) return -1;
    struct adytumfs_inode dir;
    if (adytumfs_inode_read(device, super, store, dir_inode, &dir)) return -1;
    if ((dir.mode & ADYTUMFS_MODE_DIR) == 0) return -1;
    for (u64 logical = 0; logical < dir.blocks; logical++) {
        if (adytumfs_inode_fetch(device, super, store, &dir, logical,
                                 adytumfs_dir_scratch))
            return -1;
        u32 offset = 0;
        while (offset + ADYTUMFS_DIR_HEADER <= ADYTUMFS_BLOCK_SIZE) {
            u64 entry_inode = adytumfs_read_le64(adytumfs_dir_scratch + offset);
            u16 rec_len = adytumfs_read_le16(adytumfs_dir_scratch + offset + 8);
            u8 entry_name_len = adytumfs_dir_scratch[offset + 10];
            if (rec_len < ADYTUMFS_DIR_HEADER ||
                offset + rec_len > ADYTUMFS_BLOCK_SIZE)
                break;
            if (entry_inode != 0 && entry_name_len == name_len &&
                adytumfs_name_equal(adytumfs_dir_scratch + offset + 12, name,
                                    name_len)) {
                if (out_inode) *out_inode = entry_inode;
                return 0;
            }
            offset += rec_len;
        }
    }
    return -1;
}

int adytumfs_dir_add(struct kernel_object *device,
                     struct adytumfs_superblock *super,
                     struct adytumfs_cas *store, u64 dir_inode,
                     const char *name, u32 name_len, u64 target_inode,
                     u8 type) {
    if (name_len == 0 || name_len > ADYTUMFS_NAME_MAX || target_inode == 0)
        return -1;
    u64 present;
    if (adytumfs_dir_lookup(device, super, store, dir_inode, name, name_len,
                            &present) == 0)
        return -1;
    struct adytumfs_inode dir;
    if (adytumfs_inode_read(device, super, store, dir_inode, &dir)) return -1;
    if ((dir.mode & ADYTUMFS_MODE_DIR) == 0) return -1;

    u32 needed = ADYTUMFS_DIR_HEADER + ((name_len + 3u) & ~3u);
    for (u64 logical = 0; logical < dir.blocks; logical++) {
        if (adytumfs_inode_fetch(device, super, store, &dir, logical,
                                 adytumfs_dir_scratch))
            return -1;
        if (adytumfs_dir_place(adytumfs_dir_scratch, name, name_len,
                               target_inode, type, needed) == 0) {
            adytumfs_dir_touch(&dir);
            return adytumfs_inode_remap(device, super, store, &dir, dir_inode,
                                        logical, adytumfs_dir_scratch);
        }
    }

    // No room in any existing block, so grow by one and seed it with a single
    // free record spanning the whole block.
    if (adytumfs_inode_grow(device, super, store, &dir, dir_inode, dir.blocks + 1)) return -1;
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        adytumfs_dir_scratch[index] = 0;
    adytumfs_write_le16(adytumfs_dir_scratch + 8, (u16)ADYTUMFS_BLOCK_SIZE);
    if (adytumfs_dir_place(adytumfs_dir_scratch, name, name_len, target_inode,
                           type, needed))
        return -1;
    // Through a remap and not into the mapping: the block the grow just added
    // is the one image of zeroes every hole on the volume shares.
    if (adytumfs_inode_remap(device, super, store, &dir, dir_inode,
                             dir.blocks - 1, adytumfs_dir_scratch))
        return -1;
    dir.size = dir.blocks * ADYTUMFS_BLOCK_SIZE;
    adytumfs_dir_touch(&dir);
    return adytumfs_inode_write(device, super, store, dir_inode, &dir);
}

int adytumfs_dir_remove(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 dir_inode,
                        const char *name, u32 name_len) {
    if (name_len == 0 || name_len > ADYTUMFS_NAME_MAX) return -1;
    struct adytumfs_inode dir;
    if (adytumfs_inode_read(device, super, store, dir_inode, &dir)) return -1;
    if ((dir.mode & ADYTUMFS_MODE_DIR) == 0) return -1;
    for (u64 logical = 0; logical < dir.blocks; logical++) {
        if (adytumfs_inode_fetch(device, super, store, &dir, logical,
                                 adytumfs_dir_scratch))
            return -1;
        u32 offset = 0;
        while (offset + ADYTUMFS_DIR_HEADER <= ADYTUMFS_BLOCK_SIZE) {
            u64 entry_inode = adytumfs_read_le64(adytumfs_dir_scratch + offset);
            u16 rec_len = adytumfs_read_le16(adytumfs_dir_scratch + offset + 8);
            u8 entry_name_len = adytumfs_dir_scratch[offset + 10];
            if (rec_len < ADYTUMFS_DIR_HEADER ||
                offset + rec_len > ADYTUMFS_BLOCK_SIZE)
                break;
            if (entry_inode != 0 && entry_name_len == name_len &&
                adytumfs_name_equal(adytumfs_dir_scratch + offset + 12, name,
                                    name_len)) {
                // Tombstone: a zero inode makes the record free for reuse.
                adytumfs_write_le64(adytumfs_dir_scratch + offset, 0);
                adytumfs_dir_touch(&dir);
                return adytumfs_inode_remap(device, super, store, &dir, dir_inode,
                                            logical, adytumfs_dir_scratch);
            }
            offset += rec_len;
        }
    }
    return -1;
}

int adytumfs_dir_iter(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store, u64 dir_inode,
                      u64 *cursor, char *name, u32 *name_len, u64 *inode_out,
                      u8 *type_out) {
    if (!cursor || !name || !name_len || !inode_out || !type_out) return -1;
    struct adytumfs_inode dir;
    if (adytumfs_inode_read(device, super, store, dir_inode, &dir)) return -1;
    if ((dir.mode & ADYTUMFS_MODE_DIR) == 0) return -1;
    u64 total = dir.blocks * ADYTUMFS_BLOCK_SIZE;
    while (*cursor + ADYTUMFS_DIR_HEADER <= total) {
        u64 position = *cursor;
        u64 logical = position / ADYTUMFS_BLOCK_SIZE;
        u32 within = (u32)(position % ADYTUMFS_BLOCK_SIZE);
        if (adytumfs_inode_fetch(device, super, store, &dir, logical,
                                 adytumfs_dir_scratch))
            return -1;
        u64 entry_inode = adytumfs_read_le64(adytumfs_dir_scratch + within);
        u16 rec_len = adytumfs_read_le16(adytumfs_dir_scratch + within + 8);
        u8 entry_name_len = adytumfs_dir_scratch[within + 10];
        u8 entry_type = adytumfs_dir_scratch[within + 11];
        if (rec_len < ADYTUMFS_DIR_HEADER ||
            within + rec_len > ADYTUMFS_BLOCK_SIZE)
            return -1;
        *cursor = position + rec_len;
        if (entry_inode != 0) {
            if (ADYTUMFS_DIR_HEADER + entry_name_len > rec_len) return -1;
            for (u32 index = 0; index < entry_name_len; index++)
                name[index] = (char)adytumfs_dir_scratch[within + 12 + index];
            // The VFS and the probes read the name as a C string, and a
            // name at the bound fills the last byte of a bare
            // ADYTUMFS_NAME_MAX buffer, so the terminator lands here and
            // the callers size their buffers one byte past the bound.
            name[entry_name_len] = 0;
            *name_len = entry_name_len;
            *inode_out = entry_inode;
            *type_out = entry_type;
            return 0;
        }
    }
    return 1;
}
