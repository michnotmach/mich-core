#include "adytumfs_format.h"
#include "crypto.h"
#include "adytumfs_item.h"
#include "adytumfs_tree.h"
#include "blake2b.h"
#include "rtc64.h"

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
#define ADYTUMFS_DIRENT_MAX (ADYTUMFS_DIRENT_HEADER + ADYTUMFS_NAME_MAX)
#define ADYTUMFS_DIR_BUCKET_MAX 8u
#define ADYTUMFS_DIR_BUCKET_SIZE (ADYTUMFS_DIR_BUCKET_MAX * ADYTUMFS_DIRENT_MAX)

#define ADYTUMFS_DIR_HASH_BITS 61u
#define ADYTUMFS_DIR_HASH_MASK ((((u64)1) << ADYTUMFS_DIR_HASH_BITS) - 1u)
#define ADYTUMFS_DIR_CURSOR_SHIFT 3u
#define ADYTUMFS_DIR_CURSOR_MASK 7u

// The hash a name is keyed under. BLAKE2b with a 64 bit output rather than a
// truncation of the 512 bit digest, because the output length is part of the
// parameter block: asking for eight bytes is one pass over a shorter digest
// rather than eight passes over a longer one.
int adytumfs_dir_name_hash(const char *name, u32 name_len, u64 *hash) {
    if (!name || !hash || !name_len || name_len > ADYTUMFS_NAME_MAX) return -1;
    u8 digest[8];
    if (blake2b(digest, 8, name, name_len)) return -1;
    // Masked to the width the listing cursor reserves, so every hash a
    // directory can hold is inside the range a listing walks. An unmasked hash
    // would put the top of the space past the far bound and those names would
    // resolve by lookup while never appearing in a listing.
    *hash = adytumfs_read_le64(digest) & ADYTUMFS_DIR_HASH_MASK;
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

// A directory owns no data blocks: its entries are items in the item tree
// keyed by its own number, so its extent tree stays empty and its size stays
// zero. The audit already accepts an inode that claims no blocks.
//
// The name hash is 61 bits rather than 64 so a listing cursor can carry the
// hash and the position inside its bucket in one word, which is the width the
// VFS hands back and forth. Three bits off a 64 bit hash leaves a birthday
// bound orders of magnitude past the number of names one directory can hold,
// and the alternative is a cursor too wide for the interface above it.
static void dir_bound(struct adytumfs_item_key *key, u64 dir, u64 offset) {
    key->objectid = dir;
    key->type = ADYTUMFS_ITEM_DIR;
    key->offset = offset;
    key->spare = 0;
}

static void super_root_take(struct adytumfs_superblock *super,
                            const u8 root[ADYTUMFS_HASH_SIZE]) {
    for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
        super->inode_root[byte] = root[byte];
}

// Adopt a generation the tree just built and let go of the one it replaced.
//
// The root the committed generation names has to keep resolving until the
// commit flips the superblock, so it is held; the transaction root, captured
// here on the first adoption of the window, is what tells the two apart. Every
// root built after it is named by nothing the moment the next one lands, and
// holding on is what made a rebuilt index report a leak on a volume that had
// only ever been written to. The inode landing does the same, and a directory
// edit that skipped it left one unreachable leaf behind per entry.
static int dir_root_adopt(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store,
                          const u8 root[ADYTUMFS_HASH_SIZE]) {
    u8 previous[ADYTUMFS_HASH_SIZE];
    for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
        previous[byte] = super->inode_root[byte];
    // Captured in its own pass: testing for an empty root while filling it
    // would see the first byte land and stop, leaving a root that matches
    // nothing and dropping the generation the device still names.
    if (adytumfs_item_root_empty(store->txn_root))
        for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
            store->txn_root[byte] = previous[byte];
    super_root_take(super, root);
    if (crypto_equal(previous, store->txn_root, ADYTUMFS_HASH_SIZE)) return 0;
    return adytumfs_item_drop(device, super, store, previous);
}

// Stamping the parent is what is left of the write the packed layout needed,
// and there is no longer a block to remap, so it is one inode write.
static int dir_touch_write(struct kernel_object *device,
                           struct adytumfs_superblock *super,
                           struct adytumfs_cas *store,
                           struct adytumfs_inode *dir, u64 dir_inode) {
    adytumfs_dir_touch(dir);
    return adytumfs_inode_write(device, super, store, dir_inode, dir);
}

int adytumfs_dir_lookup(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 dir_inode,
                        const char *name, u32 name_len, u64 *out_inode) {
    if (!device || !super || !store || !name) return -1;
    if (name_len == 0 || name_len > ADYTUMFS_NAME_MAX) return -1;
    struct adytumfs_inode dir;
    if (adytumfs_inode_read(device, super, store, dir_inode, &dir)) return -1;
    if ((dir.mode & ADYTUMFS_MODE_DIR) == 0) return -1;
    u64 target = 0;
    u8 type = 0;
    if (adytumfs_dir_item_find(device, super, store, super->inode_root,
                               dir_inode, name, name_len, &target, &type))
        return -1;
    if (out_inode) *out_inode = target;
    return 0;
}

int adytumfs_dir_add(struct kernel_object *device,
                     struct adytumfs_superblock *super,
                     struct adytumfs_cas *store, u64 dir_inode,
                     const char *name, u32 name_len, u64 target_inode,
                     u8 type) {
    if (!device || !super || !store || !name) return -1;
    if (name_len == 0 || name_len > ADYTUMFS_NAME_MAX || target_inode == 0)
        return -1;
    struct adytumfs_inode dir;
    if (adytumfs_inode_read(device, super, store, dir_inode, &dir)) return -1;
    if ((dir.mode & ADYTUMFS_MODE_DIR) == 0) return -1;
    u8 root[ADYTUMFS_HASH_SIZE];
    // The entry reaches the tree before the parent's timestamp, so a crash
    // between the two leaves a name that resolves and a parent whose mtime is
    // stale. The other order would leave a timestamp claiming an edit that a
    // reader cannot see.
    if (adytumfs_dir_item_add(device, super, store, super->inode_root,
                              dir_inode, name, name_len, target_inode, type,
                              root))
        return -1;
    if (dir_root_adopt(device, super, store, root)) return -1;
    return dir_touch_write(device, super, store, &dir, dir_inode);
}

int adytumfs_dir_remove(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 dir_inode,
                        const char *name, u32 name_len) {
    if (!device || !super || !store || !name) return -1;
    if (name_len == 0 || name_len > ADYTUMFS_NAME_MAX) return -1;
    struct adytumfs_inode dir;
    if (adytumfs_inode_read(device, super, store, dir_inode, &dir)) return -1;
    if ((dir.mode & ADYTUMFS_MODE_DIR) == 0) return -1;
    u8 root[ADYTUMFS_HASH_SIZE];
    if (adytumfs_dir_item_remove(device, super, store, super->inode_root,
                                 dir_inode, name, name_len, root))
        return -1;
    if (dir_root_adopt(device, super, store, root)) return -1;
    return dir_touch_write(device, super, store, &dir, dir_inode);
}

struct dir_iter_state {
    u64 dir;
    u64 resume_hash;
    u32 resume_skip;
    u32 returned;
    char *name;
    u32 *name_len;
    u64 *inode_out;
    u8 *type_out;
    u64 *cursor;
};

// One bucket at a time. Entries already handed back on an earlier call sit at
// the front of the bucket the cursor names, so they are counted past rather
// than compared, and the walk stops on the first entry after them. Returning a
// non zero value is what ends the walk, so this returns one once it has an
// entry and the caller reads that as a listing rather than as a failure.
static int dir_iter_visit(const struct adytumfs_item_key *key, const u8 *data,
                          u32 size, void *context) {
    struct dir_iter_state *it = context;
    if (key->objectid != it->dir || key->type != ADYTUMFS_ITEM_DIR) return 0;
    u32 offset = 0;
    u32 index = 0;
    while (offset + ADYTUMFS_DIRENT_HEADER <= size) {
        u64 inode = 0;
        u8 type = 0;
        u32 length = 0;
        if (adytumfs_dirent_read(data, size, offset, &inode, &type, &length))
            return -1;
        if (key->offset == it->resume_hash && index < it->resume_skip) {
            offset += ADYTUMFS_DIRENT_HEADER + length;
            index++;
            continue;
        }
        for (u32 byte = 0; byte < length; byte++)
            it->name[byte] = (char)data[offset + ADYTUMFS_DIRENT_HEADER + byte];
        // The VFS reads the name as a C string, and a name at the bound fills
        // the last byte of a bare ADYTUMFS_NAME_MAX buffer, so the terminator
        // lands here and callers size their buffers one past the bound.
        it->name[length] = 0;
        *it->name_len = length;
        *it->inode_out = inode;
        *it->type_out = type;
        *it->cursor = (key->offset << ADYTUMFS_DIR_CURSOR_SHIFT) |
                      (u64)(index + 1u);
        it->returned = 1;
        return 1;
    }
    return 0;
}

int adytumfs_dir_iter(struct kernel_object *device,
                      struct adytumfs_superblock *super,
                      struct adytumfs_cas *store, u64 dir_inode,
                      u64 *cursor, char *name, u32 *name_len, u64 *inode_out,
                      u8 *type_out) {
    if (!device || !super || !store) return -1;
    if (!cursor || !name || !name_len || !inode_out || !type_out) return -1;
    struct adytumfs_inode dir;
    if (adytumfs_inode_read(device, super, store, dir_inode, &dir)) return -1;
    if ((dir.mode & ADYTUMFS_MODE_DIR) == 0) return -1;
    struct dir_iter_state it = {0};
    it.dir = dir_inode;
    it.resume_hash = *cursor >> ADYTUMFS_DIR_CURSOR_SHIFT;
    it.resume_skip = (u32)(*cursor & ADYTUMFS_DIR_CURSOR_MASK);
    it.name = name;
    it.name_len = name_len;
    it.inode_out = inode_out;
    it.type_out = type_out;
    it.cursor = cursor;
    // Both bounds carry the directory and the entry type, and the key order is
    // objectid then type then offset, so the range is exactly this directory's
    // entries and nothing else in the tree is read.
    struct adytumfs_item_key from;
    struct adytumfs_item_key to;
    dir_bound(&from, dir_inode, *cursor ? it.resume_hash : 0);
    dir_bound(&to, dir_inode, ADYTUMFS_DIR_HASH_MASK);
    int result = adytumfs_item_walk_range(device, super, store,
                                          super->inode_root, &from, &to,
                                          dir_iter_visit, &it);
    if (result < 0) return -1;
    return it.returned ? 0 : 1;
}
