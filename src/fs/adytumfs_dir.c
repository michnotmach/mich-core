#include "adytumfs_format.h"
#include "adytumfs_tree.h"
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
