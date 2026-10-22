#include "types.h"
#include "object.h"
#include "block.h"
#include "cache.h"
#include "adytumfs.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"
#include "adytumfs_index.h"
#include "adytumfs_item.h"
#include "blake2b.h"
#include "vfs.h"
#include "resource.h"

// One staging block for raw device probes and on-disk edits; the test battery
// is single-CPU, so reuse across probes is safe.
static u8 adytumfs_probe_block[ADYTUMFS_BLOCK_SIZE];

static int probe_name_equals(const char *name, const char *expect) {
    u32 index = 0;
    while (expect[index]) {
        if (name[index] != expect[index]) return 0;
        index++;
    }
    return !name[index];
}

// block_io moves one sector per call, so a raw 4 KiB block probe reads in
// eight steps.
static int probe_read_block(struct kernel_object *dev, u64 block, u8 *buffer) {
    for (u32 sector = 0; sector < ADYTUMFS_SECTORS_PER_BLOCK; sector++)
        if (block_io(dev, BLOCK_OP_READ,
                     (u32)(block * ADYTUMFS_SECTORS_PER_BLOCK + sector), 1,
                     buffer + sector * BLOCK_SECTOR_SIZE, BLOCK_SECTOR_SIZE))
            return -1;
    return 0;
}

// Parse the volume superblock through the block cache, which the corruption
// scenarios below also write their edits through.
// Read the live generation of the pair, the same pick a mount would make,
// so device-side assertions target the set that is actually current.
// One content store for the whole file, opened whenever a superblock is read.
// The scenarios are single threaded and each formats its own volume, so a
// single static store serves all of them and no scenario has to say so.
static struct adytumfs_cas adytumfs_test_store;

// Directory entries are items in the item tree, and copy on write writes a
// node per edit that nothing reclaims until a commit, so the volumes in this
// battery have to carry the metadata churn rather than fit the smallest layout
// the packed directory records needed. Measured, not guessed: the overrun case
// creates 127 files through a sync per file and needs every block a device
// takes, while 320 sectors ran out around a hundred. One constant, because a
// size asserted against the superblock has to be the size the device was
// created with.
#define ADYTUMFS_TEST_SECTORS 2304u

// The overrun case is the exception: it fills a directory past the mount slot
// bound, which is the one place the battery needs every block a device takes.
// Giving the whole battery that size pushed the suite past the smoke timeout.
#define ADYTUMFS_OVERRUN_SECTORS 4096u

// The attached volume's mount index. Only a live mount resolves a root, so
// the question "which mount is this" is the same question as "which mount is
// still attached".
static u32 probe_mount(void) {
    for (u32 probe = 1; probe < VFS_MOUNT_MAX; probe++) {
        u64 root = 0;
        u64 generation = 0;
        if (!adytumfs_root_inode(probe, &root, &generation)) return probe;
    }
    return 0;
}

// Resolve one name inside a directory inode and report the file it names.
//
// Inode numbers are whatever the allocator handed out, and a directory lists
// in hash order, so a test that wants a particular file looks for it by name
// rather than assuming a number.
static int probe_find_in(u32 mount_id, u64 dir, const char *want, u64 *slot,
                         u32 *used, u32 *type, u32 *size, u32 *mode) {
    u64 generation = 0;
    if (adytumfs_inode_get(mount_id, dir, used, type, size, mode, &generation))
        return -1;
    u32 name_len = 0;
    while (want[name_len]) name_len++;
    u64 entry = 0;
    u32 entry_type = 0;
    if (adytumfs_dir_find(mount_id, dir, generation, want, name_len, &entry,
                          &entry_type))
        return -1;
    if (adytumfs_inode_get(mount_id, entry, used, type, size, mode,
                           &generation))
        return -1;
    *slot = entry;
    return 0;
}

static int probe_find_slot(u32 mount_id, const char *want, u64 *slot,
                           u32 *used, u32 *type, u32 *size, u32 *mode) {
    u64 root = 0;
    u64 generation = 0;
    if (adytumfs_root_inode(mount_id, &root, &generation)) return -1;
    return probe_find_in(mount_id, root, want, slot, used, type, size, mode);
}

// Either name of a hard link resolves to the same inode, and which one the
// directory happens to answer with follows from the hashes rather than from
// the order the links were made in.
static int probe_find_slot_any(u32 mount_id, const char *first,
                               const char *second, u64 *slot, u32 *used,
                               u32 *type, u32 *size, u32 *mode) {
    if (!probe_find_slot(mount_id, first, slot, used, type, size, mode))
        return 0;
    return probe_find_slot(mount_id, second, slot, used, type, size, mode);
}

static int policy_super(struct kernel_object *dev,
                        struct adytumfs_superblock *super) {
    if (adytumfs_super_read(dev, super)) return -1;
    adytumfs_cas_open(&adytumfs_test_store, super->index_start,
                      super->index_blocks);
    return 0;
}

// Publish a forged copy of one directory entry as the next generation.
//
// Content addressing means a bare byte flip is caught by the node hash before
// anything reads the entry, so a lie that has to reach a mount check needs a
// hash matching what it holds, and republishing through the tree is what
// produces one. The bucket is read first so the forgery replaces one entry and
// leaves any other name sharing the hash untouched, which is also what a real
// corruption would look like: one entry wrong, the rest of the volume sound.
static int policy_forge_dirent(struct kernel_object *dev,
                               struct adytumfs_superblock *super, u64 dir,
                               const char *name, u32 name_len, u64 target,
                               u8 type) {
    static u8 bucket[8 * (ADYTUMFS_DIRENT_HEADER + ADYTUMFS_NAME_MAX)];
    u64 hash = 0;
    if (adytumfs_dir_name_hash(name, name_len, &hash)) return -1;
    struct adytumfs_item_key key = {0};
    key.objectid = dir;
    key.type = ADYTUMFS_ITEM_DIR;
    key.offset = hash;
    u32 used = 0;
    if (!adytumfs_item_lookup(dev, super, &adytumfs_test_store,
                              super->inode_root, &key, bucket,
                              (u32)sizeof bucket, &used)) {
        u32 at = 0;
        if (adytumfs_dirent_find(bucket, used, name, name_len, &at)) return -1;
        u64 inode = 0;
        u8 old_type = 0;
        u32 length = 0;
        if (adytumfs_dirent_read(bucket, used, at, &inode, &old_type, &length))
            return -1;
        u32 entry = ADYTUMFS_DIRENT_HEADER + length;
        for (u32 index = at + entry; index < used; index++)
            bucket[index - entry] = bucket[index];
        used -= entry;
    }
    if (adytumfs_dirent_pack(bucket + used, (u32)sizeof bucket - used, target,
                             type, name, name_len))
        return -1;
    used += ADYTUMFS_DIRENT_HEADER + name_len;
    u8 next[ADYTUMFS_HASH_SIZE];
    if (adytumfs_item_insert(dev, super, &adytumfs_test_store,
                             super->inode_root, &key, bucket, used, next))
        return -1;
    for (u32 byte = 0; byte < ADYTUMFS_HASH_SIZE; byte++)
        super->inode_root[byte] = next[byte];
    return 0;
}

// Land a superblock whose root was moved outside the commit protocol.
//
// The commit skips itself when no inode is staged, and a forged directory
// entry stages none, so the generation has to be written the way the commit
// would have written it: into the slot that is not the active one, with a
// higher generation, and with the cache dropped so the mount that follows
// reads the device rather than a stale copy of it.
static int policy_land_super(struct kernel_object *dev,
                             struct adytumfs_superblock *super) {
    super->active_slot = super->active_slot ? 0 : 1;
    super->generation++;
    adytumfs_super_pack(adytumfs_probe_block, super);
    if (adytumfs_block_write(dev, adytumfs_superblock_block(super),
                             adytumfs_probe_block))
        return -1;
    if (block_cache_flush(dev)) return -1;
    block_cache_drop_device((u32)dev->value);
    return 0;
}

// Land a staging-block edit on the device and drop the cached copies, so the
// next mount attempt reads the corruption the way a later boot would.
static int policy_commit(struct kernel_object *dev, u64 block) {
    if (adytumfs_block_write(dev, block, adytumfs_probe_block)) return -1;
    if (block_cache_flush(dev)) return -1;
    block_cache_drop_device((u32)dev->value);
    return 0;
}

// Read the leaf holding one inode item and report where its bytes sit, so a
// test can forge the item in place. Content addressing means the forgery is
// caught by the hash the parent promised rather than by the item's own
// checksum, which is the stronger of the two and the one the read path makes.
static int inode_item_at(struct kernel_object *dev,
                         struct adytumfs_superblock *super,
                         struct adytumfs_cas *store, u64 number, u8 *scratch,
                         u64 *node_out, u32 *offset_out) {
    u64 node = 0;
    if (adytumfs_cas_lookup(dev, super, store, super->inode_root, &node))
        return -1;
    if (adytumfs_block_read(dev, node, scratch)) return -1;
    struct adytumfs_item_key key = {0};
    key.objectid = number;
    key.type = ADYTUMFS_ITEM_INODE;
    int at = adytumfs_item_node_search(scratch, &key);
    if (at < 0) return -1;
    const u8 *item = 0;
    struct adytumfs_item_key found = {0};
    u32 size = 0;
    if (adytumfs_item_leaf_get(scratch, (u32)at, &found, &item, &size)) return -1;
    *node_out = node;
    *offset_out = (u32)(item - scratch);
    return 0;
}

int test_adytumfs64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    struct kernel_object *mnt = root ?
        vfs_create(root, "disk", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
    u8 payload[16];
    u8 received[16];
    for (u32 i = 0; i < 16; i++) {
        payload[i] = (u8)('A' + i);
        received[i] = 0;
    }
    u32 transferred = 0;
    int valid = root && mnt && dev && !adytumfs_format(dev) &&
        !vfs_mount_adytumfs(mnt, dev);
    struct kernel_object *disk = valid ? vfs_lookup(root, "disk") : 0;
    struct kernel_object *node = disk ?
        vfs_create_mode(disk, "hello", VFS_NODE_REGULAR, 0604) : 0;
    struct kernel_object *folder = disk ?
        vfs_create_mode(disk, "folder", VFS_NODE_DIRECTORY, 0711) : 0;
    struct kernel_object *nested = folder ?
        vfs_create_mode(folder, "nested", VFS_NODE_REGULAR, 0620) : 0;
    // A component of the full POSIX NAME_MAX length round-trips through the
    // directory blocks and the slot table.
    char stretched_name[VFS_NAME_MAX + 1];
    for (u32 i = 0; i < VFS_NAME_MAX; i++)
        stretched_name[i] = (u8)('a' + (i % 26));
    stretched_name[VFS_NAME_MAX] = 0;
    struct kernel_object *stretched = disk ?
        vfs_create_mode(disk, stretched_name, VFS_NODE_REGULAR, 0600) : 0;
    struct kernel_object *stretched_found = stretched ?
        vfs_lookup(disk, stretched_name) : 0;
    valid = valid && stretched && stretched_found;
    if (stretched_found) object_release(stretched_found);
    if (stretched) {
        if (vfs_unlink(disk, stretched_name)) valid = 0;
        object_release(stretched);
    }
    // List the mount root: hello and folder survive, the unlinked long name
    // does not, and the entry types and inode numbers are real.
    struct kernel_object *listing = disk ? vfs_open(disk) : 0;
    u64 listing_cursor = 0;
    char listing_name[VFS_NAME_MAX + 1];
    u32 listing_hello = 0;
    u32 listing_folder = 0;
    while (listing) {
        u32 listing_len = 0;
        u64 listing_inode = 0;
        u32 listing_type = 0;
        int step = vfs_read_dir(listing, &listing_cursor, listing_name,
                                &listing_len, &listing_inode, &listing_type);
        if (step < 0) {
            valid = 0;
            break;
        }
        if (step > 0) break;
        if (probe_name_equals(listing_name, "hello")) {
            listing_hello++;
            if (listing_type != VFS_NODE_REGULAR || !listing_inode) valid = 0;
        } else if (probe_name_equals(listing_name, "folder")) {
            listing_folder++;
            if (listing_type != VFS_NODE_DIRECTORY || !listing_inode)
                valid = 0;
        } else {
            valid = 0;
        }
    }
    valid = valid && listing && listing_hello == 1 && listing_folder == 1;
    if (listing) object_release(listing);
    struct kernel_object *opened = node ? vfs_open(node) : 0;
    struct vfs_node_info info;
    valid = valid && disk && node && folder && nested && opened &&
        !vfs_write(opened, 0, payload, sizeof(payload), &transferred) &&
        transferred == sizeof(payload) &&
        !vfs_read(opened, 0, received, sizeof(received), &transferred) &&
        transferred == sizeof(received) &&
        !vfs_stat(opened, &info) &&
        info.filesystem == VFS_FILESYSTEM_ADYTUMFS &&
        info.size == sizeof(payload) && info.mode == 0604 && !info.readonly;
    for (u32 i = 0; i < 16; i++)
        if (received[i] != payload[i]) valid = 0;
    valid = valid && !vfs_truncate(opened, 4) &&
        !vfs_stat(node, &info) && info.size == 4 &&
        !vfs_read(opened, 0, received, sizeof(received), &transferred) &&
        transferred == 4 && vfs_unmount(mnt) < 0;
    // A write past the end lands through the transport on a block the
    // allocator handed back, and the truncate redirect writes it again: a
    // cached image of that block must not survive either write.
    valid = valid &&
        !vfs_write(opened, 516, payload, 4, &transferred) &&
        transferred == 4 &&
        !vfs_fsync(opened) &&
        !vfs_truncate(opened, 4) &&
        !vfs_read(opened, 0, received, 4, &transferred) &&
        transferred == 4 && received[0] == payload[0] &&
        received[3] == payload[3] &&
        !vfs_stat(node, &info) && info.size == 4;
    if (opened) {
        object_release(opened);
        opened = 0;
    }

    // A hard link lands a second disk name on one inode: the VFS reports
    // the shared count, a directory or a cross-filesystem target refuses,
    // and the remount below proves the pair walked back in.
    struct kernel_object *alias = node ?
        (vfs_link(node, disk, "hello-alias") ? 0 :
         vfs_lookup(disk, "hello-alias")) : 0;
    valid = valid && alias == node && !vfs_stat(node, &info) &&
        info.links == 2 && vfs_link(folder, disk, "folder-alias") < 0 &&
        vfs_link(node, root, "cross") < 0 &&
        vfs_link(node, disk, "folder") < 0;

    int first_unmount = mnt && !vfs_unmount(mnt);
    int remounted = first_unmount && !vfs_mount_adytumfs(mnt, dev);
    struct kernel_object *fresh_directory = remounted ?
        vfs_lookup(root, "disk") : 0;
    struct kernel_object *fresh = fresh_directory ?
        vfs_lookup(fresh_directory, "hello") : 0;
    struct kernel_object *fresh_folder = fresh_directory ?
        vfs_lookup(fresh_directory, "folder") : 0;
    struct kernel_object *fresh_nested = fresh_folder ?
        vfs_lookup(fresh_folder, "nested") : 0;
    struct kernel_object *fresh_alias = fresh_directory ?
        vfs_lookup(fresh_directory, "hello-alias") : 0;
    struct kernel_object *reopened = fresh ? vfs_open(fresh) : 0;
    valid = valid && first_unmount && remounted && fresh_directory && fresh &&
        fresh_folder && fresh_nested && fresh_alias == fresh &&
        !vfs_stat(fresh, &info) &&
        info.mode == 0604 && info.size == 4 && info.links == 2 &&
        info.uid == 0 && info.gid == 0 && info.atime && info.mtime &&
        info.ctime &&
        !vfs_stat(fresh_folder, &info) && info.mode == 0711 &&
        info.links == 2 &&
        !vfs_stat(fresh_nested, &info) && info.mode == 0620 && reopened &&
        vfs_unmount(mnt) < 0;

    if (!vfs_stat(fresh, &info)) {
    }
    if (!vfs_stat(fresh_folder, &info)) {
    }
    if (!vfs_stat(fresh_nested, &info)) {
    }
    // Ask the backend for the picture a path walk would build: names resolve
    // through the item tree and the inode carries the type, mode, and the
    // truncated size that reached the disk.
    u32 mount_id = probe_mount();
    u32 used = 0, type = 0, size = 0, mode = 0;
    u64 hello_slot = 0;
    u64 folder_slot = 0;
    u64 nested_slot = 0;
    // "nested" is found inside the inode "folder" resolved to, which is the
    // parent link stated directly rather than inferred from numbering.
    valid = valid && mount_id &&
        !probe_find_slot_any(mount_id, "hello", "hello-alias", &hello_slot,
                             &used, &type, &size, &mode) &&
        used == 1 && type == VFS_NODE_REGULAR && size == 4 && mode == 0604 &&
        !probe_find_slot(mount_id, "folder", &folder_slot, &used, &type,
                         &size, &mode) &&
        used == 1 && type == VFS_NODE_DIRECTORY && mode == 0711 &&
        !probe_find_in(mount_id, folder_slot, "nested", &nested_slot, &used,
                       &type, &size, &mode) &&
        used == 1 && type == VFS_NODE_REGULAR && mode == 0620 &&
        nested_slot && nested_slot != folder_slot;
    if (reopened) {
        object_release(reopened);
        reopened = 0;
    }
    int second_unmount = fresh_directory && fresh_folder &&
        !vfs_unlink(fresh_directory, "hello") &&
        !vfs_stat(fresh, &info) && info.links == 1 && info.linked &&
        !vfs_lookup(fresh_directory, "hello") &&
        !vfs_unlink(fresh_directory, "hello-alias") &&
        !vfs_unlink(fresh_folder, "nested") &&
        !vfs_unlink(fresh_directory, "folder") && !vfs_unmount(mnt);
    int final_remount = second_unmount && !vfs_mount_adytumfs(mnt, dev);
    struct kernel_object *final_directory = final_remount ?
        vfs_lookup(root, "disk") : 0;
    struct kernel_object *missing = final_directory ?
        vfs_lookup(final_directory, "hello") : 0;
    struct kernel_object *missing_alias = final_directory ?
        vfs_lookup(final_directory, "hello-alias") : 0;
    struct kernel_object *stale = final_remount && node ? vfs_open(node) : 0;
    valid = valid && second_unmount && final_remount &&
        vfs_stat(node, &info) < 0 && !stale && !missing &&
        !missing_alias;
    if (stale) object_release(stale);
    if (missing) object_release(missing);
    // A file keeps its data and its inode while a descriptor stays open
    // past the last unlink; the reclaim lands with the final close, and
    // the slot picture a later mount would scan is root only.
    struct kernel_object *ghost = final_directory ?
        vfs_create(final_directory, "ghost", VFS_NODE_REGULAR) : 0;
    struct kernel_object *ghost_fd = ghost ? vfs_open(ghost) : 0;
    valid = valid && ghost && ghost_fd &&
        !vfs_write(ghost_fd, 0, payload + 8, 4, &transferred) &&
        transferred == 4 && !vfs_unlink(final_directory, "ghost") &&
        !vfs_lookup(final_directory, "ghost") &&
        !vfs_read(ghost_fd, 0, received, 4, &transferred) &&
        transferred == 4 && received[0] == payload[8] &&
        !vfs_stat(ghost_fd, &info) && info.size == 4 && !info.linked &&
        !info.links && vfs_unmount(mnt) < 0;
    if (ghost_fd) {
        object_release(ghost_fd);
        ghost_fd = 0;
    }
    if (ghost) {
        object_release(ghost);
        ghost = 0;
    }
    // The property under test is that nothing unlinked comes back: a fresh
    // mount of the volume resolves its root and that root lists nothing.
    u32 ghost_mount = probe_mount();
    u64 ghost_root = 0;
    u64 ghost_generation = 0;
    u32 ghost_entries = 0;
    if (ghost_mount &&
        !adytumfs_root_inode(ghost_mount, &ghost_root, &ghost_generation)) {
        u64 ghost_cursor = 0;
        for (;;) {
            char ghost_name[ADYTUMFS_NAME_MAX + 1];
            u32 ghost_len = 0;
            u64 ghost_target = 0;
            u32 ghost_type = 0;
            if (adytumfs_dir_read(ghost_mount, ghost_root, ghost_generation,
                                  &ghost_cursor, ghost_name, &ghost_len,
                                  &ghost_target, &ghost_type))
                break;
            ghost_entries++;
        }
    }
    valid = valid && ghost_mount && ghost_root && !ghost_entries;
    if (final_directory) object_release(final_directory);
    if (final_remount && vfs_unmount(mnt)) valid = 0;
    // Rename reaches the disk: the moved name, the replaced target, and
    // the renamed directory all walk back in after a remount, a
    // mountpoint keeps its name, and a descriptor stays usable across
    // the move of its name.
    int rename_mounted = mnt && !vfs_mount_adytumfs(mnt, dev);
    struct kernel_object *rename_dir = rename_mounted ?
        vfs_lookup(root, "disk") : 0;
    struct kernel_object *rename_folder = rename_dir ?
        vfs_create(rename_dir, "folder", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *rename_file = rename_folder ?
        vfs_create(rename_folder, "file", VFS_NODE_REGULAR) : 0;
    struct kernel_object *rename_victim = rename_dir ?
        vfs_create(rename_dir, "victim", VFS_NODE_REGULAR) : 0;
    struct kernel_object *rename_fd = rename_file ? vfs_open(rename_file) : 0;
    valid = valid && rename_mounted && rename_dir && rename_folder &&
        rename_file && rename_victim && rename_fd &&
        vfs_rename(root, "disk", root, "volume") < 0 &&
        !vfs_write(rename_fd, 0, payload, 4, &transferred) &&
        transferred == 4 &&
        !vfs_rename(rename_folder, "file", rename_dir, "moved");
    struct kernel_object *replaced = valid ?
        vfs_lookup(rename_dir, "victim") : 0;
    struct kernel_object *arrived = valid ?
        vfs_lookup(rename_dir, "moved") : 0;
    valid = valid && !vfs_stat(rename_fd, &info) && info.size == 4 &&
        info.linked && arrived == rename_file &&
        !vfs_rename(rename_dir, "moved", rename_dir, "victim") &&
        replaced == rename_victim && !vfs_lookup(rename_dir, "moved") &&
        !vfs_rename(rename_dir, "folder", rename_dir, "archive");
    if (replaced) object_release(replaced);
    if (arrived) object_release(arrived);
    if (rename_fd) {
        object_release(rename_fd);
        rename_fd = 0;
    }
    int rename_unmount = rename_dir && !vfs_unmount(mnt);
    int rename_remount = rename_unmount && !vfs_mount_adytumfs(mnt, dev);
    struct kernel_object *disk_again = rename_remount ?
        vfs_lookup(root, "disk") : 0;
    struct kernel_object *archive_again = disk_again ?
        vfs_lookup(disk_again, "archive") : 0;
    struct kernel_object *victim_again = disk_again ?
        vfs_lookup(disk_again, "victim") : 0;
    valid = valid && rename_unmount && rename_remount && disk_again &&
        archive_again && victim_again && !vfs_lookup(disk_again, "moved") &&
        !vfs_lookup(disk_again, "folder") &&
        !vfs_stat(victim_again, &info) && info.size == 4 &&
        info.type == VFS_NODE_REGULAR && info.links == 1 &&
        !vfs_stat(archive_again, &info) &&
        info.type == VFS_NODE_DIRECTORY && info.links == 2;
    // The picture a later mount would build: the renamed directory answers
    // to its new name, the moved file kept its inode under the replaced
    // name, and the name that was replaced no longer resolves.
    u32 rename_mount = probe_mount();
    u32 rename_used = 0;
    u32 rename_type = 0;
    u32 rename_size = 0;
    u32 rename_mode = 0;
    u64 rename_root = 0;
    u64 rename_generation = 0;
    u64 archive_inode = 0;
    u64 victim_inode = 0;
    u64 gone_inode = 0;
    valid = valid && rename_mount &&
        !adytumfs_root_inode(rename_mount, &rename_root, &rename_generation) &&
        !probe_find_in(rename_mount, rename_root, "archive", &archive_inode,
                       &rename_used, &rename_type, &rename_size,
                       &rename_mode) &&
        rename_used == 1 && rename_type == VFS_NODE_DIRECTORY &&
        !probe_find_in(rename_mount, rename_root, "victim", &victim_inode,
                       &rename_used, &rename_type, &rename_size,
                       &rename_mode) &&
        rename_used == 1 && rename_type == VFS_NODE_REGULAR &&
        rename_size == 4 &&
        adytumfs_dir_find(rename_mount, rename_root, rename_generation,
                          "file", 4, &gone_inode, &rename_type);
    if (victim_again) object_release(victim_again);
    if (archive_again) object_release(archive_again);
    if (disk_again) object_release(disk_again);
    if (rename_remount && vfs_unmount(mnt)) valid = 0;
    if (rename_victim) object_release(rename_victim);
    if (rename_file) object_release(rename_file);
    if (rename_folder) object_release(rename_folder);
    if (rename_dir) object_release(rename_dir);
    // A symlink on the volume keeps its target in the file body: the
    // link survives a remount with the same string, the same length, and
    // the same inode, and the slot picture reports the type.
    int link_mounted = mnt && !vfs_mount_adytumfs(mnt, dev);
    struct kernel_object *link_dir = link_mounted ?
        vfs_lookup(root, "disk") : 0;
    struct kernel_object *guide = link_dir ?
        vfs_symlink(link_dir, "guide", "/volume/landing") : 0;
    char link_target[VFS_PATH_MAX];
    u32 link_length = 0;
    int rc_link_read = vfs_readlink(guide, link_target,
                                    sizeof(link_target), &link_length);
    int rc_link_stat = vfs_stat(guide, &info);
    int link_unmount = link_dir && !vfs_unmount(mnt);
    int link_remount = link_unmount && !vfs_mount_adytumfs(mnt, dev);
    struct kernel_object *link_dir_again = link_remount ?
        vfs_lookup(root, "disk") : 0;
    struct kernel_object *guide_again = link_dir_again ?
        vfs_lookup(link_dir_again, "guide") : 0;
    char target_again[VFS_PATH_MAX];
    u32 again_length = 0;
    int rc_read_again = vfs_readlink(guide_again, target_again,
                                     sizeof(target_again), &again_length);
    int targets_equal = !rc_read_again && !rc_link_read &&
        again_length == link_length;
    for (u32 index = 0; targets_equal && index < again_length; index++)
        if (target_again[index] != link_target[index]) targets_equal = 0;
    int rc_again_stat = vfs_stat(guide_again, &info);
    int rc_guide_unlink = vfs_unlink(link_dir_again, "guide");
    valid = valid && link_mounted && link_dir && guide && !rc_link_read &&
        link_length == 15 && !rc_link_stat &&
        info.type == VFS_NODE_SYMLINK && info.size == 15 &&
        link_unmount && link_remount && link_dir_again && guide_again &&
        !rc_read_again && targets_equal && !rc_again_stat &&
        info.type == VFS_NODE_SYMLINK && info.size == 15 &&
        !rc_guide_unlink;
    if (guide_again) object_release(guide_again);
    if (link_dir_again) object_release(link_dir_again);
    if (guide) object_release(guide);
    if (link_dir) object_release(link_dir);
    if (link_remount && vfs_unmount(mnt)) valid = 0;
    if (alias) object_release(alias);
    if (fresh_alias) object_release(fresh_alias);
    if (missing_alias) object_release(missing_alias);
    if (fresh_nested) object_release(fresh_nested);
    if (fresh_folder) object_release(fresh_folder);
    if (fresh) object_release(fresh);
    if (fresh_directory) object_release(fresh_directory);
    if (nested) object_release(nested);
    if (folder) object_release(folder);
    if (node) object_release(node);
    if (disk) object_release(disk);
    if (root) vfs_unlink(root, "disk");
    if (mnt) object_release(mnt);
    if (root) object_release(root);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

int test_adytumfs_pages64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    struct kernel_object *mnt = root ?
        vfs_create(root, "pages", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
    int valid = root && mnt && dev && !adytumfs_format(dev) &&
        !vfs_mount_adytumfs(mnt, dev);
    struct kernel_object *disk = valid ? vfs_lookup(root, "pages") : 0;
    struct kernel_object *node = disk ?
        vfs_create(disk, "wide", VFS_NODE_REGULAR) : 0;
    struct kernel_object *opened = node ? vfs_open(node) : 0;
    valid = valid && disk && node && opened;

    // Two full pages plus a tail, so the flush has to walk more than one
    // dirty bit and the partial page keeps its untouched bytes.
    u32 span = 3 * 4096;
    u32 transferred = 0;
    for (u32 offset = 0; offset < span && valid; offset += 512) {
        u8 chunk[512];
        for (u32 index = 0; index < sizeof(chunk); index++)
            chunk[index] = (u8)(offset / 512 + index);
        if (vfs_write(opened, offset, chunk, sizeof(chunk), &transferred) ||
            transferred != sizeof(chunk))
            valid = 0;
    }

    // Write-back: neither the name nor the data reached the device. The
    // metadata stages with the pages and lands on the same flip, so the
    // volume on the platter is still the formatted one and carries no
    // "wide" to resolve.
    u32 size = 0;
    struct vfs_node_info info;
    struct adytumfs_superblock probe;
    u64 wide_inode = 0;
    valid = valid && !vfs_stat(opened, &info) && info.size == span &&
        !probe_read_block(dev, 0, adytumfs_probe_block) &&
        !adytumfs_super_unpack(&probe, adytumfs_probe_block) &&
        probe.format_version == ADYTUMFS_FORMAT_VERSION &&
        probe.total_blocks ==
            ADYTUMFS_TEST_SECTORS / ADYTUMFS_SECTORS_PER_BLOCK &&
        probe.root_inode == ADYTUMFS_ROOT_INODE &&
        probe.generation == 1;
    adytumfs_cas_open(&adytumfs_test_store, probe.index_start,
                      probe.index_blocks);
    valid = valid &&
        adytumfs_dir_lookup(dev, &probe, &adytumfs_test_store,
                            probe.root_inode, "wide", 4, &wide_inode) != 0;

    valid = valid && !vfs_sync(opened);

    // The flush landed: the name resolves, the inode describes the grown
    // file, and the extent blocks on the device hold the written pattern.
    valid = valid && !adytumfs_super_read(dev, &probe) &&
        !adytumfs_dir_lookup(dev, &probe, &adytumfs_test_store,
                             probe.root_inode, "wide", 4, &wide_inode) &&
        wide_inode;
    struct adytumfs_inode probe_inode;
    valid = valid &&
        !adytumfs_inode_read(dev, &probe, &adytumfs_test_store, wide_inode,
                             &probe_inode) &&
        (probe_inode.mode & ADYTUMFS_MODE_REG) &&
        probe_inode.size == span &&
        probe_inode.blocks == span / ADYTUMFS_BLOCK_SIZE;
    for (u64 logical = 0; logical < span / ADYTUMFS_BLOCK_SIZE && valid;
         logical++) {
        u64 physical = 0;
        valid = !adytumfs_inode_map(dev, &probe, &adytumfs_test_store,
                                    &probe_inode, logical, &physical) &&
            !probe_read_block(dev, physical, adytumfs_probe_block);
        for (u32 sector = 0;
             sector < ADYTUMFS_SECTORS_PER_BLOCK && valid; sector++)
            for (u32 index = 0; index < BLOCK_SECTOR_SIZE && valid; index++)
                if (adytumfs_probe_block[sector * BLOCK_SECTOR_SIZE + index] !=
                    (u8)(logical * ADYTUMFS_SECTORS_PER_BLOCK + sector + index))
                    valid = 0;
    }

    // Read it all back through a fresh cache after the remount below.
    u8 got[512];
    for (u32 offset = 0; offset < span && valid; offset += 512) {
        if (vfs_read(opened, offset, got, sizeof(got), &transferred) ||
            transferred != sizeof(got))
            valid = 0;
        for (u32 index = 0; index < sizeof(got) && valid; index++)
            if (got[index] != (u8)(offset / 512 + index)) valid = 0;
    }

    struct kernel_object *pages = opened ? vfs_file_pages(opened, &size) : 0;
    struct page_resource *resource = pages ? page_resource_get(pages) : 0;
    valid = valid && pages && resource && resource->pages >= span / 4096 &&
        size == span;
    if (pages) object_release(pages);

    if (opened) {
        object_release(opened);
        opened = 0;
    }
    if (node) {
        object_release(node);
        node = 0;
    }
    if (disk) {
        object_release(disk);
        disk = 0;
    }

    // Survives a remount: the flush really landed on the device.
    if (mnt && vfs_unmount(mnt)) valid = 0;
    if (mnt && vfs_mount_adytumfs(mnt, dev)) valid = 0;
    struct kernel_object *again = valid ? vfs_lookup(root, "pages") : 0;
    struct kernel_object *reopened_node = again ?
        vfs_lookup(again, "wide") : 0;
    struct kernel_object *reopened = reopened_node ?
        vfs_open(reopened_node) : 0;
    valid = valid && again && reopened_node && reopened;
    for (u32 offset = 0; offset < span && valid; offset += 512) {
        if (vfs_read(reopened, offset, got, sizeof(got), &transferred) ||
            transferred != sizeof(got))
            valid = 0;
        for (u32 index = 0; index < sizeof(got) && valid; index++)
            if (got[index] != (u8)(offset / 512 + index)) valid = 0;
    }

    if (reopened) object_release(reopened);
    if (reopened_node) object_release(reopened_node);
    if (again) object_release(again);
    if (mnt && vfs_unmount(mnt)) valid = 0;
    if (root) vfs_unlink(root, "pages");
    if (mnt) object_release(mnt);
    if (root) object_release(root);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

int test_adytumfs_policy64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    int valid = root != 0;

    // A dirent naming an inode the volume no longer backs must fail the mount
    // rather than surface a file with another inode's content. What catches
    // it is the volume audit, not a namespace walk: a zeroed inode fails its
    // own mode and size checks before any name is resolved.
    {
        struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
        struct kernel_object *point = root ?
            vfs_create(root, "policy", VFS_NODE_DIRECTORY) : 0;
        int ok = dev && point && !adytumfs_format(dev) &&
            !vfs_mount_adytumfs(point, dev);
        struct kernel_object *disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *node = disk ?
            vfs_create(disk, "hello", VFS_NODE_REGULAR) : 0;
        ok = ok && disk && node;
        if (node) object_release(node);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        struct adytumfs_superblock super;
        u64 target = 0;
        int sr = policy_super(dev, &super);
        int dl = sr ? -1 : adytumfs_dir_lookup(dev, &super,
                                               &adytumfs_test_store,
                                               super.root_inode, "hello", 5,
                                               &target);
        ok = ok && !sr && !dl && target;
        u64 zeroed = 0;
        u32 at = 0;
        ok = ok && !inode_item_at(dev, &super, &adytumfs_test_store, target,
                                  adytumfs_probe_block, &zeroed, &at);
        if (ok)
            for (u32 index = 0; index < ADYTUMFS_INODE_SIZE; index++)
                adytumfs_probe_block[at + index] = 0;
        ok = ok && !policy_commit(dev, zeroed) &&
            vfs_mount_adytumfs(point, dev) < 0;
        valid = valid && ok;
        if (point) object_release(point);
        if (root) vfs_unlink(root, "policy");
        if (dev) object_release(dev);
    }

    // A dirent whose type disagrees with the target inode means the tree
    // cannot be trusted, so the mount must fail.
    {
        struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
        struct kernel_object *point = root ?
            vfs_create(root, "policy", VFS_NODE_DIRECTORY) : 0;
        int ok = dev && point && !adytumfs_format(dev) &&
            !vfs_mount_adytumfs(point, dev);
        struct kernel_object *disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *node = disk ?
            vfs_create(disk, "hello", VFS_NODE_REGULAR) : 0;
        ok = ok && disk && node;
        if (node) object_release(node);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        struct adytumfs_superblock super;
        u64 hello = 0;
        ok = ok && !policy_super(dev, &super) &&
            !adytumfs_dir_lookup(dev, &super, &adytumfs_test_store,
                                 super.root_inode, "hello", 5, &hello) &&
            hello &&
            !policy_forge_dirent(dev, &super, super.root_inode, "hello", 5,
                                 hello, ADYTUMFS_DTYPE_DIR) &&
            !policy_land_super(dev, &super) &&
            vfs_mount_adytumfs(point, dev) < 0;
        valid = valid && ok;
        if (point) object_release(point);
        if (root) vfs_unlink(root, "policy");
        if (dev) object_release(dev);
    }

    // Two names for one directory stay structural corruption: a regular
    // inode's second name is a hard link now, but a directory can never
    // carry one, so the mount must fail.
    {
        struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
        struct kernel_object *point = root ?
            vfs_create(root, "policy", VFS_NODE_DIRECTORY) : 0;
        int ok = dev && point && !adytumfs_format(dev) &&
            !vfs_mount_adytumfs(point, dev);
        struct kernel_object *disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *first = disk ?
            vfs_create(disk, "a", VFS_NODE_DIRECTORY) : 0;
        struct kernel_object *second = disk ?
            vfs_create(disk, "b", VFS_NODE_DIRECTORY) : 0;
        ok = ok && disk && first && second;
        if (first) object_release(first);
        if (second) object_release(second);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        struct adytumfs_superblock super;
        u64 alias = 0;
        ok = ok && !policy_super(dev, &super) &&
            !adytumfs_dir_lookup(dev, &super, &adytumfs_test_store,
                                 super.root_inode, "a", 1,
                                 &alias) &&
            alias &&
            !policy_forge_dirent(dev, &super, super.root_inode, "b", 1, alias,
                                 ADYTUMFS_DTYPE_DIR) &&
            !policy_land_super(dev, &super) &&
            vfs_mount_adytumfs(point, dev) < 0;
        valid = valid && ok;
        if (point) object_release(point);
        if (root) vfs_unlink(root, "policy");
        if (dev) object_release(dev);
    }

    // An inode no dirent names is invisible, not fatal: the mount succeeds,
    // the orphan stays unreached, and the table still admits new files.
    {
        struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
        struct kernel_object *point = root ?
            vfs_create(root, "policy", VFS_NODE_DIRECTORY) : 0;
        int ok = dev && point && !adytumfs_format(dev) &&
            !vfs_mount_adytumfs(point, dev);
        struct kernel_object *disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *first = disk ?
            vfs_create(disk, "a", VFS_NODE_REGULAR) : 0;
        struct kernel_object *second = disk ?
            vfs_create(disk, "b", VFS_NODE_REGULAR) : 0;
        ok = ok && disk && first && second;
        if (first) object_release(first);
        if (second) object_release(second);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        struct adytumfs_superblock super;
        // The name goes out through the format layer, the way the reclaim
        // path drops it ahead of the inode. What survives is a real orphan
        // in a consistent volume, not a dirent forged behind the tree.
        ok = ok && !policy_super(dev, &super) &&
            !adytumfs_dir_remove(dev, &super, &adytumfs_test_store,
                                 super.root_inode, "b", 1) &&
            !adytumfs_commit(dev, &super, &adytumfs_test_store) && !block_cache_flush(dev);
        if (dev) block_cache_drop_device((u32)dev->value);
        ok = ok && !vfs_mount_adytumfs(point, dev);
        disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *kept = disk ? vfs_lookup(disk, "a") : 0;
        struct kernel_object *added = disk ?
            vfs_create(disk, "c", VFS_NODE_REGULAR) : 0;
        ok = ok && disk && kept && added && !vfs_lookup(disk, "b");
        if (added) object_release(added);
        if (kept) object_release(kept);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        valid = valid && ok;
        if (point) object_release(point);
        if (root) vfs_unlink(root, "policy");
        if (dev) object_release(dev);
    }

    // A volume carrying more files than the old mount's slot table held used
    // to be unmountable, and the file past the bound was dropped with it.
    // Nothing renumbers files now, so the mount succeeds and the last file
    // resolves like the first: the bound this block existed to prove is the
    // one that went away.
    {
        struct kernel_object *dev = block_create(ADYTUMFS_OVERRUN_SECTORS, 0);
        struct kernel_object *point = root ?
            vfs_create(root, "policy", VFS_NODE_DIRECTORY) : 0;
        int ok = dev && point && !adytumfs_format(dev) &&
            !vfs_mount_adytumfs(point, dev);
        struct kernel_object *disk = ok ? vfs_lookup(root, "policy") : 0;
        for (u32 index = 0; index < 127 && ok; index++) {
            char label[5];
            label[0] = 'f';
            label[1] = (char)('0' + index / 100);
            label[2] = (char)('0' + (index / 10) % 10);
            label[3] = (char)('0' + index % 10);
            label[4] = 0;
            struct kernel_object *node = disk ?
                vfs_create(disk, label, VFS_NODE_REGULAR) : 0;
            ok = node != 0;
            if (node) {
                // Creating a file stages two copy-on-write edits, an inode and
                // a directory entry, and nothing reclaims the generations they
                // supersede until a commit. Only a sync boundary commits, so a
                // volume this size has to be synced through the loop: without
                // it the allocations run out around a hundred files and the
                // overrun this block exists to prove never becomes reachable.
                struct kernel_object *file = vfs_open(node);
                ok = file && !vfs_fsync(file);
                if (file) object_release(file);
                object_release(node);
            }
        }
        ok = ok && disk;
        if (disk) object_release(disk);
        ok = ok && point && !vfs_unmount(point);
        struct adytumfs_superblock super;
        u64 extra = 0;
        ok = ok && !policy_super(dev, &super);
        ok = ok &&
            !adytumfs_inode_alloc(dev, &super, &adytumfs_test_store,
                                  (u16)(ADYTUMFS_MODE_REG | 0644u), &extra) &&
            extra;
        ok = ok &&
            !adytumfs_dir_add(dev, &super, &adytumfs_test_store,
                              super.root_inode, "extra", 5,
                              extra, ADYTUMFS_DTYPE_REG);
        ok = ok && !adytumfs_commit(dev, &super, &adytumfs_test_store);
        if (dev) block_cache_drop_device((u32)dev->value);
        ok = ok && !vfs_mount_adytumfs(point, dev);
        disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *first_file = disk ?
            vfs_lookup(disk, "f000") : 0;
        struct kernel_object *past_bound = disk ?
            vfs_lookup(disk, "extra") : 0;
        ok = ok && disk && first_file && past_bound;
        if (past_bound) object_release(past_bound);
        if (first_file) object_release(first_file);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        valid = valid && ok;
        if (point) object_release(point);
        if (root) vfs_unlink(root, "policy");
        if (dev) object_release(dev);
    }

    // Two names for one directory, built through the format layer so the
    // volume is structurally sound and the audit accepts it. A file may carry
    // many names, but a directory has one parent here, so the second name
    // resolves to nothing rather than giving the subtree two homes.
    {
        struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
        struct kernel_object *point = root ?
            vfs_create(root, "policy", VFS_NODE_DIRECTORY) : 0;
        int ok = dev && point && !adytumfs_format(dev) &&
            !vfs_mount_adytumfs(point, dev);
        struct kernel_object *disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *node = disk ?
            vfs_create(disk, "a", VFS_NODE_DIRECTORY) : 0;
        ok = ok && disk && node;
        if (node) object_release(node);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        struct adytumfs_superblock super;
        u64 target = 0;
        ok = ok && !policy_super(dev, &super) &&
            !adytumfs_dir_lookup(dev, &super, &adytumfs_test_store,
                                 super.root_inode, "a", 1, &target) &&
            target &&
            !adytumfs_dir_add(dev, &super, &adytumfs_test_store,
                              super.root_inode, "b", 1, target,
                              ADYTUMFS_DTYPE_DIR) &&
            !adytumfs_commit(dev, &super, &adytumfs_test_store);
        if (dev) block_cache_drop_device((u32)dev->value);
        ok = ok && !vfs_mount_adytumfs(point, dev);
        disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *first_name = disk ? vfs_lookup(disk, "a") : 0;
        struct kernel_object *second_name = disk ? vfs_lookup(disk, "b") : 0;
        ok = ok && disk && first_name && !second_name;
        if (second_name) object_release(second_name);
        if (first_name) object_release(first_name);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        valid = valid && ok;
        if (point) object_release(point);
        if (root) vfs_unlink(root, "policy");
        if (dev) object_release(dev);
    }

    // A volume may carry more names for one file than this VFS can record.
    // Nothing counts them at mount any more, so the mount succeeds and the
    // names past the alias bound simply do not resolve: a name the VFS
    // cannot record would be unlinked under another name's identity.
    {
        struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
        struct kernel_object *point = root ?
            vfs_create(root, "policy", VFS_NODE_DIRECTORY) : 0;
        int ok = dev && point && !adytumfs_format(dev) &&
            !vfs_mount_adytumfs(point, dev);
        struct kernel_object *disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *node = disk ?
            vfs_create(disk, "hello", VFS_NODE_REGULAR) : 0;
        ok = ok && disk && node;
        if (node) object_release(node);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        struct adytumfs_superblock super;
        u64 target = 0;
        ok = ok && !policy_super(dev, &super) &&
            !adytumfs_dir_lookup(dev, &super, &adytumfs_test_store,
                                 super.root_inode, "hello", 5,
                                 &target) &&
            target;
        for (u32 index = 0; ok && index <= VFS_ALIAS_MAX; index++) {
            char label[4];
            label[0] = 'l';
            label[1] = (char)('0' + index / 10);
            label[2] = (char)('0' + index % 10);
            label[3] = 0;
            ok = !adytumfs_dir_add(dev, &super, &adytumfs_test_store,
                                   super.root_inode, label, 3,
                                   target, ADYTUMFS_DTYPE_REG);
        }
        ok = ok && !adytumfs_commit(dev, &super, &adytumfs_test_store);
        if (dev) block_cache_drop_device((u32)dev->value);
        ok = ok && !vfs_mount_adytumfs(point, dev);
        disk = ok ? vfs_lookup(root, "policy") : 0;
        struct kernel_object *primary = disk ? vfs_lookup(disk, "hello") : 0;
        ok = ok && disk && primary;
        if (primary) object_release(primary);
        for (u32 index = 0; ok && index < VFS_ALIAS_MAX; index++) {
            char label[4];
            label[0] = 'l';
            label[1] = (char)('0' + index / 10);
            label[2] = (char)('0' + index % 10);
            label[3] = 0;
            struct kernel_object *found = vfs_lookup(disk, label);
            ok = found != 0;
            if (found) object_release(found);
        }
        if (ok && disk) {
            char label[4];
            label[0] = 'l';
            label[1] = (char)('0' + VFS_ALIAS_MAX / 10);
            label[2] = (char)('0' + VFS_ALIAS_MAX % 10);
            label[3] = 0;
            struct kernel_object *overflow = vfs_lookup(disk, label);
            ok = !overflow;
            if (overflow) object_release(overflow);
        }
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point);
        valid = valid && ok;
        if (point) object_release(point);
        if (root) vfs_unlink(root, "policy");
        if (dev) object_release(dev);
    }

    if (root) object_release(root);
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

// Payloads are short byte ramps so a leaked or overwritten page is caught by
// one comparison instead of a full buffer audit.
static void reuse_fill(u8 *buffer, u32 length, u8 base) {
    for (u32 index = 0; index < length; index++)
        buffer[index] = (u8)(base + index);
}

// A grown hole reads back as zeroes, which a ramp comparison cannot express.
static int checksum_zeroes(const u8 *buffer, u32 length) {
    for (u32 index = 0; index < length; index++)
        if (buffer[index]) return 0;
    return 1;
}

static int reuse_matches(const u8 *buffer, u32 length, u8 base) {
    for (u32 index = 0; index < length; index++)
        if (buffer[index] != (u8)(base + index)) return 0;
    return 1;
}

int test_adytumfs_reuse64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    int valid = root != 0;

    // A handle that outlives its unlink keeps its vnode, and the freed slot
    // can be reused by the next create. Every later backend call through the
    // stale handle must fail closed instead of reaching the new owner.
    {
        struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
        struct kernel_object *point = root ?
            vfs_create(root, "reuse", VFS_NODE_DIRECTORY) : 0;
        int ok = dev && point && !adytumfs_format(dev);
        ok = ok && !vfs_mount_adytumfs(point, dev);
        struct kernel_object *disk = ok ? vfs_lookup(root, "reuse") : 0;
        u32 mount_id = probe_mount();
        u32 used = 0, type = 0, size = 0, mode = 0, moved = 0;
        u64 reuse_root = 0;
        u64 reuse_generation = 0;
        u64 first_inode = 0;
        u64 second_inode = 0;
        u64 third_inode = 0;
        u64 fourth_inode = 0;
        if (mount_id)
            adytumfs_root_inode(mount_id, &reuse_root, &reuse_generation);
        u64 first_generation = 0;
        u64 second_generation = 0;
        u64 third_generation = 0;
        u64 fourth_generation = 0;
        u8 payload[16];
        u8 received[16];

        // An open descriptor holds the unlinked inode alive, so the number
        // is not handed back until the final close, and the data stays
        // readable through the descriptor for exactly as long as the
        // descriptor stays open.
        struct kernel_object *first = disk ?
            vfs_create(disk, "first", VFS_NODE_REGULAR) : 0;
        struct kernel_object *first_file = first ? vfs_open(first) : 0;
        reuse_fill(payload, sizeof(payload), 0x10);
        ok = ok && disk && mount_id && first && first_file &&
            !probe_find_in(mount_id, reuse_root, "first", &first_inode,
                           &used, &type, &size, &mode) &&
            used == 1 && first_inode;
        ok = ok &&
            !adytumfs_inode_get(mount_id, first_inode, &used, &type, &size,
                                &mode, &first_generation) &&
            used == 1 && first_generation;
        ok = ok &&
            !vfs_write(first_file, 0, payload, sizeof(payload), &moved) &&
            moved == sizeof(payload) && !vfs_sync(first_file);
        ok = ok && !vfs_unlink(disk, "first") &&
            !vfs_lookup(disk, "first") &&
            !vfs_read(first_file, 0, received, sizeof(received), &moved) &&
            moved == sizeof(received) &&
            reuse_matches(received, sizeof(received), 0x10);
        if (first_file) {
            object_release(first_file);
            first_file = 0;
        }
        if (first) {
            object_release(first);
            first = 0;
        }
        struct kernel_object *second = disk ?
            vfs_create(disk, "second", VFS_NODE_REGULAR) : 0;
        struct kernel_object *second_file = second ? vfs_open(second) : 0;
        reuse_fill(payload, sizeof(payload), 0x20);
        // The allocation is a high-water mark, so the file created after
        // the reclaim takes a fresh number rather than the reclaimed one,
        // and a handle still holding the old pair cannot reach it.
        ok = ok && second && second_file &&
            !probe_find_in(mount_id, reuse_root, "second", &second_inode,
                           &used, &type, &size, &mode) &&
            used == 1 && second_inode && second_inode != first_inode &&
            !adytumfs_inode_get(mount_id, second_inode, &used, &type, &size,
                                &mode, &second_generation) &&
            second_generation && second_generation != first_generation &&
            !adytumfs_inode_get(mount_id, first_inode, &used, &type, &size,
                                &mode, 0) &&
            !used;
        ok = ok &&
            !vfs_write(second_file, 0, payload, sizeof(payload), &moved) &&
            moved == sizeof(payload) && !vfs_sync(second_file) &&
            !vfs_read(second_file, 0, received, sizeof(received), &moved) &&
            moved == sizeof(received) &&
            reuse_matches(received, sizeof(received), 0x20);
        // The grown write lands on the slot whose previous life ended in a
        // deferred release, and the dirty page reaches the disk.
        reuse_fill(payload, sizeof(payload), 0x30);
        ok = ok && !vfs_write(second_file, 4096, payload, sizeof(payload),
                              &moved) &&
            moved == sizeof(payload) && !vfs_sync(second_file) &&
            !vfs_read(second_file, 4096, received, sizeof(received), &moved) &&
            moved == sizeof(received) &&
            reuse_matches(received, sizeof(received), 0x30);

        // A handle that never touched the disk still holds its inode past
        // the unlink, so the number cannot be handed out under a live
        // descriptor and the write-through-a-stale-cache hazard cannot
        // arise in the first place.
        struct kernel_object *third = disk ?
            vfs_create(disk, "third", VFS_NODE_REGULAR) : 0;
        struct kernel_object *third_file = third ? vfs_open(third) : 0;
        ok = ok && third && third_file &&
            !probe_find_in(mount_id, reuse_root, "third", &third_inode,
                           &used, &type, &size, &mode) &&
            used == 1 &&
            !adytumfs_inode_get(mount_id, third_inode, &used, &type, &size,
                                &mode, &third_generation) &&
            third_generation &&
            !vfs_unlink(disk, "third") &&
            !vfs_read(third_file, 0, received, sizeof(received), &moved) &&
            moved == 0;
        if (third_file) {
            object_release(third_file);
            third_file = 0;
        }
        if (third) {
            object_release(third);
            third = 0;
        }
        struct kernel_object *fourth = disk ?
            vfs_create(disk, "fourth", VFS_NODE_REGULAR) : 0;
        struct kernel_object *fourth_file = fourth ? vfs_open(fourth) : 0;
        reuse_fill(payload, sizeof(payload), 0x50);
        ok = ok && fourth && fourth_file &&
            !probe_find_in(mount_id, reuse_root, "fourth", &fourth_inode,
                           &used, &type, &size, &mode) &&
            used == 1 && fourth_inode && fourth_inode != third_inode &&
            !adytumfs_inode_get(mount_id, fourth_inode, &used, &type, &size,
                                &mode, &fourth_generation) &&
            fourth_generation && fourth_generation != third_generation;
        ok = ok && !vfs_write(fourth_file, 0, payload, sizeof(payload),
                              &moved) &&
            moved == sizeof(payload) && !vfs_sync(fourth_file) &&
            !vfs_read(fourth_file, 0, received, sizeof(received), &moved) &&
            moved == sizeof(received) &&
            reuse_matches(received, sizeof(received), 0x50);

        if (fourth_file) object_release(fourth_file);
        if (fourth) object_release(fourth);
        if (second_file) object_release(second_file);
        if (second) object_release(second);
        if (disk) object_release(disk);
        ok = ok && !vfs_unmount(point) && !vfs_mount_adytumfs(point, dev);
        struct kernel_object *fresh = ok ? vfs_lookup(root, "reuse") : 0;
        struct kernel_object *kept_second = fresh ?
            vfs_lookup(fresh, "second") : 0;
        struct kernel_object *kept_fourth = fresh ?
            vfs_lookup(fresh, "fourth") : 0;
        struct kernel_object *second_read = kept_second ?
            vfs_open(kept_second) : 0;
        struct kernel_object *fourth_read = kept_fourth ?
            vfs_open(kept_fourth) : 0;
        ok = ok && fresh && kept_second && kept_fourth && second_read &&
            fourth_read && !vfs_lookup(fresh, "first") &&
            !vfs_lookup(fresh, "third") &&
            !vfs_read(second_read, 0, received, sizeof(received), &moved) &&
            moved == sizeof(received) &&
            reuse_matches(received, sizeof(received), 0x20) &&
            !vfs_read(second_read, 4096, received, sizeof(received), &moved) &&
            moved == sizeof(received) &&
            reuse_matches(received, sizeof(received), 0x30) &&
            !vfs_read(fourth_read, 0, received, sizeof(received), &moved) &&
            moved == sizeof(received) &&
            reuse_matches(received, sizeof(received), 0x50);
        if (second_read) object_release(second_read);
        if (fourth_read) object_release(fourth_read);
        if (kept_second) object_release(kept_second);
        if (kept_fourth) object_release(kept_fourth);
        if (fresh) object_release(fresh);
        ok = ok && !vfs_unmount(point);
        valid = valid && ok;
        if (point) object_release(point);
        if (root) vfs_unlink(root, "reuse");
        if (dev) object_release(dev);
    }

    if (root) object_release(root);
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

// Stage the baseline every integrity scenario corrupts: one volume, two
// one-block files, written and synced through the VFS, then unmounted, so the
// on-disk state is exactly what a clean session leaves behind. Returns 0 with
// the device, the mount point, the parsed superblock, and both file inodes.
static int integrity_stage(struct kernel_object *root,
                           struct kernel_object **dev_out,
                           struct kernel_object **point_out,
                           struct adytumfs_superblock *super,
                           u64 *data_inode, u64 *other_inode) {
    struct kernel_object *dev = block_create(ADYTUMFS_TEST_SECTORS, 0);
    struct kernel_object *point = root ?
        vfs_create(root, "integrity", VFS_NODE_DIRECTORY) : 0;
    int ok = dev && point && !adytumfs_format(dev) &&
        !vfs_mount_adytumfs(point, dev);
    struct kernel_object *disk = ok ? vfs_lookup(root, "integrity") : 0;
    struct kernel_object *data = disk ?
        vfs_create_mode(disk, "data", VFS_NODE_REGULAR, 0600) : 0;
    struct kernel_object *other = disk ?
        vfs_create_mode(disk, "other", VFS_NODE_REGULAR, 0600) : 0;
    struct kernel_object *data_file = data ? vfs_open(data) : 0;
    struct kernel_object *other_file = other ? vfs_open(other) : 0;
    u32 moved = 0;
    u8 payload[16];
    reuse_fill(payload, sizeof(payload), 0x60);
    ok = ok && data && other && data_file && other_file &&
        !vfs_write(data_file, 0, payload, sizeof(payload), &moved) &&
        moved == sizeof(payload) && !vfs_sync(data_file);
    ok = ok && !vfs_write(other_file, 0, payload, sizeof(payload), &moved) &&
        moved == sizeof(payload) && !vfs_sync(other_file);
    if (data_file) object_release(data_file);
    if (other_file) object_release(other_file);
    if (data) object_release(data);
    if (other) object_release(other);
    if (disk) object_release(disk);
    ok = ok && point && !vfs_unmount(point);
    ok = ok && !policy_super(dev, super);
    ok = ok &&
        !adytumfs_dir_lookup(dev, super, &adytumfs_test_store,
                             super->root_inode, "data", 4,
                             data_inode) && *data_inode;
    ok = ok &&
        !adytumfs_dir_lookup(dev, super, &adytumfs_test_store,
                             super->root_inode, "other", 5,
                             other_inode) && *other_inode;
    if (!ok) {
        if (point) object_release(point);
        if (dev) object_release(dev);
        return -1;
    }
    *dev_out = dev;
    *point_out = point;
    return 0;
}

// The block a file's first byte lives in, and the hash that block is keyed by
// in the index. A corruption scenario forges the index rather than the inode
// now, because the index is what names locations, and it is keyed by content,
// so the key has to be recovered the way the filesystem computed it.
static int integrity_first_block(struct kernel_object *dev,
                                 struct adytumfs_superblock *super, u64 inode,
                                 u64 *block, u8 hash[ADYTUMFS_HASH_SIZE]) {
    struct adytumfs_inode in;
    if (adytumfs_inode_read(dev, super, &adytumfs_test_store, inode, &in))
        return -1;
    if (adytumfs_inode_map(dev, super, &adytumfs_test_store, &in, 0, block))
        return -1;
    if (adytumfs_block_read(dev, *block, adytumfs_probe_block)) return -1;
    return blake2b(hash, ADYTUMFS_HASH_SIZE, adytumfs_probe_block,
                   ADYTUMFS_BLOCK_SIZE);
}

// Land the open window through the commit protocol and drop the cached
// copies, so the next mount reads the bytes the way a fresh boot would.
static int integrity_commit(struct kernel_object *dev,
                            struct adytumfs_superblock *super) {
    // The commit lands the window and skips itself when nothing staged, so
    // the flush after it is what carries raw device edits to the platter
    // before the drop throws the cached copies away.
    if (adytumfs_commit(dev, super, &adytumfs_test_store) || block_cache_flush(dev)) return -1;
    block_cache_drop_device((u32)dev->value);
    return 0;
}

static void integrity_cleanup(struct kernel_object *root,
                              struct kernel_object *point,
                              struct kernel_object *dev) {
    if (point) object_release(point);
    if (root) vfs_unlink(root, "integrity");
    // Drop any window still open, so a later device object that reuses this
    // address cannot inherit its staging.
    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
}

int test_adytumfs_integrity64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    int valid = root != 0;
    struct adytumfs_superblock super;
    u64 data_inode = 0;
    u64 other_inode = 0;
    struct adytumfs_inode in;
    struct kernel_object *dev = 0;
    struct kernel_object *point = 0;
    u64 claimed_block = 0;
    u64 forged_node = 0;
    u64 leak = 0;
    u32 item_at = 0;
    int ok = 0;

    // A forged extent into the metadata prefix would alias the superblock or
    // the inode table through a regular file.
    u8 key[ADYTUMFS_HASH_SIZE];
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !adytumfs_inode_read(dev, &super, &adytumfs_test_store, data_inode,
                             &in) && in.blocks == 1 &&
        !integrity_first_block(dev, &super, data_inode, &claimed_block, key) &&
        !adytumfs_index_repoint(dev, &adytumfs_test_store.index, key,
                                0) &&
        // The lie is confined to the index: the block still holds the content
        // its own hash names, so the mount rebuilds the mapping and takes the
        // volume. The prefix cannot come back in the rebuilt index, because
        // the scan that fills it stops at the allocatable span.
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) == 0 &&
        !vfs_unmount(point);
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // The backup superblock block is never allocatable either.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !integrity_first_block(dev, &super, data_inode, &claimed_block, key) &&
        !adytumfs_index_repoint(dev, &adytumfs_test_store.index, key,
                                super.total_blocks - 1) &&
        // Same shape as the prefix forgery: the shadow tail is outside the
        // span the rebuild scans, so the true mapping is what comes back.
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) == 0 &&
        !vfs_unmount(point);
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // Two mappings naming one block would let two files write through a
    // single allocation behind each other's backs. The audit catches it
    // without comparing them pairwise: one more mapping than there are
    // allocated blocks is the disagreement. The rebuild then settles it
    // rather than merely refusing it: the block is rehashed once, so the twin
    // no tree names is dropped and the count comes back to the truth.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !integrity_first_block(dev, &super, data_inode, &claimed_block, key);
    if (ok) key[0] ^= 0xffu;
    ok = ok &&
        !adytumfs_index_insert(dev, &adytumfs_test_store.index, key,
                               claimed_block) &&
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) == 0 &&
        !vfs_unmount(point);
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // A mapping on a bit the bitmap says is free means the allocator would
    // hand that block to a second owner.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !integrity_first_block(dev, &super, data_inode, &claimed_block, key) &&
        !adytumfs_block_read(dev, adytumfs_bitmap_block(&super, 0),
                             adytumfs_probe_block);
    if (ok)
        adytumfs_probe_block[claimed_block / 8] &=
            (u8)~(1u << (claimed_block % 8));
    ok = ok && !adytumfs_block_write(dev, adytumfs_bitmap_block(&super, 0),
                                     adytumfs_probe_block) &&
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) < 0;
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // An allocated bit no extent owns is a leak the volume must not paper
    // over.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !adytumfs_block_read(dev, adytumfs_bitmap_block(&super, 0),
                             adytumfs_probe_block);
    if (ok) {
        for (leak = super.data_start; leak < super.total_blocks - 1; leak++)
            if (!(adytumfs_probe_block[leak / 8] &
                  (u8)(1u << (leak % 8))))
                break;
        ok = leak < super.total_blocks - 1;
        if (ok)
            adytumfs_probe_block[leak / 8] |= (u8)(1u << (leak % 8));
    }
    ok = ok && !adytumfs_block_write(dev, adytumfs_bitmap_block(&super, 0),
                                     adytumfs_probe_block) &&
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) < 0;
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // The block count must equal the bytes the extent tree covers, or reads
    // clamp to a lie.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !adytumfs_inode_read(dev, &super, &adytumfs_test_store, data_inode,
                             &in);
    if (ok) in.blocks = 2;
    ok = ok && !adytumfs_inode_write(dev, &super, &adytumfs_test_store,
                                     data_inode, &in) &&
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) < 0;
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // The v2 case for an extent sitting behind the zero length terminator has
    // no v3 counterpart, and that is the point rather than an omission: a
    // zero length entry is unrepresentable, so there is no terminator to put
    // anything behind and no layout of this kind to refuse.

    // The mount root is a directory; anything else would have file data
    // parsed as directory records.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !adytumfs_inode_read(dev, &super, &adytumfs_test_store,
                             super.root_inode, &in);
    if (ok) in.mode = ADYTUMFS_MODE_REG | 0755u;
    ok = ok && !adytumfs_inode_write(dev, &super, &adytumfs_test_store,
                                     super.root_inode, &in) &&
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) < 0;
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // The free block counter must state what a bitmap scan finds.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode);
    if (ok) super.free_blocks += 1;
    if (ok) adytumfs_super_pack(adytumfs_probe_block, &super);
    ok = ok && !adytumfs_block_write(dev, adytumfs_superblock_block(&super),
                                     adytumfs_probe_block) &&
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) < 0;
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // So must the live inode counter.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode);
    if (ok) super.live_inodes -= 1;
    if (ok) adytumfs_super_pack(adytumfs_probe_block, &super);
    ok = ok && !adytumfs_block_write(dev, adytumfs_superblock_block(&super),
                                     adytumfs_probe_block) &&
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) < 0;
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // An orphaned file still owns its blocks, so a consistent volume with an
    // unreachable inode must keep mounting.
    // The name goes out through the format layer, so the orphan is one the
    // reclaim path could really have left behind: the tree and its hashes
    // agree, and only the inode is unreachable.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !adytumfs_dir_remove(dev, &super, &adytumfs_test_store,
                             super.root_inode, "data", 4) &&
        !integrity_commit(dev, &super) &&
        !vfs_mount_adytumfs(point, dev);
    struct kernel_object *disk = ok ? vfs_lookup(root, "integrity") : 0;
    struct kernel_object *kept = disk ? vfs_lookup(disk, "other") : 0;
    ok = ok && disk && kept && !vfs_lookup(disk, "data");
    if (kept) object_release(kept);
    if (disk) object_release(disk);
    ok = ok && !vfs_unmount(point);
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    // A damaged item means the tree itself is lying, reachable or not.
    ok = !integrity_stage(root, &dev, &point, &super, &data_inode,
                          &other_inode) &&
        !adytumfs_dir_remove(dev, &super, &adytumfs_test_store,
                             super.root_inode, "data", 4) &&
        !integrity_commit(dev, &super);
    // The name is out and landed before the node is touched, so the broken
    // item is the only lie left on the volume and the failure has to belong
    // to it.
    ok = ok && !inode_item_at(dev, &super, &adytumfs_test_store, data_inode,
                              adytumfs_probe_block, &forged_node, &item_at);
    if (ok) adytumfs_probe_block[item_at + 100] ^= 0xffu;
    ok = ok && !adytumfs_block_write(dev, forged_node, adytumfs_probe_block) &&
        !block_cache_flush(dev);
    if (dev) block_cache_drop_device((u32)dev->value);
    ok = ok && vfs_mount_adytumfs(point, dev) < 0;
    valid = valid && ok;
    integrity_cleanup(root, point, dev);

    if (root) object_release(root);
    if (object_active_count() != objects) {
    }
    if (vfs_node_active_count() != nodes) {
    }
    if (vfs_file_active_count() != files) {
    }
    if (vfs_mount_active_count() != mounts) {
    }
    if (block_active_count() != devices) {
    }
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

int test_adytumfs_checksum64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    struct kernel_object *dev = 0;
    struct kernel_object *point = 0;
    struct adytumfs_superblock super;
    u64 data_inode = 0;
    u64 other_inode = 0;
    int valid = !integrity_stage(root, &dev, &point, &super, &data_inode,
                                 &other_inode);
    u8 payload[16];
    u8 received[32];
    u64 moved = 0;

    // A clean volume reads back through the verified path: both staged files
    // hand their bytes over with the region vouching for every block.
    valid = valid && !adytumfs_file_read(dev, &super, &adytumfs_test_store,
                                         data_inode, 0, received,
                                         16, &moved) &&
        moved == 16 && reuse_matches(received, 16, 0x60) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, other_inode, 0,
                            received, 16,
                            &moved) &&
        moved == 16 && reuse_matches(received, 16, 0x60);

    // Flip one data byte behind the filesystem's back: the mount still
    // succeeds (the metadata views agree), but the read must refuse the
    // bytes rather than serve silent corruption.
    struct adytumfs_inode in;
    u64 physical = 0;
    valid = valid && !adytumfs_inode_read(dev, &super, &adytumfs_test_store,
                                          data_inode, &in) &&
        !adytumfs_inode_map(dev, &super, &adytumfs_test_store, &in, 0,
                            &physical) &&
        !adytumfs_block_read(dev, physical, adytumfs_probe_block);
    if (valid) adytumfs_probe_block[8] ^= 0xffu;
    valid = valid && !adytumfs_block_write(dev, physical,
                                           adytumfs_probe_block) &&
        !integrity_commit(dev, &super) &&
        adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 0,
                           received, 16,
                           &moved) < 0;
    if (valid) adytumfs_probe_block[8] ^= 0xffu;
    valid = valid && !adytumfs_block_write(dev, physical,
                                           adytumfs_probe_block) &&
        !integrity_commit(dev, &super) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 0,
                            received, 16,
                            &moved);

    // Flip the region entry instead. The region no longer vouches for
    // content, the hash the parent records does, and the bytes below are
    // intact, so the read has to serve them. A later step drops the region
    // from the format altogether; until then this pins where authority sits.
    u64 index = physical - super.data_start;
    u64 region_block = super.data_end +
        index / ADYTUMFS_CHECKSUMS_PER_BLOCK;
    u32 entry = (u32)(index % ADYTUMFS_CHECKSUMS_PER_BLOCK) * 4u;
    valid = valid && !adytumfs_block_read(dev, region_block,
                                          adytumfs_probe_block);
    if (valid) adytumfs_probe_block[entry] ^= 0x1u;
    valid = valid && !adytumfs_block_write(dev, region_block,
                                           adytumfs_probe_block) &&
        !integrity_commit(dev, &super) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 0,
                            received, 16, &moved) &&
        moved == 16 && reuse_matches(received, 16, 0x60);
    if (valid) adytumfs_probe_block[entry] ^= 0x1u;
    valid = valid && !adytumfs_block_write(dev, region_block,
                                           adytumfs_probe_block) &&
        !integrity_commit(dev, &super);

    // The write paths seal what they write: an overwrite through the file
    // path, a partial block read-modify-write, and a grow whose fresh blocks
    // must read back as zeroed holes with their own sealed entries.
    reuse_fill(payload, sizeof(payload), 0xa0);
    valid = valid && !adytumfs_file_write(dev, &super, &adytumfs_test_store,
                                          data_inode, 0, payload,
                                          sizeof(payload), &moved) &&
        moved == sizeof(payload) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 0,
                            received, 16, &moved) &&
        moved == 16 && reuse_matches(received, 16, 0xa0);
    reuse_fill(payload, sizeof(payload), 0xb0);
    valid = valid && !adytumfs_file_write(dev, &super, &adytumfs_test_store,
                                          data_inode, 4, payload,
                                          8, &moved) &&
        moved == 8 &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 0,
                            received, 16, &moved) &&
        moved == 16 && received[0] == 0xa0u && received[3] == 0xa3u &&
        received[4] == 0xb0u && received[11] == 0xb7u && received[12] == 0xacu;
    reuse_fill(payload, sizeof(payload), 0xc0);
    valid = valid && !adytumfs_file_write(dev, &super, &adytumfs_test_store,
                                          data_inode, 8192,
                                          payload, sizeof(payload), &moved) &&
        moved == sizeof(payload) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 4096,
                            received, 16,
                           &moved) &&
        moved == 16 && checksum_zeroes(received, 16) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 8192,
                            received, 16,
                           &moved) &&
        moved == 16 && reuse_matches(received, 16, 0xc0);
    valid = valid && !integrity_commit(dev, &super);

    // The page path and the mount walk go through the same region: a VFS
    // mount, open, read, and clean unmount of the grown file must work with
    // every block still verified.
    valid = valid && !vfs_mount_adytumfs(point, dev);
    struct kernel_object *disk = valid ? vfs_lookup(root, "integrity") : 0;
    struct kernel_object *node = disk ? vfs_lookup(disk, "data") : 0;
    struct kernel_object *opened = node ? vfs_open(node) : 0;
    u32 transferred = 0;
    valid = valid && opened &&
        !vfs_read(opened, 0, received, 16, &transferred) &&
        transferred == 16 && received[0] == 0xa0u && received[3] == 0xa3u &&
        received[4] == 0xb0u && received[11] == 0xb7u && received[12] == 0xacu;
    if (opened) {
        object_release(opened);
        opened = 0;
    }
    if (node) {
        object_release(node);
        node = 0;
    }
    if (disk) {
        object_release(disk);
        disk = 0;
    }
    valid = valid && point && !vfs_unmount(point);

    // A flipped byte in the node holding the directory's entries must fail the
    // mount itself: the walk resolves every node through the verified path, and
    // a directory is an item in the tree now rather than a block of packed
    // entries, so the byte that used to sit in a dirent sits in a leaf. The
    // offset is past the node header and the first slot's key, which puts it in
    // the entry's own bytes where a real corruption would land.
    u64 leaf = 0;
    valid = valid && !adytumfs_cas_lookup(dev, &super, &adytumfs_test_store,
                                          super.inode_root, &leaf) &&
        !adytumfs_block_read(dev, leaf, adytumfs_probe_block);
    if (valid) adytumfs_probe_block[56] ^= 0x80u;
    valid = valid && !adytumfs_block_write(dev, leaf, adytumfs_probe_block) &&
        !integrity_commit(dev, &super) && vfs_mount_adytumfs(point, dev) < 0;
    if (valid) adytumfs_probe_block[56] ^= 0x80u;
    valid = valid && !adytumfs_block_write(dev, leaf, adytumfs_probe_block) &&
        !integrity_commit(dev, &super);

    integrity_cleanup(root, point, dev);
    if (root) object_release(root);
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}

int test_adytumfs_cow64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    struct kernel_object *dev = 0;
    struct kernel_object *point = 0;
    struct adytumfs_superblock super;
    u64 data_inode = 0;
    u64 other_inode = 0;
    int valid = !integrity_stage(root, &dev, &point, &super, &data_inode,
                                 &other_inode);
    u8 payload[16];
    u8 received[32];
    u64 moved = 0;
    struct adytumfs_inode in;
    u64 physical = 0;
    u64 fresh_physical = 0;
    struct adytumfs_superblock probe_super;
    u64 free_before = 0;

    // Overwriting a mapped block must leave the old bytes untouched on the
    // device and reroute the extent to a fresh block. The free count drops by
    // two and nothing comes back: the sibling file was staged with the same
    // bytes, so the image being written over is still named, and because the
    // two files hold one entry each under the same key the leaf that names it
    // is byte for byte the same node and is shared too. Content addressing
    // deduplicates the tree, not just the data.
    valid = valid && !adytumfs_inode_read(dev, &super, &adytumfs_test_store,
                                          data_inode, &in) &&
        !adytumfs_inode_map(dev, &super, &adytumfs_test_store, &in, 0,
                            &physical) &&
        !probe_read_block(dev, physical, adytumfs_probe_block) &&
        reuse_matches(adytumfs_probe_block, 16, 0x60) &&
        !policy_super(dev, &probe_super);
    free_before = probe_super.free_blocks;
    reuse_fill(payload, sizeof(payload), 0xa0);
    valid = valid && !adytumfs_file_write(dev, &super, &adytumfs_test_store,
                                          data_inode, 0, payload,
                                          sizeof(payload), &moved) &&
        moved == sizeof(payload) &&
        !adytumfs_inode_read(dev, &super, &adytumfs_test_store, data_inode,
                             &in) &&
        !adytumfs_inode_map(dev, &super, &adytumfs_test_store, &in, 0,
                            &fresh_physical) &&
        fresh_physical != physical &&
        !probe_read_block(dev, physical, adytumfs_probe_block) &&
        reuse_matches(adytumfs_probe_block, 16, 0x60) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 0,
                            received, 16, &moved) &&
        moved == 16 && reuse_matches(received, 16, 0xa0) &&
        !policy_super(dev, &probe_super) &&
        free_before - super.free_blocks == 2u;

    // A partial block read-modify-write redirects the same way: the previous
    // image survives at the old physical block and the merge reads back.
    // The probes below read the raw device, so the cache has to land first.
    valid = valid && !integrity_commit(dev, &super) &&
        !adytumfs_inode_map(dev, &super, &adytumfs_test_store, &in, 0,
                            &physical) &&
        !probe_read_block(dev, physical, adytumfs_probe_block) &&
        reuse_matches(adytumfs_probe_block, 16, 0xa0);
    reuse_fill(payload, sizeof(payload), 0xb0);
    valid = valid && !adytumfs_file_write(dev, &super, &adytumfs_test_store,
                                          data_inode, 4, payload,
                                          8, &moved) &&
        moved == 8 &&
        !integrity_commit(dev, &super) &&
        !probe_read_block(dev, physical, adytumfs_probe_block) &&
        reuse_matches(adytumfs_probe_block, 16, 0xa0) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 0,
                            received, 16, &moved) &&
        moved == 16 && received[0] == 0xa0u && received[3] == 0xa3u &&
        received[4] == 0xb0u && received[11] == 0xb7u && received[12] == 0xacu;

    // Repeated overwrites must not leak: every redirect returns the previous
    // block to the pool, so the free count stays where it started.
    u8 ramp_base = 0xc0;
    for (u32 round = 0; valid && round < 4; round++) {
        reuse_fill(payload, sizeof(payload), ramp_base);
        valid = !adytumfs_file_write(dev, &super, &adytumfs_test_store,
                                     data_inode, 0, payload,
                                     sizeof(payload), &moved) &&
            moved == sizeof(payload) &&
            !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode,
                                0, received, 16,
                               &moved) &&
            moved == 16 && reuse_matches(received, 16, ramp_base);
        ramp_base = (u8)(ramp_base + 0x10u);
    }
    // Every one of those overwrites replaced content only this file named,
    // and this file's leaf has been its own since the first redirect, so each
    // redirect gave back exactly what it took and the count is where that
    // redirect left it: two short of the staged volume, which are the block
    // and the leaf the sibling still holds.
    valid = valid && !policy_super(dev, &probe_super) &&
        free_before - super.free_blocks == 2u;

    // Redirecting the middle block of a multi-block extent splits it; the
    // untouched neighbours must keep reading their images through the split.
    reuse_fill(adytumfs_probe_block, ADYTUMFS_BLOCK_SIZE, 0xd1);
    valid = valid && !adytumfs_file_write(dev, &super, &adytumfs_test_store,
                                          data_inode, 4096,
                                          adytumfs_probe_block,
                                          ADYTUMFS_BLOCK_SIZE, &moved) &&
        moved == ADYTUMFS_BLOCK_SIZE &&
        !adytumfs_file_write(dev, &super, &adytumfs_test_store, data_inode,
                             8192,
                             adytumfs_probe_block, ADYTUMFS_BLOCK_SIZE,
                             &moved) &&
        moved == ADYTUMFS_BLOCK_SIZE &&
        !adytumfs_inode_read(dev, &super, &adytumfs_test_store, data_inode,
                             &in) &&
        !adytumfs_inode_map(dev, &super, &adytumfs_test_store, &in, 1,
                            &physical);
    reuse_fill(payload, sizeof(payload), 0xe0);
    valid = valid && !adytumfs_file_write(dev, &super, &adytumfs_test_store,
                                          data_inode, 4096,
                                          payload, sizeof(payload), &moved) &&
        moved == sizeof(payload) && !integrity_commit(dev, &super) &&
        !probe_read_block(dev, physical, adytumfs_probe_block) &&
        reuse_matches(adytumfs_probe_block, 16, 0xd1) &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode, 4096,
                            received, 32,
                            &moved) &&
        moved == 32 && reuse_matches(received, 16, 0xe0) &&
        received[16] == 0xe1u && received[31] == 0xf0u &&
        !adytumfs_file_read(dev, &super, &adytumfs_test_store, data_inode,
                            8192 + 16, received, 16,
                            &moved) &&
        moved == 16 && reuse_matches(received, 16, 0xe1);

    // The page-cache write-back redirects too: a VFS write of a mounted file
    // leaves the original physical block untouched and reads back new.
    valid = valid && !vfs_mount_adytumfs(point, dev);
    {
        struct kernel_object *disk = valid ? vfs_lookup(root, "integrity") : 0;
        struct kernel_object *node = disk ? vfs_lookup(disk, "other") : 0;
        struct kernel_object *opened = node ? vfs_open(node) : 0;
        struct adytumfs_superblock live;
        u64 other_num = 0;
        valid = valid && opened &&
            !policy_super(dev, &live) &&
            !adytumfs_dir_lookup(dev, &live, &adytumfs_test_store,
                                 live.root_inode, "other", 5, &other_num) &&
            !adytumfs_inode_read(dev, &live, &adytumfs_test_store, other_num,
                                 &in) &&
            !adytumfs_inode_map(dev, &live, &adytumfs_test_store, &in, 0,
                                &physical) &&
            !probe_read_block(dev, physical, adytumfs_probe_block) &&
            reuse_matches(adytumfs_probe_block, 16, 0x60);
        reuse_fill(payload, sizeof(payload), 0xd0);
        u32 transferred = 0;
        valid = valid && !vfs_write(opened, 0, payload, sizeof(payload),
                                    &transferred) &&
            transferred == sizeof(payload) && !vfs_sync(opened) &&
            !probe_read_block(dev, physical, adytumfs_probe_block) &&
            reuse_matches(adytumfs_probe_block, 16, 0x60);
        if (opened) object_release(opened);
        if (node) object_release(node);
        if (disk) object_release(disk);
    }
    valid = valid && point && !vfs_unmount(point);
    valid = valid && !vfs_mount_adytumfs(point, dev);
    {
        struct kernel_object *disk = valid ? vfs_lookup(root, "integrity") : 0;
        struct kernel_object *node = disk ? vfs_lookup(disk, "other") : 0;
        struct kernel_object *opened = node ? vfs_open(node) : 0;
        u32 transferred = 0;
        valid = valid && opened &&
            !vfs_read(opened, 0, received, 16, &transferred) &&
            transferred == 16 && reuse_matches(received, 16, 0xd0);
        if (opened) object_release(opened);
        if (node) object_release(node);
        if (disk) object_release(disk);
    }
    valid = valid && point && !vfs_unmount(point);

    // The removal is copy on write, so the generation the device still names
    // keeps resolving the name until the commit that supersedes it. Reading
    // the superblock back off the device rather than reusing the one the
    // removal updated is what makes that a statement about the device and not
    // about the copy in memory, which is the property a crash between the two
    // depends on.
    valid = valid && !adytumfs_super_read(dev, &super) &&
        !adytumfs_dir_remove(dev, &super, &adytumfs_test_store,
                             super.root_inode, "data", 4);
    // The removal is copy on write, so the generation the device still names
    // keeps resolving the name until a commit supersedes it. Reading the
    // superblock back off the device rather than reusing the one the removal
    // updated is what makes that a statement about the device and not about
    // the copy in memory, which is what a crash between the two relies on.
    struct adytumfs_superblock on_device;
    u64 survivor = 0;
    valid = valid && !adytumfs_super_read(dev, &on_device) &&
        !adytumfs_dir_lookup(dev, &on_device, &adytumfs_test_store,
                             on_device.root_inode, "data", 4, &survivor) &&
        survivor == data_inode;
    valid = valid &&
        adytumfs_dir_lookup(dev, &super, &adytumfs_test_store, super.root_inode,
                            "data", 4,
                            &data_inode) < 0 &&
        !adytumfs_dir_lookup(dev, &super, &adytumfs_test_store,
                             super.root_inode, "other", 5,
                             &other_inode) &&
        other_inode;

    // The steady state must still verify: the remount walks and audits the
    // whole volume, so a leaked or lost block fails here.
    valid = valid && !integrity_commit(dev, &super) && !vfs_mount_adytumfs(point, dev);
    {
        struct kernel_object *disk = valid ? vfs_lookup(root, "integrity") : 0;
        struct kernel_object *kept = disk ? vfs_lookup(disk, "other") : 0;
        valid = valid && disk && kept && !vfs_lookup(disk, "data");
        if (kept) object_release(kept);
        if (disk) object_release(disk);
    }
    valid = valid && point && !vfs_unmount(point);

    integrity_cleanup(root, point, dev);
    if (root) object_release(root);
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
