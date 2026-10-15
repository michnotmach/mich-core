#include "adytumfs.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"
#include "adytumfs_tree.h"
#include "vfs.h"
#include "block.h"
#include "cache.h"
#include "resource.h"
#include "rtc64.h"

#define ADYTUMFS_MOUNT_MAX 8

// The VFS numbers a mount's files 0..ADYTUMFS_INODE_MAX with 0 as the mount
// root, and uses 0 as the "no backend file" id for ramfs nodes. The on-disk
// format numbers inodes from 1 because a zero dirent target marks a free
// record, so this backend translates through a dense slot table rebuilt by
// walking the tree at attach. The table also carries the name and parent the
// VFS mount scan asks for, which the on-disk inode does not store.
struct adytumfs_slot {
    u64 inode;
    u64 generation;
    u32 parent;
    char name[VFS_NAME_MAX + 1];
};

// One bit per cached page. A single u64 word capped a file at 64 pages even
// though the on-disk format has no such limit: an extent length is a free
// u32 and a contiguous grow extends the last extent, so the array is what
// lets a file reach what the device can actually hold.
#define ADYTUMFS_PAGE_WORD_BITS 64u
#define ADYTUMFS_PAGE_WORDS (ADYTUMFS_FILE_PAGES / ADYTUMFS_PAGE_WORD_BITS)

struct adytumfs_cache {
    struct kernel_object *pages;
    u64 present[ADYTUMFS_PAGE_WORDS];
    u64 dirty[ADYTUMFS_PAGE_WORDS];
    u32 active;
};

static int cache_test(const u64 *mask, u32 page) {
    return (int)((mask[page / ADYTUMFS_PAGE_WORD_BITS] >>
                  (page % ADYTUMFS_PAGE_WORD_BITS)) & 1u);
}

static void cache_mark(u64 *mask, u32 page) {
    mask[page / ADYTUMFS_PAGE_WORD_BITS] |=
        1ull << (page % ADYTUMFS_PAGE_WORD_BITS);
}

static void cache_unmark(u64 *mask, u32 page) {
    mask[page / ADYTUMFS_PAGE_WORD_BITS] &=
        ~(1ull << (page % ADYTUMFS_PAGE_WORD_BITS));
}

static void cache_clear_all(u64 *mask) {
    for (u32 index = 0; index < ADYTUMFS_PAGE_WORDS; index++)
        mask[index] = 0;
}

static int cache_any(const u64 *mask) {
    for (u32 index = 0; index < ADYTUMFS_PAGE_WORDS; index++)
        if (mask[index]) return 1;
    return 0;
}

struct adytumfs_mount {
    struct kernel_object *device;
    struct adytumfs_superblock super;
    // The content store this volume's extent trees resolve through. It lives
    // per mount because the index it caches sits at an address the superblock
    // gives, and two volumes have two indexes.
    struct adytumfs_cas store;
    struct adytumfs_slot slots[ADYTUMFS_INODE_MAX];
    struct adytumfs_cache cache[ADYTUMFS_INODE_MAX];
    u32 active;
};

static struct adytumfs_mount mounts[ADYTUMFS_MOUNT_MAX];

// One staging block for the superblock read and the truncate tail; the
// backend paths are single-CPU, like the rest of the format layer.
static u8 adytumfs_backend_scratch[ADYTUMFS_BLOCK_SIZE];

static struct adytumfs_mount *mount_at(u32 mount) {
    if (!mount || mount >= ADYTUMFS_MOUNT_MAX) return 0;
    struct adytumfs_mount *m = &mounts[mount];
    return m->active ? m : 0;
}

// A slot id is reused once its file is unlinked, while a node that was
// unlinked with an open handle keeps calling into the backend. Every entry
// point that addresses a slot must therefore also see the generation the
// caller captured when the node was scanned or created, and a mismatch is a
// stale handle: fail closed rather than touch the new owner of the slot.
static struct adytumfs_mount *slot_mount(u32 mount, u32 inode,
                                         u64 generation) {
    struct adytumfs_mount *m = mount_at(mount);
    if (!m || inode >= ADYTUMFS_INODE_MAX || !m->slots[inode].inode ||
        m->slots[inode].generation != generation)
        return 0;
    return m;
}

static u32 slot_name_len(const struct adytumfs_slot *slot) {
    u32 length = 0;
    while (length < VFS_NAME_MAX && slot->name[length]) length++;
    return length;
}

// Read the on-disk inode behind a VFS slot id.
static int slot_inode_read(struct adytumfs_mount *m, u32 slot,
                           struct adytumfs_inode *out) {
    if (!m || slot >= ADYTUMFS_INODE_MAX || !m->slots[slot].inode) return -1;
    return adytumfs_inode_read(m->device, &m->super, m->slots[slot].inode,
                               out);
}

// The format stores the VFS node type in the POSIX type bits of the mode.
static u32 slot_type(const struct adytumfs_inode *inode) {
    u32 bits = inode->mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG |
                              ADYTUMFS_MODE_LNK);
    return bits == ADYTUMFS_MODE_DIR ? VFS_NODE_DIRECTORY :
        bits == ADYTUMFS_MODE_LNK ? VFS_NODE_SYMLINK : VFS_NODE_REGULAR;
}

// Fill the slot table by walking directories from the root. A record that
// names a dead or out-of-range inode, a record whose type disagrees with the
// target inode, a second name for a directory, or a name past the VFS bound
// means the tree is inconsistent, so the mount fails rather than guesses; a
// second name for a regular inode is a hard link the sink reports. The
// queue is bounded by the slot count because every directory owns a slot
// before it is queued, and a parent always owns a lower slot than its
// children, so the table cannot express a cycle.
static int walk_tree(struct adytumfs_mount *m, adytumfs_alias_sink sink) {
    struct adytumfs_inode root;
    if (adytumfs_inode_read(m->device, &m->super, m->super.root_inode, &root))
        return -1;
    // The mount root is the directory every walk starts from; anything else
    // would have file data parsed as directory records.
    if ((root.mode & ADYTUMFS_MODE_DIR) == 0) return -1;
    m->slots[0].inode = m->super.root_inode;
    m->slots[0].generation = root.generation;
    m->slots[0].parent = 0;
    for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++) m->slots[0].name[byte] = 0;
    u64 queue_inode[ADYTUMFS_INODE_MAX];
    u32 queue_slot[ADYTUMFS_INODE_MAX];
    u32 head = 0;
    u32 tail = 1;
    u32 used = 1;
    queue_inode[0] = m->super.root_inode;
    queue_slot[0] = 0;
    while (head < tail) {
        u64 dir_inode = queue_inode[head];
        u32 dir_slot = queue_slot[head];
        head++;
        u64 cursor = 0;
        for (;;) {
            char name[ADYTUMFS_NAME_MAX + 1];
            u32 name_len = 0;
            u64 target = 0;
            u8 type = 0;
            int step = adytumfs_dir_iter(m->device, &m->super, &m->store, dir_inode,
                                         &cursor, name, &name_len, &target,
                                         &type);
            if (step == 1) break;
            if (step < 0) return -1;
            struct adytumfs_inode child;
            if (adytumfs_inode_read(m->device, &m->super, target, &child) ||
                child.mode == 0)
                return -1;
            u32 bits = child.mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG |
                                     ADYTUMFS_MODE_LNK);
            if (bits != ADYTUMFS_MODE_DIR && bits != ADYTUMFS_MODE_REG &&
                bits != ADYTUMFS_MODE_LNK)
                return -1;
            u32 expect = bits == ADYTUMFS_MODE_DIR ? ADYTUMFS_DTYPE_DIR :
                bits == ADYTUMFS_MODE_LNK ? ADYTUMFS_DTYPE_LNK :
                ADYTUMFS_DTYPE_REG;
            if (type != expect) return -1;
            if (!name_len || name_len > VFS_NAME_MAX) return -1;
            u32 found = ADYTUMFS_INODE_MAX;
            for (u32 slot = 0; slot < used; slot++)
                if (m->slots[slot].inode == target) {
                    found = slot;
                    break;
                }
            if (found != ADYTUMFS_INODE_MAX) {
                // A second name for a regular inode is a hard link the
                // caller records through the sink; a directory can never
                // carry one, so that stays a structural reject.
                if (bits != ADYTUMFS_MODE_REG || !sink ||
                    sink(dir_slot, found, name, name_len))
                    return -1;
                continue;
            }
            if (used >= ADYTUMFS_INODE_MAX) return -1;
            u32 slot = used++;
            m->slots[slot].inode = target;
            m->slots[slot].generation = child.generation;
            m->slots[slot].parent = dir_slot;
            for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
                m->slots[slot].name[byte] = 0;
            for (u32 byte = 0; byte < name_len; byte++)
                m->slots[slot].name[byte] = name[byte];
            if (bits == ADYTUMFS_MODE_DIR) {
                queue_inode[tail] = target;
                queue_slot[tail] = slot;
                tail++;
            }
        }
    }
    return 0;
}

// Resolve a cache slot, dropping it when the page resource it borrows was
// revoked in the meantime.
static struct adytumfs_cache *cache_slot(struct adytumfs_mount *m,
                                         u32 inode) {
    if (!m || inode >= ADYTUMFS_INODE_MAX) return 0;
    struct adytumfs_cache *slot = &m->cache[inode];
    if (!slot->active) return 0;
    struct page_resource *resource =
        slot->pages ? page_resource_get(slot->pages) : 0;
    if (!resource || resource->revoked) {
        slot->pages = 0;
        cache_clear_all(slot->present);
        cache_clear_all(slot->dirty);
        slot->active = 0;
        return 0;
    }
    return slot;
}

// One submit is bounded by BLOCK_IO_SG_SECTORS_MAX sectors, not by the SG
// entry count, so a transfer is chunked at eight pages even though a page
// resource holds up to sixty four.
#define ADYTUMFS_SG_PAGES (BLOCK_IO_SG_SECTORS_MAX / (4096u / BLOCK_SECTOR_SIZE))

// Move count pages between the page resource and the device. lba is the
// device sector of page first; the caller guarantees the pages of the batch
// map to physically adjacent blocks.
static int page_transfer(struct adytumfs_mount *m, struct adytumfs_cache *slot,
                         u32 lba, u32 first, u32 count, u32 op) {
    if (!count || count > ADYTUMFS_SG_PAGES) return -1;
    struct kernel_object *pages[ADYTUMFS_SG_PAGES];
    u32 indices[ADYTUMFS_SG_PAGES];
    u32 offsets[ADYTUMFS_SG_PAGES];
    u32 lengths[ADYTUMFS_SG_PAGES];
    for (u32 index = 0; index < count; index++) {
        pages[index] = slot->pages;
        indices[index] = first + index;
        offsets[index] = 0;
        lengths[index] = 4096;
    }
    struct kernel_object *sg =
        sg_resource_create(pages, indices, offsets, lengths, count);
    if (!sg) return -1;
    u32 sectors = count * (4096u / BLOCK_SECTOR_SIZE);
    // The transfer moves bytes through the transport, not the block cache,
    // so a cached image of the target sectors would keep serving the
    // previous contents behind the write. Drop it the way block_zero does.
    if (op == BLOCK_OP_WRITE)
        block_cache_invalidate(m->device, lba, sectors);
    u64 id = 0;
    i32 status = -1;
    u32 transferred = 0;
    int result = -1;
    if (block_submit_sg(m->device, op, lba, sectors, sg, &id)) {
        // Ramdisk-backed devices carry no scatter-gather transport, so the
        // page still has to move one page at a time through the copy path.
        struct page_resource *resource = page_resource_get(slot->pages);
        result = 0;
        for (u32 index = 0; index < count && !result; index++) {
            u8 *bytes = resource ?
                (u8 *)(uptr_t)resource->physical[first + index] : 0;
            if (!bytes) {
                result = -1;
                break;
            }
            for (u32 sector = 0;
                 sector < 4096u / BLOCK_SECTOR_SIZE && !result; sector++)
                result = block_io(m->device, op,
                                  lba + index * (4096u / BLOCK_SECTOR_SIZE) +
                                      sector,
                                  1, bytes + sector * BLOCK_SECTOR_SIZE,
                                  BLOCK_SECTOR_SIZE);
        }
        sg_resource_revoke(sg);
        object_release(sg);
        return result;
    }
    {
        if (block_collect(m->device, id, &status, &transferred, 0, 0))
            for (u32 spin = 0; spin < 1000000; spin++) {
                block_service(m->device);
                if (!block_collect(m->device, id, &status, &transferred, 0, 0))
                    break;
                __asm__ volatile("pause");
            }
        if (!status && transferred == sectors * BLOCK_SECTOR_SIZE) result = 0;
    }
    sg_resource_revoke(sg);
    object_release(sg);
    return result;
}

int adytumfs_pages_attach(u32 mount, u32 inode, u64 generation,
                          struct kernel_object *pages) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !pages || m->cache[inode].active)
        return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in) || (in.mode & ADYTUMFS_MODE_REG) == 0)
        return -1;
    struct page_resource *resource = page_resource_get(pages);
    if (!resource || resource->pages > ADYTUMFS_FILE_PAGES) return -1;
    struct adytumfs_cache *slot = &m->cache[inode];
    slot->pages = pages;
    cache_clear_all(slot->present);
    cache_clear_all(slot->dirty);
    slot->active = 1;
    return 0;
}

int adytumfs_pages_fault(u32 mount, u32 inode, u64 generation, u32 page) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    struct adytumfs_cache *slot = cache_slot(m, inode);
    struct adytumfs_inode in;
    if (!slot || page >= ADYTUMFS_FILE_PAGES ||
        slot_inode_read(m, inode, &in) || (in.mode & ADYTUMFS_MODE_REG) == 0)
        return -1;
    if (cache_test(slot->present, page)) return 0;
    struct page_resource *resource = page_resource_get(slot->pages);
    if (!resource || page >= resource->pages) return -1;
    u8 *bytes = (u8 *)(uptr_t)resource->physical[page];
    if (!bytes) return -1;
    u64 physical = 0;
    // A page past the file size or past the allocated extents reads as
    // zeroes: the write path grows at sync, not at fault.
    if (page * 4096u >= in.size ||
        adytumfs_inode_map(m->device, &m->super, &m->store, &in, page, &physical)) {
        for (u32 index = 0; index < 4096; index++) bytes[index] = 0;
        cache_mark(slot->present, page);
        return 0;
    }
    if (page_transfer(m, slot, (u32)(physical * ADYTUMFS_SECTORS_PER_BLOCK),
                      page, 1, BLOCK_OP_READ))
        return -1;
    // The transfer filled the page from the device, so the region must vouch
    // for those bytes exactly like the read path demands.
    if (adytumfs_data_check(m->device, &m->super, physical, bytes)) return -1;
    cache_mark(slot->present, page);
    return 0;
}

int adytumfs_pages_dirty(u32 mount, u32 inode, u64 generation, u32 page,
                         u32 size) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    struct adytumfs_cache *slot = cache_slot(m, inode);
    struct adytumfs_inode in;
    if (!slot || page >= ADYTUMFS_FILE_PAGES || size > ADYTUMFS_FILE_SIZE_MAX ||
        slot_inode_read(m, inode, &in) || (in.mode & ADYTUMFS_MODE_REG) == 0)
        return -1;
    cache_mark(slot->present, page);
    cache_mark(slot->dirty, page);
    if (size > in.size) {
        in.size = size;
        if (adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                                 &in))
            return -1;
    }
    return 0;
}

int adytumfs_pages_sync(u32 mount, u32 inode, u64 generation) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    struct adytumfs_cache *slot = cache_slot(m, inode);
    if (!m) return -1;
    if (!slot) return 0;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in) || (in.mode & ADYTUMFS_MODE_REG) == 0)
        return -1;
    if (!cache_any(slot->dirty)) return 0;
    // Grow to the write-back size, not only over the dirty pages: a write
    // that skipped pages leaves holes whose blocks must exist and read as
    // zeroes. Growth only appends, so attached pages stay valid.
    u64 needed = in.size / ADYTUMFS_BLOCK_SIZE +
                 (in.size % ADYTUMFS_BLOCK_SIZE ? 1 : 0);
    if (needed > ADYTUMFS_FILE_PAGES) needed = ADYTUMFS_FILE_PAGES;
    if (needed > in.blocks &&
        adytumfs_inode_grow(m->device, &m->super, &m->store, &in,
                            m->slots[inode].inode, needed))
        return -1;
    // Every dirty page is remapped rather than written where it sits. The
    // block a page maps to is named by content hash and may be shared with
    // another file, or with a hole, so writing it in place would change bytes
    // this file does not own. Remapping is what makes the sharing safe, and it
    // is also why the old distinction between pages that predate this
    // write-back and pages the grow just added is gone: both are remapped.
    //
    // Each remap commits the inode, because the tree root moves and an inode
    // on disk that named the previous root has to be replaced before the old
    // tree is let go. A flush of many pages therefore writes the inode once
    // per page. That is the price of the crash argument holding after every
    // step, and batching it is a separate change with its own rollback story.
    struct page_resource *resource = page_resource_get(slot->pages);
    if (!resource) return -1;
    for (u32 page = 0; page < ADYTUMFS_FILE_PAGES; page++) {
        if (!cache_test(slot->dirty, page)) continue;
        u8 *bytes = (u8 *)(uptr_t)resource->physical[page];
        if (!bytes) return -1;
        if (adytumfs_inode_remap(m->device, &m->super, &m->store, &in,
                                 m->slots[inode].inode, page, bytes))
            return -1;
        cache_unmark(slot->dirty, page);
    }
    // Sync is the agreed commit boundary: the redirected pages and the
    // staged metadata land together or not at all.
    return adytumfs_commit(m->device, &m->super);
}

void adytumfs_pages_detach(u32 mount, u32 inode, u64 generation) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m) return;
    struct adytumfs_cache *slot = &m->cache[inode];
    slot->pages = 0;
    cache_clear_all(slot->present);
    cache_clear_all(slot->dirty);
    slot->active = 0;
}

int adytumfs_format(struct kernel_object *device) {
    // Kept under the VFS-facing name so callers outside the fs layer do not
    // change; the on-disk work lives with the format stack.
    return adytumfs_make(device);
}

int adytumfs_attach(u32 mount, struct kernel_object *device,
                    adytumfs_alias_sink sink) {
    if (!mount || mount >= ADYTUMFS_MOUNT_MAX || mount_at(mount) || !device)
        return -1;
    // One active mount per device: a second window on the same volume would
    // stage metadata against a superblock copy the first mount is already
    // committing past.
    for (u32 scan = 0; scan < ADYTUMFS_MOUNT_MAX; scan++)
        if (mounts[scan].device == device) return -1;
    // The window is keyed by device pointer, and a released device object
    // can hand that pointer to a new volume: every read below passes
    // through the staging, so the stale window has to go before them.
    adytumfs_window_discard(device);
    struct adytumfs_superblock super;
    if (adytumfs_super_read(device, &super)) return -1;
    // A structurally valid superblock whose tree does not verify is post
    // commit corruption, not a torn commit: the commit order lands data and
    // metadata before the superblock flip, so a torn flip fails the checksum
    // above and only rot gets this far. Falling back to the older generation
    // here would roll the volume back over the damage; the mount fails
    // instead, leaving both generations for an explicit repair pass.
    // v1 defines no ro-compat features; an image asking for one would need a
    // read-only mount, which the VFS contract cannot express.
    if (super.feature_ro_compat) return -1;
    if (adytumfs_verify(device, &super)) return -1;
    if (object_retain(device)) return -1;
    struct adytumfs_mount *m = &mounts[mount];
    for (u32 slot = 0; slot < ADYTUMFS_INODE_MAX; slot++) {
        m->slots[slot].inode = 0;
        m->slots[slot].generation = 0;
        m->slots[slot].parent = 0;
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            m->slots[slot].name[byte] = 0;
        m->cache[slot].pages = 0;
        cache_clear_all(m->cache[slot].present);
        cache_clear_all(m->cache[slot].dirty);
        m->cache[slot].active = 0;
    }
    m->super = super;
    m->device = device;
    adytumfs_cas_open(&m->store, super.index_start, super.index_blocks);
    if (walk_tree(m, sink)) {
        m->device = 0;
        object_release(device);
        return -1;
    }
    m->active = 1;
    return 0;
}

void adytumfs_detach(u32 mount) {
    struct adytumfs_mount *m = mount_at(mount);
    if (!m) return;
    if (m->device) {
        for (u32 inode = 0; inode < ADYTUMFS_INODE_MAX; inode++) {
            if (!m->cache[inode].active) continue;
            adytumfs_pages_sync(mount, inode, m->slots[inode].generation);
            adytumfs_pages_detach(mount, inode, m->slots[inode].generation);
        }
        // Unmount is the other commit boundary; pages_sync already committed
        // per file, so this lands windows that only touched raw metadata.
        adytumfs_commit(m->device, &m->super);
        object_release(m->device);
    }
    m->device = 0;
    m->active = 0;
}

u32 adytumfs_inode_count(u32 mount) {
    // The VFS mount scan stacks arrays of this size and attach rejects a
    // fuller image, so the bound is the slot table, not the volume's inode
    // count.
    return mount_at(mount) ? ADYTUMFS_INODE_MAX : 0;
}

int adytumfs_inode_get(u32 mount, u32 inode, u32 *used, u32 *type, u32 *size,
                      u32 *parent, u32 *mode, char *name, u64 *generation) {
    struct adytumfs_mount *m = mount_at(mount);
    if (!m || inode >= ADYTUMFS_INODE_MAX) return -1;
    if (!m->slots[inode].inode) {
        if (used) *used = 0;
        if (type) *type = 0;
        if (size) *size = 0;
        if (parent) *parent = 0;
        if (mode) *mode = 0;
        if (generation) *generation = 0;
        if (name)
            for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++) name[byte] = 0;
        return 0;
    }
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    // On-disk sizes are untrusted: clamp to the allocated extents and to the
    // page-resource bound, or a crafted inode drives reads past the mapping.
    u64 bound = in.blocks * ADYTUMFS_BLOCK_SIZE;
    if (bound > ADYTUMFS_FILE_SIZE_MAX) bound = ADYTUMFS_FILE_SIZE_MAX;
    if (used) *used = 1;
    if (type) *type = slot_type(&in);
    if (size) *size = (u32)(in.size < bound ? in.size : bound);
    if (parent) *parent = m->slots[inode].parent;
    if (mode) *mode = in.mode & VFS_MODE_MASK;
    if (generation) *generation = m->slots[inode].generation;
    if (name)
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            name[byte] = m->slots[inode].name[byte];
    return 0;
}

int adytumfs_touch(u32 mount, u32 inode, u64 generation, u32 flags) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !flags) return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    u32 changed = 0;
    u64 now = rtc64_wall_clock();
    u32 now_nsec = rtc64_wall_clock_nsec();
    // Relatime-lite: a read only refreshes atime while it still trails the
    // last data change, so steady-state reads never dirty the inode.
    if ((flags & ADYTUMFS_TOUCH_ATIME) && in.atime < in.mtime) {
        in.atime = now;
        in.atime_nsec = now_nsec;
        changed = 1;
    }
    if (flags & ADYTUMFS_TOUCH_MTIME) {
        in.mtime = now;
        in.mtime_nsec = now_nsec;
        changed = 1;
    }
    if (flags & ADYTUMFS_TOUCH_CTIME) {
        in.ctime = now;
        in.ctime_nsec = now_nsec;
        changed = 1;
    }
    if (!changed) return 0;
    return adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                                &in);
}

int adytumfs_inode_update(u32 mount, u32 inode, u64 generation, u32 flags,
                          u32 mode, u32 uid, u32 gid) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !flags || (flags & ~(ADYTUMFS_SET_MODE | ADYTUMFS_SET_UID |
                                   ADYTUMFS_SET_GID)))
        return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    u32 changed = 0;
    if ((flags & ADYTUMFS_SET_MODE) && (in.mode & 0777u) != mode) {
        // The on-disk mode carries the type bits over the permission bits,
        // so an edit replaces only the permission half.
        in.mode = (u16)((in.mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG)) |
                        mode);
        changed = 1;
    }
    if ((flags & ADYTUMFS_SET_UID) && in.uid != uid) {
        in.uid = uid;
        changed = 1;
    }
    if ((flags & ADYTUMFS_SET_GID) && in.gid != gid) {
        in.gid = gid;
        changed = 1;
    }
    if (!changed) return 0;
    in.ctime = rtc64_wall_clock();
    in.ctime_nsec = rtc64_wall_clock_nsec();
    return adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                                &in);
}

int adytumfs_set_times(u32 mount, u32 inode, u64 generation, u32 flags,
                       u64 atime, u32 atime_nsec, u64 mtime, u32 mtime_nsec) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !flags ||
        (flags & ~(ADYTUMFS_TIME_SET_ATIME | ADYTUMFS_TIME_SET_MTIME)))
        return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    u32 changed = 0;
    if ((flags & ADYTUMFS_TIME_SET_ATIME) &&
        (in.atime != atime || in.atime_nsec != atime_nsec)) {
        in.atime = atime;
        in.atime_nsec = atime_nsec;
        changed = 1;
    }
    if ((flags & ADYTUMFS_TIME_SET_MTIME) &&
        (in.mtime != mtime || in.mtime_nsec != mtime_nsec)) {
        in.mtime = mtime;
        in.mtime_nsec = mtime_nsec;
        changed = 1;
    }
    // A timestamp edit is metadata the vouching path can see, so ctime
    // moves with any real change; a call restating the stored values stays
    // a no-op, the same rule inode_update holds.
    if (!changed) return 0;
    in.ctime = rtc64_wall_clock();
    in.ctime_nsec = rtc64_wall_clock_nsec();
    return adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                                &in);
}

int adytumfs_inode_meta(u32 mount, u32 inode, u64 generation, u16 *links,
                        u32 *uid, u32 *gid, u64 *atime, u64 *mtime,
                        u64 *ctime, u32 *atime_nsec, u32 *mtime_nsec,
                        u32 *ctime_nsec) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m) return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    if (links) *links = in.links;
    if (uid) *uid = in.uid;
    if (gid) *gid = in.gid;
    if (atime) *atime = in.atime;
    if (mtime) *mtime = in.mtime;
    if (ctime) *ctime = in.ctime;
    if (atime_nsec) *atime_nsec = in.atime_nsec;
    if (mtime_nsec) *mtime_nsec = in.mtime_nsec;
    if (ctime_nsec) *ctime_nsec = in.ctime_nsec;
    return 0;
}

int adytumfs_dir_read(u32 mount, u32 inode, u64 generation, u64 *cursor,
                      char *name, u32 *name_len, u64 *entry_inode,
                      u32 *type) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !cursor || !name || !name_len || !entry_inode || !type)
        return -1;
    u64 target = 0;
    u8 disk_type = 0;
    int result = adytumfs_dir_iter(m->device, &m->super,
                                    &m->store,
                                   m->slots[inode].inode, cursor, name,
                                   name_len, &target, &disk_type);
    if (result) return result;
    if (disk_type == ADYTUMFS_DTYPE_REG) {
        *type = VFS_NODE_REGULAR;
    } else if (disk_type == ADYTUMFS_DTYPE_DIR) {
        *type = VFS_NODE_DIRECTORY;
    } else {
        // A type this build never writes is corruption, not a listing.
        return -1;
    }
    *entry_inode = target;
    return 0;
}

int adytumfs_inode_create(u32 mount, const char *name, u32 parent, u32 type,
                         u32 mode, u32 *inode, u64 *generation) {
    struct adytumfs_mount *m = mount_at(mount);
    if (!m || !name || !name[0] || !inode || parent >= ADYTUMFS_INODE_MAX ||
        (type != VFS_NODE_REGULAR && type != VFS_NODE_DIRECTORY &&
         type != VFS_NODE_SYMLINK) ||
        (mode & ~VFS_MODE_MASK))
        return -1;
    u32 name_len = 0;
    while (name[name_len] && name_len < VFS_NAME_MAX) name_len++;
    if (name_len == VFS_NAME_MAX && name[name_len]) return -1;
    struct adytumfs_inode dir;
    if (slot_inode_read(m, parent, &dir) || (dir.mode & ADYTUMFS_MODE_DIR) == 0)
        return -1;
    // Reserve the table slot before touching the disk so a full table never
    // leaves an allocated inode behind.
    u32 slot = 0;
    for (u32 index = 1; index < ADYTUMFS_INODE_MAX; index++)
        if (!m->slots[index].inode) {
            slot = index;
            break;
        }
    if (!slot) return -1;
    u16 disk_mode = (u16)(mode | (type == VFS_NODE_DIRECTORY ?
        ADYTUMFS_MODE_DIR : type == VFS_NODE_SYMLINK ?
        ADYTUMFS_MODE_LNK : ADYTUMFS_MODE_REG));
    u64 target = 0;
    if (adytumfs_create_at(m->device, &m->super, &m->store,
                           m->slots[parent].inode, name,
                           name_len, disk_mode, &target))
        return -1;
    // The allocator stamps a fresh generation into the on-disk inode, and the
    // slot table must carry the same value the caller will be told to present
    // on every later backend call.
    struct adytumfs_inode fresh;
    if (adytumfs_inode_read(m->device, &m->super, target, &fresh)) return -1;
    m->slots[slot].inode = target;
    m->slots[slot].generation = fresh.generation;
    m->slots[slot].parent = parent;
    for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
        m->slots[slot].name[byte] = 0;
    for (u32 byte = 0; byte < name_len; byte++)
        m->slots[slot].name[byte] = name[byte];
    *inode = slot;
    if (generation) *generation = fresh.generation;
    return 0;
}

// One name measured against the VFS bound; the walk and the VFS callers
// keep names short and terminated, so an overlong or empty name is a
// caller bug and reads back as the reject length.
static u32 bounded_name_len(const char *name) {
    u32 len = 0;
    while (len < VFS_NAME_MAX && name[len]) len++;
    return name[len] ? VFS_NAME_MAX + 1u : len;
}

int adytumfs_inode_link(u32 mount, u32 inode, u64 generation, u32 parent,
                        const char *name) {
    // Slot zero is the mount root and a legitimate link parent; the
    // linked inode itself is always a regular file below it.
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !name || parent >= ADYTUMFS_INODE_MAX) return -1;
    u32 name_len = bounded_name_len(name);
    if (!name_len || name_len > VFS_NAME_MAX) return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in) ||
        (in.mode & ADYTUMFS_MODE_REG) == 0)
        return -1;
    struct adytumfs_inode dir;
    if (slot_inode_read(m, parent, &dir) ||
        (dir.mode & ADYTUMFS_MODE_DIR) == 0)
        return -1;
    // The on-disk count is a u16 and stops there; the VFS alias bound is
    // far lower, so this only guards a volume edited by hand.
    if (in.links == 0xFFFFu) return -1;
    // The count rises before the name lands: a crash between the two
    // leaves a stale-high count the next mount reports, while the reverse
    // order could reclaim an inode a surviving name still points at.
    in.links++;
    in.ctime = rtc64_wall_clock();
    in.ctime_nsec = rtc64_wall_clock_nsec();
    if (adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                             &in))
        return -1;
    if (adytumfs_dir_add(m->device, &m->super, &m->store, m->slots[parent].inode, name,
                         name_len, m->slots[inode].inode,
                         ADYTUMFS_DTYPE_REG)) {
        // The name could not land, so the count goes back down; a failed
        // rollback write just leaves the stale-high drift above.
        in.links--;
        adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                             &in);
        return -1;
    }
    adytumfs_touch(mount, parent, m->slots[parent].generation,
                   ADYTUMFS_TOUCH_MTIME | ADYTUMFS_TOUCH_CTIME);
    return 0;
}

// Reclaim the data and persist the emptied inode before the slot goes; the
// caller removes the name first, so a crash inside leaves an orphan with
// its data intact, never a live name over blocks a later allocation can
// reuse.
static int inode_reclaim(u32 mount, struct adytumfs_mount *m, u32 inode) {
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    adytumfs_pages_detach(mount, inode, m->slots[inode].generation);
    if (adytumfs_inode_truncate(m->device, &m->super, &m->store, &in, m->slots[inode].inode, 0)) return -1;
    in.size = 0;
    if (adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                             &in))
        return -1;
    if (adytumfs_inode_free(m->device, &m->super, m->slots[inode].inode))
        return -1;
    m->slots[inode].inode = 0;
    m->slots[inode].parent = 0;
    for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
        m->slots[inode].name[byte] = 0;
    return 0;
}

int adytumfs_unlink(u32 mount, u32 inode, u64 generation, u32 parent,
                    const char *name, int last_close) {
    // Slot zero is the mount root and a legitimate unlink parent; the
    // unlinked inode below it can be either kind.
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !name || parent >= ADYTUMFS_INODE_MAX) return -1;
    u32 name_len = bounded_name_len(name);
    if (!name_len || name_len > VFS_NAME_MAX) return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    u32 bits = in.mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG |
                          ADYTUMFS_MODE_LNK);
    if (bits != ADYTUMFS_MODE_DIR && bits != ADYTUMFS_MODE_REG &&
        bits != ADYTUMFS_MODE_LNK)
        return -1;
    struct adytumfs_inode dir;
    if (slot_inode_read(m, parent, &dir) ||
        (dir.mode & ADYTUMFS_MODE_DIR) == 0)
        return -1;
    if (bits == ADYTUMFS_MODE_DIR) {
        // The VFS only unlinks directories it sees as empty; hold the disk
        // to the same rule, because tombstoned records still own a data
        // block.
        char probe[ADYTUMFS_NAME_MAX + 1];
        u32 probe_len = 0;
        u64 target = 0;
        u8 type = 0;
        u64 cursor = 0;
        if (adytumfs_dir_iter(m->device, &m->super, &m->store, m->slots[inode].inode,
                              &cursor, probe, &probe_len, &target,
                              &type) != 1)
            return -1;
    }
    // The name goes before the count: a crash between the two leaves a
    // stale-high count, never a live name over blocks a later allocation
    // can reuse.
    if (adytumfs_dir_remove(m->device, &m->super, &m->store, m->slots[parent].inode,
                            name, name_len))
        return -1;
    adytumfs_touch(mount, parent, m->slots[parent].generation,
                   ADYTUMFS_TOUCH_MTIME | ADYTUMFS_TOUCH_CTIME);
    if (bits == ADYTUMFS_MODE_REG && in.links > 1) {
        // A regular inode keeps its remaining names; the count on disk
        // says how many.
        in.links--;
        in.ctime = rtc64_wall_clock();
        in.ctime_nsec = rtc64_wall_clock_nsec();
        return adytumfs_inode_write(m->device, &m->super,
                                    m->slots[inode].inode, &in);
    }
    if (last_close) {
        // The last name is gone but a descriptor still holds the inode:
        // zero the count now and leave pages, data, and the slot to the
        // reclaim the final close triggers.
        in.links = 0;
        in.ctime = rtc64_wall_clock();
        in.ctime_nsec = rtc64_wall_clock_nsec();
        return adytumfs_inode_write(m->device, &m->super,
                                    m->slots[inode].inode, &in);
    }
    return inode_reclaim(mount, m, inode);
}

int adytumfs_rename(u32 mount, u32 inode, u64 generation, u32 old_parent,
                    const char *name, u32 new_parent, const char *new_name) {
    // The VFS settles names, kinds, mountpoints, and cycles; this layer
    // holds the disk to the same story and lands the move in one commit.
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !name || !new_name || !inode ||
        old_parent >= ADYTUMFS_INODE_MAX || new_parent >= ADYTUMFS_INODE_MAX)
        return -1;
    u32 name_len = bounded_name_len(name);
    u32 new_len = bounded_name_len(new_name);
    if (!name_len || name_len > VFS_NAME_MAX || !new_len ||
        new_len > VFS_NAME_MAX)
        return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    u32 bits = in.mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG |
                          ADYTUMFS_MODE_LNK);
    if (bits != ADYTUMFS_MODE_DIR && bits != ADYTUMFS_MODE_REG &&
        bits != ADYTUMFS_MODE_LNK)
        return -1;
    struct adytumfs_inode old_dir, new_dir;
    if (slot_inode_read(m, old_parent, &old_dir) ||
        (old_dir.mode & ADYTUMFS_MODE_DIR) == 0 ||
        slot_inode_read(m, new_parent, &new_dir) ||
        (new_dir.mode & ADYTUMFS_MODE_DIR) == 0)
        return -1;
    // The moved name must live under the old parent and point here, and the
    // new name must be free: anything else is a stale VFS view.
    u64 present = 0;
    if (adytumfs_dir_lookup(m->device, &m->super, &m->store, m->slots[old_parent].inode, name,
                            name_len, &present) ||
        present != m->slots[inode].inode)
        return -1;
    u64 taken = 0;
    if (adytumfs_dir_lookup(m->device, &m->super, &m->store, m->slots[new_parent].inode, new_name,
                            new_len, &taken) == 0)
        return -1;
    // A rename never touches the link count: the moved name keeps vouching
    // for the same inode, so only the ctime and the two directory times
    // move. The staged ctime lands first, like the count before a link
    // name: a failure past this point leaves a stale-new time, never a
    // name the metadata cannot vouch for.
    in.ctime = rtc64_wall_clock();
    in.ctime_nsec = rtc64_wall_clock_nsec();
    if (adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                             &in))
        return -1;
    // The old name leaves before the new one lands: a crash between the
    // two leaves an orphan holding its data, never one inode under two
    // names the link count cannot vouch for.
    if (adytumfs_dir_remove(m->device, &m->super, &m->store, m->slots[old_parent].inode, name,
                            name_len))
        return -1;
    u8 dtype = bits == ADYTUMFS_MODE_DIR ? ADYTUMFS_DTYPE_DIR :
        bits == ADYTUMFS_MODE_LNK ? ADYTUMFS_DTYPE_LNK :
        ADYTUMFS_DTYPE_REG;
    if (adytumfs_dir_add(m->device, &m->super, &m->store, m->slots[new_parent].inode, new_name,
                         new_len, m->slots[inode].inode, dtype)) {
        // The rename never happened, so put the old name back before
        // failing: the VFS view must keep matching the disk. A failed
        // rollback leaves the accepted orphan form.
        adytumfs_dir_add(m->device, &m->super, &m->store, m->slots[old_parent].inode, name,
                         name_len, m->slots[inode].inode, dtype);
        return -1;
    }
    adytumfs_touch(mount, old_parent, m->slots[old_parent].generation,
                   ADYTUMFS_TOUCH_MTIME | ADYTUMFS_TOUCH_CTIME);
    adytumfs_touch(mount, new_parent, m->slots[new_parent].generation,
                   ADYTUMFS_TOUCH_MTIME | ADYTUMFS_TOUCH_CTIME);
    // The slot cache carries the primary name the mount scan asks for;
    // when the moved name was an alias, the primary keeps its slot.
    if (m->slots[inode].parent == old_parent &&
        slot_name_len(&m->slots[inode]) == name_len) {
        int primary = 1;
        for (u32 byte = 0; byte < name_len; byte++)
            if (m->slots[inode].name[byte] != name[byte]) primary = 0;
        if (primary) {
            m->slots[inode].parent = new_parent;
            for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
                m->slots[inode].name[byte] = 0;
            for (u32 byte = 0; byte < new_len; byte++)
                m->slots[inode].name[byte] = new_name[byte];
        }
    }
    // One commit lands the move, its times, and any target removal the
    // caller staged before this call: the whole rename is a single flip.
    return adytumfs_commit(m->device, &m->super);
}

// Write the target into a freshly created symlink inode's file body. The
// write joins the create in the same staging window, so one commit lands
// the inode, its name, and the string together.
int adytumfs_symlink_write(u32 mount, u32 inode, u64 generation,
                           const char *target) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !target || !target[0]) return -1;
    u32 length = 0;
    while (length < VFS_PATH_MAX && target[length]) length++;
    if (length >= VFS_PATH_MAX) return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    u32 bits = in.mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG |
                          ADYTUMFS_MODE_LNK);
    // Only a fresh link takes a body this way; anything else is a stale
    // VFS view writing over real data.
    if (bits != ADYTUMFS_MODE_LNK || in.blocks || in.size) return -1;
    for (u32 index = 0; index < ADYTUMFS_BLOCK_SIZE; index++)
        adytumfs_backend_scratch[index] = 0;
    for (u32 index = 0; index < length; index++)
        adytumfs_backend_scratch[index] = (u8)target[index];
    if (adytumfs_inode_grow(m->device, &m->super, &m->store, &in, m->slots[inode].inode, 1)) return -1;
    // Through a remap and not into the mapping, because the block the grow
    // added is the image of zeroes every hole on the volume shares.
    if (adytumfs_inode_remap(m->device, &m->super, &m->store, &in,
                             m->slots[inode].inode, 0,
                             adytumfs_backend_scratch))
        return -1;
    u64 now = rtc64_wall_clock();
    u32 now_nsec = rtc64_wall_clock_nsec();
    in.mtime = now;
    in.ctime = now;
    in.mtime_nsec = now_nsec;
    in.ctime_nsec = now_nsec;
    in.size = length;
    if (adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                             &in))
        return -1;
    return adytumfs_commit(m->device, &m->super);
}

// Read a symlink's target out of its data block for the mount scan: the
// string is bounded by the path bound, so one block is the whole extent.
int adytumfs_symlink_target(u32 mount, u32 inode, u64 generation,
                            char *target) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !target) return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    u32 bits = in.mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG |
                          ADYTUMFS_MODE_LNK);
    if (bits != ADYTUMFS_MODE_LNK) return -1;
    if (!in.size || in.size >= VFS_PATH_MAX || !in.blocks) return -1;
    u64 physical = 0;
    if (adytumfs_inode_map(m->device, &m->super, &m->store, &in, 0, &physical) ||
        adytumfs_data_read(m->device, &m->super, physical,
                           adytumfs_backend_scratch))
        return -1;
    for (u32 index = 0; index < in.size; index++)
        target[index] = (char)adytumfs_backend_scratch[index];
    target[in.size] = 0;
    // A body the first byte of which is empty is not a target anything
    // could resolve; the format layer refuses to mirror it.
    return target[0] ? 0 : -1;
}

int adytumfs_inode_release(u32 mount, u32 inode, u64 generation) {
    struct adytumfs_mount *m = mount_at(mount);
    if (!m || !m->active || !inode || inode >= ADYTUMFS_INODE_MAX)
        return -1;
    if (!m->slots[inode].inode ||
        m->slots[inode].generation != generation)
        return 0;
    return inode_reclaim(mount, m, inode);
}

int adytumfs_inode_remove(u32 mount, u32 inode) {
    struct adytumfs_mount *m = mount_at(mount);
    if (!m || !inode || inode >= ADYTUMFS_INODE_MAX ||
        !m->slots[inode].inode)
        return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in)) return -1;
    u32 bits = in.mode & (ADYTUMFS_MODE_DIR | ADYTUMFS_MODE_REG |
                          ADYTUMFS_MODE_LNK);
    if (bits != ADYTUMFS_MODE_DIR && bits != ADYTUMFS_MODE_REG &&
        bits != ADYTUMFS_MODE_LNK)
        return -1;
    if (bits == ADYTUMFS_MODE_DIR) {
        // The VFS only unlinks directories it sees as empty; hold the disk to
        // the same rule, because tombstoned records still own a data block.
        char name[ADYTUMFS_NAME_MAX + 1];
        u32 name_len = 0;
        u64 target = 0;
        u8 type = 0;
        u64 cursor = 0;
        if (adytumfs_dir_iter(m->device, &m->super, &m->store, m->slots[inode].inode,
                              &cursor, name, &name_len, &target, &type) != 1)
            return -1;
    }
    u32 parent = m->slots[inode].parent;
    // The name goes before the reclaim, so a crash between the two leaves
    // an orphan with its data intact rather than a live name over blocks
    // a later allocation can reuse.
    if (adytumfs_dir_remove(m->device, &m->super, &m->store, m->slots[parent].inode,
                            m->slots[inode].name,
                            slot_name_len(&m->slots[inode])))
        return -1;
    return inode_reclaim(mount, m, inode);
}

int adytumfs_truncate(u32 mount, u32 inode, u64 generation, u32 size,
                     u32 *new_size) {
    struct adytumfs_mount *m = slot_mount(mount, inode, generation);
    if (!m || !new_size || size > ADYTUMFS_FILE_SIZE_MAX) return -1;
    struct adytumfs_inode in;
    if (slot_inode_read(m, inode, &in) || (in.mode & ADYTUMFS_MODE_REG) == 0)
        return -1;
    u64 blocks = size / ADYTUMFS_BLOCK_SIZE +
                 (size % ADYTUMFS_BLOCK_SIZE ? 1 : 0);
    if (blocks > in.blocks) {
        if (adytumfs_inode_grow(m->device, &m->super, &m->store, &in, m->slots[inode].inode, blocks)) return -1;
    } else if (blocks < in.blocks) {
        if (adytumfs_inode_truncate(m->device, &m->super, &m->store, &in, m->slots[inode].inode, blocks))
            return -1;
    }
    if (size % ADYTUMFS_BLOCK_SIZE) {
        // Reads clamp to size but a mapping exposes the whole page, so the
        // bytes past the new size inside the kept tail block read as zeroes.
        u64 physical = 0;
        if (adytumfs_inode_map(m->device, &m->super, &m->store, &in, blocks - 1, &physical)) return -1;
        if (adytumfs_data_read(m->device, &m->super, physical,
                               adytumfs_backend_scratch))
            return -1;
        for (u32 index = size % ADYTUMFS_BLOCK_SIZE;
             index < ADYTUMFS_BLOCK_SIZE; index++)
            adytumfs_backend_scratch[index] = 0;
        if (adytumfs_inode_remap(m->device, &m->super, &m->store, &in,
                                 m->slots[inode].inode, blocks - 1,
                                 adytumfs_backend_scratch))
            return -1;
    }
    // Truncation changes the data, so mtime and ctime move with the new size.
    u64 now = rtc64_wall_clock();
    u32 now_nsec = rtc64_wall_clock_nsec();
    in.mtime = now;
    in.ctime = now;
    in.mtime_nsec = now_nsec;
    in.ctime_nsec = now_nsec;
    in.size = size;
    if (adytumfs_inode_write(m->device, &m->super, m->slots[inode].inode,
                             &in) ||
        adytumfs_commit(m->device, &m->super))
        return -1;
    *new_size = size;
    return 0;
}
