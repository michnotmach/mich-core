#include "vfs.h"
#include "posix_tty.h"
#include "spinlock.h"
#include "klock.h"
#include "resource.h"
#include "adytumfs.h"
#include "entropy.h"
#include "rtc64.h"

struct vfs_node_state {
    struct kernel_object *self;
    const u8 *external_data;
    struct kernel_object *pages;
    char name[VFS_NAME_MAX + 1];
    // The target a symlink name resolves through; empty for every other
    // node. The disk copy is the truth for adytumfs, this is the runtime
    // mirror the mount scan and readlink read from.
    char target[VFS_PATH_MAX];
    u32 parent;
    u32 type;
    u32 generation;
    u32 size;
    u32 filesystem;
    u32 mount;
    u32 mount_generation;
    u32 readonly;
    u32 mode;
    u32 uid;
    u32 gid;
    u32 special;
    u32 linked;
    u32 fs_id;
    u64 fs_generation;
    u64 atime;
    u64 mtime;
    u64 ctime;
    // Nanoseconds inside the seconds above, mirroring the on-disk inode
    // fields for the node-table filesystems.
    u32 atime_nsec;
    u32 mtime_nsec;
    u32 ctime_nsec;
    u32 active;
};

struct vfs_file_state {
    struct kernel_object *node;
    u32 active;
};

struct vfs_mount_state {
    struct kernel_object *self;
    struct kernel_object *root;
    struct kernel_object *mountpoint;
    u32 generation;
    u32 filesystem;
    u32 active;
};

static struct vfs_node_state nodes[VFS_NODE_MAX];
static struct vfs_file_state files[VFS_FILE_MAX];
static struct vfs_mount_state mounts[VFS_MOUNT_MAX];

// Hard links keep the node table single-parent: a node carries its first
// dentry inline, and every extra name for the same inode lives here.
// Directories never link, so an alias always names a regular file.

struct vfs_alias_state {
    u32 active;
    u32 node;
    u32 parent;
    char name[VFS_NAME_MAX + 1];
};

static struct vfs_alias_state aliases[VFS_ALIAS_MAX];
// One lock for the file, node, alias and mount tables: the paths cross
// between them, so a second lock at this level would only ever nest on
// itself. A level rather than a plain spinlock because these paths create
// and release objects, which take the object lock.
static struct klock vfs_klock = KLOCK_INIT(KLOCK_LEVEL_VFS);
static struct kernel_object *root_object;
static struct kernel_object *root_mount;

static int valid_name(const char *name) {
    if (!name || !name[0]) return 0;
    u32 length = 0;
    while (length < VFS_NAME_MAX && name[length]) {
        if (name[length] == '/') return 0;
        length++;
    }
    if (!length || (length == VFS_NAME_MAX && name[length])) return 0;
    if (length == 1 && name[0] == '.') return 0;
    if (length == 2 && name[0] == '.' && name[1] == '.') return 0;
    return 1;
}

static int names_equal(const char *left, const char *right) {
    for (u32 index = 0; index < VFS_NAME_MAX; index++) {
        if (left[index] != right[index]) return 0;
        if (!left[index]) return 1;
    }
    return 1;
}

static struct vfs_node_state *node_for(const struct kernel_object *object) {
    if (!object || !object->active ||
        (object->type != KOBJECT_VNODE && object->type != KOBJECT_DIRECTORY) ||
        !object->value || object->value > VFS_NODE_MAX)
        return 0;
    struct vfs_node_state *node = &nodes[object->value - 1];
    return node->active && node->self == object ? node : 0;
}

static struct vfs_file_state *file_for(const struct kernel_object *object) {
    if (!object || !object->active || object->type != KOBJECT_FILE ||
        !object->value || object->value > VFS_FILE_MAX)
        return 0;
    struct vfs_file_state *file = &files[object->value - 1];
    return file->active ? file : 0;
}

static u32 node_index(const struct vfs_node_state *node) {
    return (u32)(node - nodes);
}

static struct vfs_mount_state *mount_for_point(
    const struct kernel_object *object) {
    for (u32 index = 1; index < VFS_MOUNT_MAX; index++)
        if (mounts[index].active && mounts[index].mountpoint == object)
            return &mounts[index];
    return 0;
}

static struct vfs_mount_state *mount_for_root(
    const struct kernel_object *object) {
    for (u32 index = 1; index < VFS_MOUNT_MAX; index++)
        if (mounts[index].active && mounts[index].root == object)
            return &mounts[index];
    return 0;
}

static int node_backing_live(const struct vfs_node_state *node) {
    if (node && node->filesystem == VFS_FILESYSTEM_ADYTUMFS) {
        if (!node->mount || node->mount >= VFS_MOUNT_MAX) return 0;
        const struct vfs_mount_state *mount = &mounts[node->mount];
        return mount->active && mount->filesystem == VFS_FILESYSTEM_ADYTUMFS &&
               mount->generation == node->mount_generation;
    }
    return 1;
}

static int mount_has_open_file_locked(u32 mount_index, u32 generation) {
    for (u32 index = 0; index < VFS_FILE_MAX; index++) {
        if (!files[index].active) continue;
        struct vfs_node_state *node = node_for(files[index].node);
        if (node && node->filesystem == VFS_FILESYSTEM_ADYTUMFS &&
            node->mount == mount_index &&
            node->mount_generation == generation)
            return 1;
    }
    return 0;
}

// A descriptor still holding a node keeps that node's backing alive; the
// unlink path asks this before deciding between an eager reclaim and the
// deferred one the final close triggers.
static int node_has_open_file_locked(struct kernel_object *node) {
    for (u32 index = 0; index < VFS_FILE_MAX; index++)
        if (files[index].active && files[index].node == node) return 1;
    return 0;
}

static u32 child_count(u32 parent) {
    u32 count = 0;
    for (u32 index = 0; index < VFS_NODE_MAX; index++)
        if (nodes[index].active && nodes[index].linked &&
            nodes[index].parent == parent)
            count++;
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++)
        if (aliases[index].active && aliases[index].parent == parent)
            count++;
    return count;
}

static u32 alias_count(u32 node) {
    u32 count = 0;
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++)
        if (aliases[index].active && aliases[index].node == node)
            count++;
    return count;
}

static struct vfs_alias_state *alias_for_node(u32 node) {
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++)
        if (aliases[index].active && aliases[index].node == node)
            return &aliases[index];
    return 0;
}

static u32 directory_children(u32 parent) {
    u32 count = 0;
    for (u32 index = 0; index < VFS_NODE_MAX; index++)
        if (nodes[index].active && nodes[index].linked &&
            nodes[index].parent == parent &&
            nodes[index].type == VFS_NODE_DIRECTORY)
            count++;
    return count;
}

static void node_destroy(struct kernel_object *object) {
    if (!object || !object->value || object->value > VFS_NODE_MAX) return;
    struct vfs_node_state *node = &nodes[object->value - 1];
    klock_acquire(&vfs_klock);
    if (!node->active || node->self != object) {
        klock_release(&vfs_klock);
        return;
    }
    node->self = 0;
    node->external_data = 0;
    // Names die with their node: an alias cannot outlive the inode it
    // points at, and every teardown path that releases the node lands
    // here, unmount included.
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++)
        if (aliases[index].active && aliases[index].node == object->value - 1)
            aliases[index].active = 0;
    if (node->pages) {
        // The adytumfs cache slot borrows this resource, so it must be dropped
        // before the last reference goes away.
        if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS) {
            adytumfs_pages_sync(node->mount, node->fs_id,
                                node->fs_generation);
            adytumfs_pages_detach(node->mount, node->fs_id,
                                  node->fs_generation);
        }
        object_release(node->pages);
        node->pages = 0;
    }
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS && !node->linked) {
        // An unlinked inode waits for its final descriptor: the last
        // reference dropping here is that close, so the deferred reclaim
        // lands with it. Linked nodes die only with their mount, and a
        // released mount already tore its volume down, so the call is a
        // no-op unless this exact inode deferred.
        adytumfs_inode_release(node->mount, node->fs_id,
                               node->fs_generation);
    }
    for (u32 index = 0; index <= VFS_NAME_MAX; index++)
        node->name[index] = 0;
    node->parent = VFS_NODE_MAX;
    node->type = 0;
    node->size = 0;
    node->filesystem = 0;
    node->mount = VFS_MOUNT_MAX;
    node->mount_generation = 0;
    node->readonly = 0;
    node->mode = 0;
    node->uid = 0;
    node->gid = 0;
    node->special = VFS_SPECIAL_NONE;
    node->linked = 0;
    node->fs_id = 0;
    node->fs_generation = 0;
    node->active = 0;
    node->generation++;
    if (!node->generation) node->generation = 1;
    klock_release(&vfs_klock);
}

static void file_destroy(struct kernel_object *object) {
    if (!object || !object->value || object->value > VFS_FILE_MAX) return;
    struct vfs_file_state *file = &files[object->value - 1];
    klock_acquire(&vfs_klock);
    if (!file->active) {
        klock_release(&vfs_klock);
        return;
    }
    struct kernel_object *node = file->node;
    file->node = 0;
    file->active = 0;
    klock_release(&vfs_klock);
    if (node) object_release(node);
}

// Every object this drops is a node, and a node's destroy takes this lock,
// so the releases wait for the unlock. The active flag is not part of the
// claim: unmount clears it first to keep a second caller from releasing the
// same object twice.
static void mount_destroy(struct kernel_object *object) {
    if (!object || !object->value || object->value > VFS_MOUNT_MAX) return;
    u32 mount_index = (u32)object->value - 1;
    struct vfs_mount_state *mount = &mounts[mount_index];
    struct kernel_object *pending[VFS_NODE_MAX + 2];
    u32 pending_count = 0;
    klock_acquire(&vfs_klock);
    if (mount->self != object) {
        klock_release(&vfs_klock);
        return;
    }
    mount->self = 0;
    if (mount->filesystem == VFS_FILESYSTEM_ADYTUMFS)
        adytumfs_detach(mount_index);
    if (mount_index) {
        for (u32 index = 1; index < VFS_NODE_MAX; index++) {
            struct vfs_node_state *node = &nodes[index];
            if (!node->active || node->mount != mount_index || !node->linked)
                continue;
            node->linked = 0;
            node->parent = VFS_NODE_MAX;
            if (node->self && pending_count < VFS_NODE_MAX)
                pending[pending_count++] = node->self;
        }
    }
    if (mount->root && pending_count < VFS_NODE_MAX + 1)
        pending[pending_count++] = mount->root;
    if (mount->mountpoint && pending_count < VFS_NODE_MAX + 2)
        pending[pending_count++] = mount->mountpoint;
    mount->root = 0;
    mount->mountpoint = 0;
    mount->filesystem = 0;
    mount->active = 0;
    mount->generation++;
    if (!mount->generation) mount->generation = 1;
    klock_release(&vfs_klock);
    for (u32 index = 0; index < pending_count; index++)
        object_release(pending[index]);
}

void vfs_init(void) {
    vfs_klock.lock.ticket = 0;
    vfs_klock.lock.served = 0;
    root_object = 0;
    root_mount = 0;
    for (u32 index = 0; index < VFS_NODE_MAX; index++) {
        nodes[index].self = 0;
        nodes[index].external_data = 0;
        nodes[index].pages = 0;
        nodes[index].parent = VFS_NODE_MAX;
        nodes[index].type = 0;
        nodes[index].generation = 1;
        nodes[index].size = 0;
        nodes[index].filesystem = 0;
        nodes[index].mount = VFS_MOUNT_MAX;
        nodes[index].mount_generation = 0;
        nodes[index].readonly = 0;
        nodes[index].mode = 0;
        nodes[index].linked = 0;
        nodes[index].fs_id = 0;
        nodes[index].active = 0;
    }
    for (u32 index = 0; index < VFS_FILE_MAX; index++) {
        files[index].node = 0;
        files[index].active = 0;
    }
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++) {
        aliases[index].active = 0;
        aliases[index].node = 0;
        aliases[index].parent = 0;
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            aliases[index].name[byte] = 0;
    }
    for (u32 index = 0; index < VFS_MOUNT_MAX; index++) {
        mounts[index].self = 0;
        mounts[index].root = 0;
        mounts[index].mountpoint = 0;
        mounts[index].generation = 1;
        mounts[index].filesystem = 0;
        mounts[index].active = 0;
    }
    struct vfs_node_state *root = &nodes[0];
    root->parent = VFS_NODE_MAX;
    root->type = VFS_NODE_DIRECTORY;
    root->size = 0;
    root->filesystem = VFS_FILESYSTEM_RAMFS;
    root->mount = 0;
    root->mount_generation = 0;
    root->readonly = 0;
    root->mode = VFS_MODE_DIRECTORY_DEFAULT;
    u64 now = rtc64_wall_clock();
    u32 now_nsec = rtc64_wall_clock_nsec();
    root->atime = now;
    root->mtime = now;
    root->ctime = now;
    root->atime_nsec = now_nsec;
    root->mtime_nsec = now_nsec;
    root->ctime_nsec = now_nsec;
    root->linked = 1;
    root->active = 1;
    root->name[0] = 0;
    root_object = object_create(KOBJECT_DIRECTORY, 1, node_destroy);
    if (!root_object) {
        root->active = 0;
        return;
    }
    root->self = root_object;
    struct vfs_mount_state *mount = &mounts[0];
    if (object_retain(root_object)) return;
    mount->root = root_object;
    mount->mountpoint = 0;
    mount->filesystem = VFS_FILESYSTEM_RAMFS;
    mount->active = 1;
    root_mount = object_create(KOBJECT_MOUNT, 1, mount_destroy);
    if (!root_mount) {
        mount->active = 0;
        object_release(root_object);
    } else {
        mount->self = root_mount;
    }
}

struct kernel_object *vfs_root(void) {
    if (!root_object || !root_object->active || object_retain(root_object)) return 0;
    return root_object;
}

struct kernel_object *vfs_mount_root(void) {
    if (!root_mount || !root_mount->active || object_retain(root_mount)) return 0;
    return root_mount;
}

int vfs_unmount(struct kernel_object *directory) {
    struct vfs_mount_state *mount = mount_for_point(directory);
    if (!mount || !mount->self || !mount->active) return -1;
    u32 mount_index = (u32)(mount - mounts);
    klock_acquire(&vfs_klock);
    if (!mount->active || !mount->self) {
        klock_release(&vfs_klock);
        return -1;
    }
    if (mount->filesystem == VFS_FILESYSTEM_ADYTUMFS &&
        mount_has_open_file_locked(mount_index, mount->generation)) {
        klock_release(&vfs_klock);
        return -1;
    }
    struct kernel_object *self = mount->self;
    mount->active = 0;
    klock_release(&vfs_klock);
    object_release(self);
    return 0;
}

int vfs_mount_bootfs(struct kernel_object *directory,
                     const struct vfs_bootfs_entry *entries, u32 count) {
    struct vfs_node_state *point = node_for(directory);
    if (!point || point->type != VFS_NODE_DIRECTORY || !point->linked ||
        point->readonly || !entries || !count ||
        count > VFS_BOOTFS_ENTRY_MAX || child_count(node_index(point)) ||
        mount_for_point(directory))
        return -1;
    for (u32 index = 0; index < count; index++) {
        if (!valid_name(entries[index].name) || !entries[index].data ||
            !entries[index].size ||
            entries[index].size > VFS_BOOTFS_FILE_SIZE_MAX)
            return -1;
        for (u32 other = 0; other < index; other++)
            if (names_equal(entries[index].name, entries[other].name))
                return -1;
    }
    u32 mount_index = VFS_MOUNT_MAX;
    for (u32 index = 1; index < VFS_MOUNT_MAX; index++)
        if (!mounts[index].active) {
            mount_index = index;
            break;
        }
    if (mount_index == VFS_MOUNT_MAX) return -1;
    u32 slots[VFS_BOOTFS_ENTRY_MAX + 1];
    u32 found = 0;
    for (u32 index = 1; index < VFS_NODE_MAX && found < count + 1; index++)
        if (!nodes[index].active) slots[found++] = index;
    if (found != count + 1) return -1;
    u32 created = 0;
    for (u32 item = 0; item < count + 1; item++) {
        struct vfs_node_state *node = &nodes[slots[item]];
        node->external_data = item ? (const u8 *)entries[item - 1].data : 0;
        node->parent = item ? slots[0] : VFS_NODE_MAX;
        node->type = item ? VFS_NODE_REGULAR : VFS_NODE_DIRECTORY;
        node->size = item ? entries[item - 1].size : 0;
        node->filesystem = VFS_FILESYSTEM_BOOTFS;
        node->mount = mount_index;
        node->mount_generation = mounts[mount_index].generation;
        node->readonly = 1;
        // Boot modules are executables: read-only, but carrying X so the
        // execve permission check admits them.
        node->mode = item ? 0555u : VFS_MODE_DIRECTORY_READONLY;
        node->linked = 1;
        node->fs_id = 0;
        node->active = 1;
        const char *name = item ? entries[item - 1].name : point->name;
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            node->name[byte] = 0;
        for (u32 byte = 0; name[byte]; byte++) node->name[byte] = name[byte];
        node->self = object_create(
            item ? KOBJECT_VNODE : KOBJECT_DIRECTORY,
            slots[item] + 1, node_destroy);
        if (!node->self) {
            node->active = 0;
            for (u32 undo = 0; undo < created; undo++)
                object_release(nodes[slots[undo]].self);
            return -1;
        }
        created++;
    }
    struct vfs_mount_state *mount = &mounts[mount_index];
    if (object_retain(nodes[slots[0]].self) || object_retain(directory)) {
        if (nodes[slots[0]].self->references > 1)
            object_release(nodes[slots[0]].self);
        for (u32 undo = 0; undo < created; undo++)
            object_release(nodes[slots[undo]].self);
        return -1;
    }
    mount->root = nodes[slots[0]].self;
    mount->mountpoint = directory;
    mount->filesystem = VFS_FILESYSTEM_BOOTFS;
    mount->active = 1;
    mount->self = object_create(
        KOBJECT_MOUNT, mount_index + 1, mount_destroy);
    if (!mount->self) {
        mount->active = 0;
        mount->root = 0;
        mount->mountpoint = 0;
        mount->filesystem = 0;
        object_release(directory);
        object_release(nodes[slots[0]].self);
        for (u32 undo = 0; undo < created; undo++)
            object_release(nodes[slots[undo]].self);
        return -1;
    }
    return 0;
}

// Second names the adytumfs walk reports, held in slot space until the
// nodes exist and the pairs can materialize as VFS aliases. Mounts run one
// at a time from the kernel side, so a single buffer serves them all.
struct vfs_alias_scan {
    u32 parent;
    u32 slot;
    char name[VFS_NAME_MAX + 1];
};
static struct vfs_alias_scan alias_scan[VFS_ALIAS_MAX];
static u32 alias_scan_count;

// The walk calls back with every second name for a regular inode; the
// scan records the pair and the mount materializes the alias once the
// nodes exist. A volume carrying more hard links than the alias bound
// fails the mount rather than half-lists its names.
static int vfs_alias_sink(u32 parent, u32 slot, const char *name,
                          u32 name_len) {
    if (alias_scan_count >= VFS_ALIAS_MAX || !name || !name_len ||
        name_len > VFS_NAME_MAX)
        return -1;
    struct vfs_alias_scan *scan = &alias_scan[alias_scan_count++];
    scan->parent = parent;
    scan->slot = slot;
    for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
        scan->name[byte] = 0;
    for (u32 byte = 0; byte < name_len; byte++)
        scan->name[byte] = name[byte];
    return 0;
}

int vfs_mount_adytumfs(struct kernel_object *directory,
                      struct kernel_object *device) {
    struct vfs_node_state *point = node_for(directory);
    if (!point || point->type != VFS_NODE_DIRECTORY || !point->linked ||
        !directory || !device || child_count(node_index(point)) ||
        mount_for_point(directory))
        return -1;
    u32 mount_index = VFS_MOUNT_MAX;
    for (u32 index = 1; index < VFS_MOUNT_MAX; index++)
        if (!mounts[index].active) {
            mount_index = index;
            break;
        }
    if (mount_index == VFS_MOUNT_MAX)
        return -1;
    alias_scan_count = 0;
    if (adytumfs_attach(mount_index, device, vfs_alias_sink))
        return -1;
    u32 inode_count = adytumfs_inode_count(mount_index);
    u32 used[ADYTUMFS_INODE_MAX];
    u32 types[ADYTUMFS_INODE_MAX];
    u32 sizes[ADYTUMFS_INODE_MAX];
    u32 parents[ADYTUMFS_INODE_MAX];
    u32 modes[ADYTUMFS_INODE_MAX];
    static char names[ADYTUMFS_INODE_MAX][VFS_NAME_MAX + 1];
    u64 generations[ADYTUMFS_INODE_MAX];
    u32 inode_item[ADYTUMFS_INODE_MAX];
    u32 count = 0;
    for (u32 inode = 0; inode < inode_count; inode++) {
        inode_item[inode] = VFS_NODE_MAX;
        if (adytumfs_inode_get(mount_index, inode, &used[inode], &types[inode],
                              &sizes[inode], &parents[inode], &modes[inode],
                              names[inode], &generations[inode])) {
            adytumfs_detach(mount_index);
            return -1;
        }
        if (!used[inode]) continue;
        if ((inode && (types[inode] != VFS_NODE_REGULAR &&
                       types[inode] != VFS_NODE_DIRECTORY &&
                       types[inode] != VFS_NODE_SYMLINK)) ||
            (modes[inode] & ~VFS_MODE_MASK) ||
            (inode && (!names[inode][0] ||
                       names[inode][VFS_NAME_MAX] ||
                       !valid_name(names[inode]))) ||
            (inode && parents[inode] >= inode_count)) {
            adytumfs_detach(mount_index);
            return -1;
        }
        inode_item[inode] = count++;
    }
    if (!used[0] || types[0] != VFS_NODE_DIRECTORY || parents[0] || !count) {
        adytumfs_detach(mount_index);
        return -1;
    }
    for (u32 inode = 1; inode < inode_count; inode++) {
        if (!used[inode]) continue;
        u32 parent = parents[inode];
        if (!used[parent] || types[parent] != VFS_NODE_DIRECTORY) {
            adytumfs_detach(mount_index);
            return -1;
        }
        u32 ancestor = inode;
        for (u32 depth = 0; depth < inode_count; depth++) {
            if (!ancestor) break;
            ancestor = parents[ancestor];
            if (ancestor >= inode_count || !used[ancestor]) {
                adytumfs_detach(mount_index);
                return -1;
            }
            if (depth + 1 == inode_count) {
                adytumfs_detach(mount_index);
                return -1;
            }
        }
    }
    u32 slots[ADYTUMFS_INODE_MAX];
    u32 found = 0;
    for (u32 index = 1; index < VFS_NODE_MAX && found < count; index++)
        if (!nodes[index].active) slots[found++] = index;
    if (found != count) {
        adytumfs_detach(mount_index);
        return -1;
    }
    u32 created = 0;
    for (u32 inode = 0; inode < inode_count; inode++) {
        if (!used[inode]) continue;
        u32 item = inode_item[inode];
        struct vfs_node_state *node = &nodes[slots[item]];
        node->external_data = 0;
        node->parent = inode ? slots[inode_item[parents[inode]]] : VFS_NODE_MAX;
        node->type = types[inode];
        node->size = sizes[inode];
        node->filesystem = VFS_FILESYSTEM_ADYTUMFS;
        node->mount = mount_index;
        node->mount_generation = mounts[mount_index].generation;
        node->readonly = 0;
        node->mode = modes[inode] ? modes[inode] :
            (node->type == VFS_NODE_DIRECTORY ? VFS_MODE_DIRECTORY_DEFAULT :
             VFS_MODE_REGULAR_DEFAULT);
        node->linked = 1;
        node->fs_id = inode;
        node->fs_generation = generations[inode];
        node->active = 1;
        // A symlink node mirrors the target the volume carries in its
        // file body, the way the alias table mirrors extra names.
        if (types[inode] == VFS_NODE_SYMLINK &&
            adytumfs_symlink_target(mount_index, inode,
                                    generations[inode], node->target)) {
            node->active = 0;
            for (u32 undo = 0; undo < created; undo++)
                object_release(nodes[slots[undo]].self);
            adytumfs_detach(mount_index);
            return -1;
        }
        const char *name = inode ? names[inode] : point->name;
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            node->name[byte] = 0;
        for (u32 byte = 0; name[byte]; byte++) node->name[byte] = name[byte];
        u32 object_type = node->type == VFS_NODE_DIRECTORY ?
            KOBJECT_DIRECTORY : KOBJECT_VNODE;
        node->self = object_create(object_type, slots[item] + 1, node_destroy);
        if (!node->self) {
            node->active = 0;
            for (u32 undo = 0; undo < created; undo++)
                object_release(nodes[slots[undo]].self);
            adytumfs_detach(mount_index);
            return -1;
        }
        created++;
    }
    // Validate and count before filling: every scanned pair must map to a
    // live regular node under a live directory, and the alias table must
    // have room for the whole set, so the fill itself cannot fail halfway
    // and leave a partial mount to undo.
    for (u32 scan = 0; scan < alias_scan_count; scan++) {
        u32 node_slot = alias_scan[scan].slot;
        u32 parent_slot = alias_scan[scan].parent;
        if (node_slot >= inode_count || parent_slot >= inode_count ||
            !used[node_slot] || !used[parent_slot] ||
            types[node_slot] != VFS_NODE_REGULAR ||
            types[parent_slot] != VFS_NODE_DIRECTORY) {
            for (u32 undo = 0; undo < created; undo++)
                object_release(nodes[slots[undo]].self);
            adytumfs_detach(mount_index);
            return -1;
        }
    }
    u32 free_aliases = 0;
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++)
        if (!aliases[index].active) free_aliases++;
    if (free_aliases < alias_scan_count) {
        for (u32 undo = 0; undo < created; undo++)
            object_release(nodes[slots[undo]].self);
        adytumfs_detach(mount_index);
        return -1;
    }
    for (u32 scan = 0; scan < alias_scan_count; scan++) {
        u32 alias_slot = VFS_ALIAS_MAX;
        for (u32 index = 0; index < VFS_ALIAS_MAX; index++)
            if (!aliases[index].active) {
                alias_slot = index;
                break;
            }
        aliases[alias_slot].node =
            slots[inode_item[alias_scan[scan].slot]];
        aliases[alias_slot].parent =
            slots[inode_item[alias_scan[scan].parent]];
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            aliases[alias_slot].name[byte] = alias_scan[scan].name[byte];
        aliases[alias_slot].active = 1;
    }
    struct vfs_mount_state *mount = &mounts[mount_index];
    if (object_retain(nodes[slots[0]].self) || object_retain(directory)) {
        if (nodes[slots[0]].self->references > 1)
            object_release(nodes[slots[0]].self);
        for (u32 undo = 0; undo < created; undo++)
            object_release(nodes[slots[undo]].self);
        adytumfs_detach(mount_index);
        return -1;
    }
    mount->root = nodes[slots[0]].self;
    mount->mountpoint = directory;
    mount->filesystem = VFS_FILESYSTEM_ADYTUMFS;
    mount->active = 1;
    mount->self = object_create(
        KOBJECT_MOUNT, mount_index + 1, mount_destroy);
    if (!mount->self) {
        mount->active = 0;
        mount->root = 0;
        mount->mountpoint = 0;
        mount->filesystem = 0;
        object_release(directory);
        object_release(nodes[slots[0]].self);
        for (u32 undo = 0; undo < created; undo++)
            object_release(nodes[slots[undo]].self);
        adytumfs_detach(mount_index);
        return -1;
    }
    return 0;
}

struct kernel_object *vfs_create_mode(struct kernel_object *directory,
                                      const char *name, u32 type, u32 mode) {
    struct vfs_node_state *parent = node_for(directory);
    if (!parent || parent->type != VFS_NODE_DIRECTORY || !parent->linked ||
        parent->readonly || !valid_name(name) ||
        (type != VFS_NODE_REGULAR && type != VFS_NODE_DIRECTORY &&
         type != VFS_NODE_SYMLINK) ||
        (mode & ~VFS_MODE_MASK))
        return 0;
    u32 parent_index = node_index(parent);
    for (u32 index = 0; index < VFS_NODE_MAX; index++)
        if (nodes[index].active && nodes[index].linked &&
            nodes[index].parent == parent_index &&
            names_equal(nodes[index].name, name))
            return 0;
    for (u32 index = 1; index < VFS_NODE_MAX; index++) {
        struct vfs_node_state *node = &nodes[index];
        if (node->active) continue;
        node->external_data = 0;
        node->pages = 0;
        node->parent = parent_index;
        node->type = type;
        node->size = 0;
        node->filesystem = parent->filesystem;
        node->mount = parent->mount;
        node->mount_generation = parent->mount_generation;
        node->readonly = 0;
        node->mode = mode;
        node->uid = 0;
        node->gid = 0;
        u64 created = rtc64_wall_clock();
        u32 created_nsec = rtc64_wall_clock_nsec();
        node->atime = created;
        node->mtime = created;
        node->ctime = created;
        node->atime_nsec = created_nsec;
        node->mtime_nsec = created_nsec;
        node->ctime_nsec = created_nsec;
        node->special = VFS_SPECIAL_NONE;
        node->linked = 1;
        node->fs_id = 0;
        node->fs_generation = 0;
        node->active = 1;
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            node->name[byte] = 0;
        for (u32 byte = 0; name[byte]; byte++) node->name[byte] = name[byte];
        for (u32 byte = 0; byte < VFS_PATH_MAX; byte++)
            node->target[byte] = 0;
        if (parent->filesystem == VFS_FILESYSTEM_ADYTUMFS &&
            adytumfs_inode_create(parent->mount, name, parent->fs_id, type,
                                 mode, &node->fs_id, &node->fs_generation)) {
            node->linked = 0;
            node->active = 0;
            return 0;
        }
        u32 object_type = type == VFS_NODE_DIRECTORY ?
            KOBJECT_DIRECTORY : KOBJECT_VNODE;
        struct kernel_object *object = object_create(
            object_type, index + 1, node_destroy);
        if (!object) {
            if (node->fs_id)
                adytumfs_inode_remove(parent->mount, node->fs_id);
            node->linked = 0;
            node->active = 0;
            return 0;
        }
        node->self = object;
        if (object_retain(object)) {
            if (node->fs_id)
                adytumfs_inode_remove(parent->mount, node->fs_id);
            node->linked = 0;
            object_release(object);
            return 0;
        }
        return object;
    }
    return 0;
}

struct kernel_object *vfs_create(struct kernel_object *directory,
                                 const char *name, u32 type) {
    u32 mode = type == VFS_NODE_DIRECTORY ? VFS_MODE_DIRECTORY_DEFAULT :
        VFS_MODE_REGULAR_DEFAULT;
    return vfs_create_mode(directory, name, type, mode);
}

struct kernel_object *vfs_create_urandom(struct kernel_object *directory) {
    struct kernel_object *object = vfs_create_mode(
        directory, "urandom", VFS_NODE_REGULAR, VFS_MODE_REGULAR_READONLY);
    if (!object) return 0;
    struct vfs_node_state *node = node_for(object);
    node->special = VFS_SPECIAL_URANDOM;
    node->readonly = 1;
    node->size = VFS_FILE_SIZE_MAX;
    return object;
}

// The null device: reads answer end of file, writes go nowhere, and the
// mode mirrors /dev/urandom because both are read-write character nodes.
struct kernel_object *vfs_create_null(struct kernel_object *directory) {
    struct kernel_object *object = vfs_create_mode(
        directory, "null", VFS_NODE_REGULAR, VFS_MODE_REGULAR_DEFAULT);
    if (!object) return 0;
    struct vfs_node_state *node = node_for(object);
    node->special = VFS_SPECIAL_NULL;
    node->readonly = 0;
    node->size = 0;
    return object;
}

struct kernel_object *vfs_create_console(struct kernel_object *directory) {
    struct kernel_object *object = vfs_create_mode(
        directory, "console", VFS_NODE_REGULAR, VFS_MODE_REGULAR_DEFAULT);
    if (!object) return 0;
    struct vfs_node_state *node = node_for(object);
    node->special = VFS_SPECIAL_CONSOLE;
    node->readonly = 0;
    node->size = 0;
    return object;
}

struct kernel_object *vfs_create_tty(struct kernel_object *directory) {
    struct kernel_object *object = vfs_create_mode(
        directory, "tty", VFS_NODE_REGULAR, VFS_MODE_REGULAR_DEFAULT);
    if (!object) return 0;
    struct vfs_node_state *node = node_for(object);
    node->special = VFS_SPECIAL_TTY;
    node->readonly = 0;
    node->size = 0;
    return object;
}

struct kernel_object *vfs_symlink(struct kernel_object *directory,
                                  const char *name, const char *target) {
    // The target lives inline in the node, so it is bounded by the path
    // bound: a longer one could never be resolved anyway.
    if (!target || !target[0]) return 0;
    u32 length = 0;
    while (length < VFS_PATH_MAX && target[length]) length++;
    if (length >= VFS_PATH_MAX) return 0;
    struct kernel_object *object = vfs_create_mode(
        directory, name, VFS_NODE_SYMLINK, VFS_MODE_SYMLINK_DEFAULT);
    if (!object) return 0;
    struct vfs_node_state *node = node_for(object);
    // The volume keeps the string in the inode's file body and one commit
    // lands the whole link; failing that unwinds the fresh inode rather
    // than leaving a link without a target on the disk.
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS &&
        adytumfs_symlink_write(node->mount, node->fs_id,
                               node->fs_generation, target)) {
        node->linked = 0;
        adytumfs_inode_remove(node->mount, node->fs_id);
        // Creating the node took two references on the same object, one for
        // the node table and one for the handle about to be returned. A failed
        // link returns no handle, so both have to go. Dropping only the handle
        // left the table holding a node that is no longer linked, and mount
        // teardown skips unlinked nodes, so the node outlived every later
        // unmount and the volume it belonged to.
        object_release(node->self);
        object_release(object);
        return 0;
    }
    for (u32 byte = 0; byte < length; byte++)
        node->target[byte] = target[byte];
    node->target[length] = 0;
    node->size = length;
    return object;
}

int vfs_readlink(struct kernel_object *node_object, char *buffer, u32 size,
                 u32 *length) {
    struct vfs_node_state *node = node_for(node_object);
    if (!node || node->type != VFS_NODE_SYMLINK || !buffer || !size ||
        !length)
        return -1;
    u32 count = 0;
    while (node->target[count] && count < VFS_PATH_MAX) count++;
    // The caller owns a buffer of the path bound; a shorter one is a
    // contract violation rather than the truncation POSIX readlink does.
    if (count + 1u > size) return -1;
    for (u32 byte = 0; byte < count; byte++)
        buffer[byte] = node->target[byte];
    buffer[count] = 0;
    *length = count;
    return 0;
}

struct kernel_object *vfs_lookup(struct kernel_object *directory,
                                 const char *name) {
    struct vfs_node_state *parent = node_for(directory);
    if (!parent || parent->type != VFS_NODE_DIRECTORY || !valid_name(name))
        return 0;
    u32 parent_index = node_index(parent);
    for (u32 index = 0; index < VFS_NODE_MAX; index++) {
        struct vfs_node_state *node = &nodes[index];
        if (!node->active || !node->linked || node->parent != parent_index ||
            !names_equal(node->name, name))
            continue;
        struct vfs_mount_state *mount = mount_for_point(node->self);
        struct kernel_object *result = mount ? mount->root : node->self;
        if (object_retain(result)) return 0;
        return result;
    }
    // An extra hard-link name resolves to the same inode object.
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++) {
        struct vfs_alias_state *alias = &aliases[index];
        if (!alias->active || alias->parent != parent_index ||
            !names_equal(alias->name, name))
            continue;
        struct kernel_object *result = nodes[alias->node].self;
        if (!result || object_retain(result)) return 0;
        return result;
    }
    return 0;
}

static int path_length(const char *path, u32 *length) {
    if (!path || !length || !path[0]) return -1;
    u32 count = 0;
    while (count < VFS_PATH_MAX && path[count]) count++;
    if (!count || count == VFS_PATH_MAX) return -1;
    *length = count;
    return 0;
}

static struct kernel_object *resolve_path(struct kernel_object *start,
                                          const char *path, int confine) {
    u32 length;
    if (path_length(path, &length)) return 0;
    // A confined resolve is scoped to start, so an absolute path (which would
    // begin the walk at the global root) is an escape by definition.
    if (confine && path[0] == '/') return 0;
    struct kernel_object *current;
    u32 offset = 0;
    if (path[0] == '/') {
        current = vfs_root();
        while (offset < length && path[offset] == '/') offset++;
    } else {
        struct vfs_node_state *node = node_for(start);
        if (!node || node->type != VFS_NODE_DIRECTORY ||
            object_retain(start))
            return 0;
        current = start;
    }
    if (!current) return 0;
    u32 components = 0;
    while (offset < length) {
        while (offset < length && path[offset] == '/') offset++;
        if (offset == length) break;
        char component[VFS_NAME_MAX + 1];
        for (u32 index = 0; index <= VFS_NAME_MAX; index++)
            component[index] = 0;
        u32 component_length = 0;
        while (offset < length && path[offset] != '/') {
            if (component_length >= VFS_NAME_MAX) {
                object_release(current);
                return 0;
            }
            component[component_length++] = path[offset++];
        }
        components++;
        if (components > VFS_PATH_COMPONENT_MAX) {
            object_release(current);
            return 0;
        }
        if (component_length == 1 && component[0] == '.') continue;
        if (component_length == 2 && component[0] == '.' &&
            component[1] == '.') {
            struct vfs_node_state *node = node_for(current);
            if (!node || node->type != VFS_NODE_DIRECTORY) {
                object_release(current);
                return 0;
            }
            // Confined resolution treats start as the top of the namespace: an
            // ascent past it, directly or across a mountpoint, is a scope escape
            // and fails rather than climbing into the parent tree.
            if (confine && current == start) {
                object_release(current);
                return 0;
            }
            u32 parent_index = node->parent;
            if (parent_index == VFS_NODE_MAX) {
                struct vfs_mount_state *mount = mount_for_root(current);
                struct vfs_node_state *point = mount ?
                    node_for(mount->mountpoint) : 0;
                if (!point) continue;
                parent_index = point->parent;
                if (parent_index == VFS_NODE_MAX) continue;
            }
            struct vfs_node_state *parent = &nodes[parent_index];
            if (!parent->active || !parent->linked || !parent->self ||
                object_retain(parent->self)) {
                object_release(current);
                return 0;
            }
            object_release(current);
            current = parent->self;
            continue;
        }
        struct kernel_object *next = vfs_lookup(current, component);
        object_release(current);
        if (!next) return 0;
        current = next;
    }
    if (length > 1 && path[length - 1] == '/') {
        struct vfs_node_state *node = node_for(current);
        if (!node || node->type != VFS_NODE_DIRECTORY) {
            object_release(current);
            return 0;
        }
    }
    return current;
}

int vfs_node_identity(struct kernel_object *object,
                      struct vfs_node_identity *identity) {
    struct vfs_node_state *node = node_for(object);
    if (!node || !identity) return -1;
    identity->slot = node_index(node);
    identity->generation = node->generation;
    identity->parent = node->parent;
    identity->parent_generation = 0;
    if (node->parent != VFS_NODE_MAX && nodes[node->parent].active)
        identity->parent_generation = nodes[node->parent].generation;
    identity->type = node->type;
    for (u32 index = 0; index <= VFS_NAME_MAX; index++)
        identity->name[index] = node->name[index];
    return 0;
}

struct kernel_object *vfs_node_parent(struct kernel_object *object) {
    struct vfs_node_state *node = node_for(object);
    if (!node) return 0;
    if (node->parent != VFS_NODE_MAX) {
        struct vfs_node_state *parent = &nodes[node->parent];
        if (parent->active && parent->self &&
            !object_retain(parent->self))
            return parent->self;
        return 0;
    }
    struct vfs_mount_state *mount = mount_for_root(object);
    if (mount && !object_retain(mount->mountpoint))
        return mount->mountpoint;
    return 0;
}

struct kernel_object *vfs_resolve(struct kernel_object *start,
                                  const char *path) {
    return resolve_path(start, path, 0);
}

struct kernel_object *vfs_resolve_beneath(struct kernel_object *start,
                                          const char *path) {
    return resolve_path(start, path, 1);
}

static struct kernel_object *path_parent(struct kernel_object *start,
                                         const char *path, char *leaf) {
    u32 length;
    if (path_length(path, &length) || !leaf) return 0;
    while (length > 1 && path[length - 1] == '/') length--;
    u32 leaf_start = length;
    while (leaf_start && path[leaf_start - 1] != '/') leaf_start--;
    u32 leaf_length = length - leaf_start;
    if (!leaf_length || leaf_length > VFS_NAME_MAX) return 0;
    for (u32 index = 0; index <= VFS_NAME_MAX; index++) leaf[index] = 0;
    for (u32 index = 0; index < leaf_length; index++)
        leaf[index] = path[leaf_start + index];
    if (!valid_name(leaf)) return 0;
    if (!leaf_start) {
        struct vfs_node_state *node = node_for(start);
        if (!node || node->type != VFS_NODE_DIRECTORY || object_retain(start))
            return 0;
        return start;
    }
    char parent_path[VFS_PATH_MAX];
    for (u32 index = 0; index < VFS_PATH_MAX; index++) parent_path[index] = 0;
    u32 parent_length = leaf_start;
    while (parent_length > 1 && path[parent_length - 1] == '/')
        parent_length--;
    for (u32 index = 0; index < parent_length; index++)
        parent_path[index] = path[index];
    if (!parent_length) {
        parent_path[0] = '.';
        parent_path[1] = 0;
    }
    return vfs_resolve(start, parent_path);
}

struct kernel_object *vfs_create_path(struct kernel_object *start,
                                      const char *path, u32 type) {
    char leaf[VFS_NAME_MAX + 1];
    struct kernel_object *parent = path_parent(start, path, leaf);
    if (!parent) return 0;
    struct kernel_object *created = vfs_create(parent, leaf, type);
    object_release(parent);
    return created;
}

int vfs_unlink_path(struct kernel_object *start, const char *path) {
    char leaf[VFS_NAME_MAX + 1];
    struct kernel_object *parent = path_parent(start, path, leaf);
    if (!parent) return -1;
    int result = vfs_unlink(parent, leaf);
    object_release(parent);
    return result;
}

static int vfs_unlink_locked(struct kernel_object *directory, const char *name,
                             struct kernel_object **dropped) {
    struct vfs_node_state *parent = node_for(directory);
    if (!parent || parent->type != VFS_NODE_DIRECTORY || parent->readonly ||
        !valid_name(name))
        return -1;
    u32 parent_index = node_index(parent);
    for (u32 index = 1; index < VFS_NODE_MAX; index++) {
        struct vfs_node_state *node = &nodes[index];
        if (!node->active || !node->linked || node->parent != parent_index ||
            !names_equal(node->name, name))
            continue;
        if (node->readonly || mount_for_point(node->self) ||
            (node->type == VFS_NODE_DIRECTORY && child_count(index)))
            return -1;
        struct vfs_alias_state *alias = alias_for_node(index);
        // The disk entry leaves before the in-memory promotion: a crash
        // between the two leaves a stale-high link count, never a VFS
        // name the disk no longer carries. The last name defers its
        // reclaim to the final close when a descriptor still holds the
        // inode.
        if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS && node->fs_id &&
            adytumfs_unlink(node->mount, node->fs_id, node->fs_generation,
                            nodes[parent_index].fs_id, node->name, !alias &&
                            node_has_open_file_locked(node->self)))
            return -1;
        // Losing the primary name promotes the first alias into the node,
        // so a hard link survives with one name fewer rather than dying.
        if (alias) {
            node->parent = alias->parent;
            for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
                node->name[byte] = alias->name[byte];
            alias->active = 0;
            return 0;
        }
        node->linked = 0;
        node->parent = VFS_NODE_MAX;
        *dropped = node->self;
        return 0;
    }
    // The name may belong to an alias rather than the node itself; the
    // primary name keeps the inode alive behind it.
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++) {
        struct vfs_alias_state *alias = &aliases[index];
        if (!alias->active || alias->parent != parent_index ||
            !names_equal(alias->name, name))
            continue;
        struct vfs_node_state *node = &nodes[alias->node];
        // The alias entry leaves the disk the same way the primary one
        // does; the inode keeps its remaining names and their count.
        if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS && node->fs_id &&
            adytumfs_unlink(node->mount, node->fs_id, node->fs_generation,
                            nodes[alias->parent].fs_id, alias->name, 0))
            return -1;
        alias->active = 0;
        return 0;
    }
    return -1;
}

int vfs_unlink(struct kernel_object *directory, const char *name) {
    struct kernel_object *dropped = 0;
    klock_acquire(&vfs_klock);
    int result = vfs_unlink_locked(directory, name, &dropped);
    klock_release(&vfs_klock);
    if (dropped) object_release(dropped);
    return result;
}

int vfs_link(struct kernel_object *node_object,
             struct kernel_object *directory, const char *name) {
    struct vfs_node_state *node = node_for(node_object);
    struct vfs_node_state *parent = node_for(directory);
    if (!node || !node_backing_live(node) || !node->linked ||
        node->type != VFS_NODE_REGULAR || !parent ||
        parent->type != VFS_NODE_DIRECTORY || !parent->linked ||
        parent->readonly || !valid_name(name) ||
        parent->filesystem != node->filesystem ||
        (node->filesystem != VFS_FILESYSTEM_RAMFS &&
         node->filesystem != VFS_FILESYSTEM_ADYTUMFS))
        return -1;
    struct kernel_object *existing = vfs_lookup(directory, name);
    if (existing) {
        object_release(existing);
        return -1;
    }
    if (alias_count(node_index(node)) + 1u >= VFS_ALIAS_MAX) return -1;
    // The disk name lands before the alias entry: a crash between the two
    // leaves a stale-high link count, never a VFS alias without its disk
    // name. Cross-volume links die here too: one inode cannot span two
    // superblocks.
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS &&
        (node->mount != parent->mount ||
         node->mount_generation != parent->mount_generation ||
         adytumfs_inode_link(node->mount, node->fs_id, node->fs_generation,
                             parent->fs_id, name)))
        return -1;
    for (u32 index = 0; index < VFS_ALIAS_MAX; index++) {
        struct vfs_alias_state *alias = &aliases[index];
        if (alias->active) continue;
        alias->node = node_index(node);
        alias->parent = node_index(parent);
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            alias->name[byte] = 0;
        for (u32 byte = 0; name[byte]; byte++)
            alias->name[byte] = name[byte];
        alias->active = 1;
        return 0;
    }
    return -1;
}

static int vfs_rename_locked(struct kernel_object *old_directory,
                             const char *name,
                             struct kernel_object *new_directory,
                             const char *new_name,
                             struct kernel_object **dropped) {
    struct vfs_node_state *old_parent = node_for(old_directory);
    struct vfs_node_state *new_parent = node_for(new_directory);
    if (!old_parent || old_parent->type != VFS_NODE_DIRECTORY ||
        !old_parent->linked || !valid_name(name) || !new_parent ||
        new_parent->type != VFS_NODE_DIRECTORY || !new_parent->linked ||
        !valid_name(new_name) || old_parent->readonly ||
        new_parent->readonly)
        return -1;
    u32 old_index = node_index(old_parent);
    u32 new_index = node_index(new_parent);
    // The name being moved is either the primary dentry or an alias.
    struct vfs_node_state *node = 0;
    for (u32 index = 1; index < VFS_NODE_MAX && !node; index++) {
        struct vfs_node_state *scan = &nodes[index];
        if (scan->active && scan->linked && scan->parent == old_index &&
            names_equal(scan->name, name))
            node = scan;
    }
    struct vfs_alias_state *source_alias = 0;
    if (!node) {
        for (u32 index = 0; index < VFS_ALIAS_MAX && !source_alias; index++) {
            struct vfs_alias_state *alias = &aliases[index];
            if (alias->active && alias->parent == old_index &&
                names_equal(alias->name, name)) {
                source_alias = alias;
                node = &nodes[alias->node];
            }
        }
    }
    if (!node || !node->active) return -1;
    // The name being replaced, when it exists, is either kind too.
    struct vfs_node_state *target = 0;
    for (u32 index = 1; index < VFS_NODE_MAX && !target; index++) {
        struct vfs_node_state *scan = &nodes[index];
        if (scan->active && scan->linked && scan->parent == new_index &&
            names_equal(scan->name, new_name))
            target = scan;
    }
    if (!target) {
        for (u32 index = 0; index < VFS_ALIAS_MAX; index++) {
            struct vfs_alias_state *alias = &aliases[index];
            if (!alias->active || alias->parent != new_index ||
                !names_equal(alias->name, new_name))
                continue;
            target = &nodes[alias->node];
            break;
        }
    }
    // Renaming onto itself, under either of its names, is a quiet success
    // that changes nothing, and so is the literal same dentry.
    if (target == node) return 0;
    if (old_index == new_index && names_equal(name, new_name)) return 0;
    // A mountpoint keeps its name while the mount lives on it.
    if (mount_for_point(node->self)) return -1;
    if (node->type == VFS_NODE_DIRECTORY) {
        // The global root and every mount root sit outside any parent and
        // cannot be picked up by name.
        if (node->parent == VFS_NODE_MAX) return -1;
        // A directory cannot land inside its own subtree.
        for (u32 ancestor = new_index; ancestor != VFS_NODE_MAX;
             ancestor = nodes[ancestor].parent)
            if (ancestor == node_index(node)) return -1;
    }
    if (target) {
        if (mount_for_point(target->self)) return -1;
        if (target->type != node->type) return -1;
    }
    // One inode cannot span filesystems, or two mounts of the same one.
    if (node->filesystem != new_parent->filesystem ||
        (node->filesystem == VFS_FILESYSTEM_ADYTUMFS &&
         (node->mount != new_parent->mount ||
          node->mount_generation != new_parent->mount_generation)))
        return -1;
    // The replaced name leaves first and uncommitted, so the adytumfs
    // move below can land in the same staging window and commit both
    // edits under one superblock flip.
    if (target && vfs_unlink_locked(new_directory, new_name, dropped))
        return -1;
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS &&
        adytumfs_rename(node->mount, node->fs_id, node->fs_generation,
                        nodes[old_index].fs_id, name,
                        nodes[new_index].fs_id, new_name))
        return -1;
    node->ctime = rtc64_wall_clock();
    node->ctime_nsec = rtc64_wall_clock_nsec();
    if (source_alias) {
        source_alias->parent = new_index;
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            source_alias->name[byte] = 0;
        for (u32 byte = 0; new_name[byte]; byte++)
            source_alias->name[byte] = new_name[byte];
        return 0;
    }
    node->parent = new_index;
    for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
        node->name[byte] = 0;
    for (u32 byte = 0; new_name[byte]; byte++)
        node->name[byte] = new_name[byte];
    return 0;
}

int vfs_rename(struct kernel_object *old_directory, const char *name,
               struct kernel_object *new_directory, const char *new_name) {
    struct kernel_object *dropped = 0;
    klock_acquire(&vfs_klock);
    int result = vfs_rename_locked(old_directory, name, new_directory,
                                   new_name, &dropped);
    klock_release(&vfs_klock);
    // The replaced name is already gone when a later step fails, so the
    // release happens on every path, not only on success.
    if (dropped) object_release(dropped);
    return result;
}

int vfs_image(struct kernel_object *object, const u8 **data, u32 *size) {
    struct vfs_node_state *node = node_for(object);
    if (!node || !node_backing_live(node) ||
        node->type != VFS_NODE_REGULAR || !node->size || !data || !size)
        return -1;
    // Page-backed files have no single contiguous image; bootfs modules do.
    if (!node->external_data) return -1;
    *data = node->external_data;
    *size = node->size;
    return 0;
}

struct kernel_object *vfs_open(struct kernel_object *object) {
    klock_acquire(&vfs_klock);
    struct vfs_node_state *node = node_for(object);
    // Directories open read-only so getdents can list them; the read and
    // write paths below still require a regular node.
    if (!node || !node_backing_live(node) ||
        (node->type != VFS_NODE_REGULAR &&
         node->type != VFS_NODE_DIRECTORY)) {
        klock_release(&vfs_klock);
        return 0;
    }
    for (u32 index = 0; index < VFS_FILE_MAX; index++) {
        struct vfs_file_state *file = &files[index];
        if (file->active) continue;
        if (object_retain(object)) {
            klock_release(&vfs_klock);
            return 0;
        }
        file->node = object;
        file->active = 1;
        struct kernel_object *opened = object_create(
            KOBJECT_FILE, index + 1, file_destroy);
        if (!opened) {
            file->node = 0;
            file->active = 0;
            object_release(object);
        }
        klock_release(&vfs_klock);
        return opened;
    }
    klock_release(&vfs_klock);
    return 0;
}

static int adytumfs_pages_ready(struct vfs_node_state *node, u32 end) {
    if (!node->pages) {
        node->pages = page_resource_create();
        if (!node->pages) return -1;
        if (adytumfs_pages_attach(node->mount, node->fs_id,
                                  node->fs_generation, node->pages)) {
            object_release(node->pages);
            node->pages = 0;
            return -1;
        }
    }
    struct page_resource *resource = page_resource_get(node->pages);
    if (!resource) return -1;
    u32 needed = (end + 4095) / 4096;
    if (needed > resource->pages &&
        page_resource_grow(node->pages, needed))
        return -1;
    for (u32 page = 0; page < needed; page++)
        if (adytumfs_pages_fault(node->mount, node->fs_id, node->fs_generation,
                                 page))
            return -1;
    return 0;
}

int vfs_read(struct kernel_object *object, u32 offset,
             void *buffer, u32 length, u32 *transferred) {
    struct vfs_file_state *file = file_for(object);
    struct vfs_node_state *node = file ? node_for(file->node) : 0;
    if (!node || !node_backing_live(node) || node->type != VFS_NODE_REGULAR ||
        !buffer || !transferred)
        return -1;
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS) {
        if (offset >= node->size) {
            *transferred = 0;
            return 0;
        }
        u32 count = node->size - offset;
        if (count > length) count = length;
        if (adytumfs_pages_ready(node, offset + count)) return -1;
        struct page_resource *resource = page_resource_get(node->pages);
        if (!resource) return -1;
        u32 done = 0;
        while (done < count) {
            u32 position = offset + done;
            u32 within = position % 4096;
            u32 chunk = 4096 - within;
            if (chunk > count - done) chunk = count - done;
            const u8 *source =
                (const u8 *)(uptr_t)resource->physical[position / 4096];
            if (!source) return -1;
            for (u32 index = 0; index < chunk; index++)
                ((u8 *)buffer)[done + index] = source[within + index];
            done += chunk;
        }
        if (count &&
            adytumfs_touch(node->mount, node->fs_id, node->fs_generation,
                           ADYTUMFS_TOUCH_ATIME))
            return -1;
        *transferred = count;
        return 0;
    }
    if (node->special == VFS_SPECIAL_URANDOM) {
        // Character-device semantics: every read returns fresh bytes and
        // the file offset carries no meaning.
        u32 count = length;
        if (count > ENTROPY_FILL_MAX) count = ENTROPY_FILL_MAX;
        if (entropy_fill(buffer, count)) return -1;
        *transferred = count;
        return 0;
    }
    if (node->special == VFS_SPECIAL_NULL) {
        *transferred = 0;
        return 0;
    }
    if (node->special == VFS_SPECIAL_CONSOLE ||
        node->special == VFS_SPECIAL_TTY) {
        int result = posix_tty_read(0, (u8 *)buffer, length, transferred);
        if (result == POSIX_TTY_EAGAIN) {
            *transferred = 0;
            return 0;
        }
        return result;
    }
    if (offset >= node->size) {
        *transferred = 0;
        return 0;
    }
    u32 count = node->size - offset;
    if (count > length) count = length;
    if (node->external_data) {
        for (u32 index = 0; index < count; index++)
            ((u8 *)buffer)[index] = node->external_data[offset + index];
        *transferred = count;
        return 0;
    }
    struct page_resource *resource =
        node->pages ? page_resource_get(node->pages) : 0;
    u32 done = 0;
    while (done < count) {
        u32 position = offset + done;
        u32 within = position % 4096;
        u32 chunk = 4096 - within;
        if (chunk > count - done) chunk = count - done;
        const u8 *source = 0;
        if (resource && position / 4096 < resource->pages)
            source = (const u8 *)(uptr_t)resource->physical[position / 4096];
        if (source)
            for (u32 index = 0; index < chunk; index++)
                ((u8 *)buffer)[done + index] = source[within + index];
        else
            for (u32 index = 0; index < chunk; index++)
                ((u8 *)buffer)[done + index] = 0;
        done += chunk;
    }
    // Same relatime-lite rule as the adytumfs backend: reads do not dirty
    // the node once atime has caught up with the last write.
    if (count && node->atime < node->mtime) {
        node->atime = rtc64_wall_clock();
        node->atime_nsec = rtc64_wall_clock_nsec();
    }
    *transferred = count;
    return 0;
}

static int write_node_locked(struct vfs_node_state *node, u32 offset,
                      const void *buffer, u32 length, u32 *transferred) {
    if (!node || !node_backing_live(node) || node->readonly ||
        node->type != VFS_NODE_REGULAR || node->external_data || !buffer ||
        !transferred || offset > VFS_FILE_SIZE_MAX ||
        length > VFS_FILE_SIZE_MAX - offset)
        return -1;
    if (node->special == VFS_SPECIAL_NULL) {
        *transferred = length;
        return 0;
    }
    if (node->special == VFS_SPECIAL_CONSOLE ||
        node->special == VFS_SPECIAL_TTY)
        return posix_tty_write(0, (const u8 *)buffer, length, transferred);
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS) {
        if (offset > ADYTUMFS_FILE_SIZE_MAX ||
            length > ADYTUMFS_FILE_SIZE_MAX - offset)
            return -1;
        u32 end = offset + length;
        if (length) {
            if (adytumfs_pages_ready(node, end)) return -1;
            struct page_resource *resource = page_resource_get(node->pages);
            if (!resource) return -1;
            u32 size = end > node->size ? end : node->size;
            u32 done = 0;
            while (done < length) {
                u32 position = offset + done;
                u32 within = position % 4096;
                u32 chunk = 4096 - within;
                if (chunk > length - done) chunk = length - done;
                u8 *target = (u8 *)(uptr_t)resource->physical[position / 4096];
                if (!target) return -1;
                for (u32 index = 0; index < chunk; index++)
                    target[within + index] = ((const u8 *)buffer)[done + index];
                if (adytumfs_pages_dirty(node->mount, node->fs_id,
                                        node->fs_generation, position / 4096,
                                        size))
                    return -1;
                done += chunk;
            }
        }
        if (end > node->size) node->size = end;
        if (length &&
            adytumfs_touch(node->mount, node->fs_id, node->fs_generation,
                           ADYTUMFS_TOUCH_MTIME | ADYTUMFS_TOUCH_CTIME))
            return -1;
        *transferred = length;
        return 0;
    }
    u32 end = offset + length;
    if (length) {
        if (!node->pages) {
            node->pages = page_resource_create();
            if (!node->pages) return -1;
        }
        struct page_resource *resource = page_resource_get(node->pages);
        if (!resource) return -1;
        u32 needed = (end + 4095) / 4096;
        if (needed > resource->pages &&
            page_resource_grow(node->pages, needed))
            return -1;
        u32 done = 0;
        while (done < length) {
            u32 position = offset + done;
            u32 within = position % 4096;
            u32 chunk = 4096 - within;
            if (chunk > length - done) chunk = length - done;
            u8 *target = (u8 *)(uptr_t)resource->physical[position / 4096];
            for (u32 index = 0; index < chunk; index++)
                target[within + index] = ((const u8 *)buffer)[done + index];
            done += chunk;
        }
    }
    if (end > node->size) node->size = end;
    if (length) {
        u64 written = rtc64_wall_clock();
        u32 written_nsec = rtc64_wall_clock_nsec();
        node->mtime = written;
        node->ctime = written;
        node->mtime_nsec = written_nsec;
        node->ctime_nsec = written_nsec;
    }
    *transferred = length;
    return 0;
}

int vfs_write(struct kernel_object *object, u32 offset,
              const void *buffer, u32 length, u32 *transferred) {
    struct vfs_file_state *file = file_for(object);
    struct vfs_node_state *node = file ? node_for(file->node) : 0;
    klock_acquire(&vfs_klock);
    int result = write_node_locked(node, offset, buffer, length, transferred);
    klock_release(&vfs_klock);
    return result;
}

int vfs_append(struct kernel_object *object, const void *buffer, u32 length,
               u32 *transferred, u32 *position) {
    struct vfs_file_state *file = file_for(object);
    struct vfs_node_state *node = file ? node_for(file->node) : 0;
    if (!position) return -1;
    klock_acquire(&vfs_klock);
    u32 offset = node ? node->size : 0;
    int result = write_node_locked(node, offset, buffer, length, transferred);
    if (!result) *position = offset + *transferred;
    klock_release(&vfs_klock);
    return result;
}

static int truncate_node_locked(struct vfs_node_state *node, u32 size) {
    if (!node || !node_backing_live(node) || node->readonly ||
        node->type != VFS_NODE_REGULAR || node->external_data ||
        size > VFS_FILE_SIZE_MAX)
        return -1;
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS) {
        u32 new_size = 0;
        if (adytumfs_pages_sync(node->mount, node->fs_id,
                                node->fs_generation))
            return -1;
        int result = adytumfs_truncate(node->mount, node->fs_id,
                                      node->fs_generation, size, &new_size);
        if (!result && node->pages) {
            adytumfs_pages_detach(node->mount, node->fs_id,
                                  node->fs_generation);
            object_release(node->pages);
            node->pages = 0;
        }
        if (!result) node->size = new_size;
        return result;
    }
    if (node->pages) {
        struct page_resource *resource = page_resource_get(node->pages);
        u32 kept = (size + 4095) / 4096;
        if (resource && kept < resource->pages &&
            page_resource_trim(node->pages, kept))
            return -1;
        if (size % 4096) {
            u8 *bytes = resource && kept - 1 < resource->pages ?
                (u8 *)(uptr_t)resource->physical[kept - 1] : 0;
            if (bytes)
                for (u32 index = size % 4096; index < 4096; index++)
                    bytes[index] = 0;
        }
    }
    node->size = size;
    u64 trimmed = rtc64_wall_clock();
    u32 trimmed_nsec = rtc64_wall_clock_nsec();
    node->mtime = trimmed;
    node->ctime = trimmed;
    node->mtime_nsec = trimmed_nsec;
    node->ctime_nsec = trimmed_nsec;
    return 0;
}

int vfs_sync(struct kernel_object *object) {
    struct vfs_file_state *file = file_for(object);
    struct vfs_node_state *node = file ? node_for(file->node) : 0;
    if (!node || !node_backing_live(node)) return -1;
    if (node->filesystem != VFS_FILESYSTEM_ADYTUMFS) return 0;
    klock_acquire(&vfs_klock);
    int result = adytumfs_pages_sync(node->mount, node->fs_id,
                                     node->fs_generation);
    klock_release(&vfs_klock);
    return result;
}

int vfs_truncate(struct kernel_object *object, u32 size) {
    struct vfs_file_state *file = file_for(object);
    struct vfs_node_state *node = file ? node_for(file->node) : 0;
    klock_acquire(&vfs_klock);
    int result = truncate_node_locked(node, size);
    klock_release(&vfs_klock);
    return result;
}

int vfs_fsync(struct kernel_object *object) {
    struct vfs_file_state *file = file_for(object);
    struct vfs_node_state *node = file ? node_for(file->node) : 0;
    if (!node || !node_backing_live(node)) return -1;
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS) {
        klock_acquire(&vfs_klock);
        // pages_sync is the staging path: it moves the dirty pages of this
        // file through the redirect machinery, and the commit it ends with
        // lands the whole open window, so the disk copy is durable up to
        // this call.
        int result = adytumfs_pages_sync(node->mount, node->fs_id,
                                         node->fs_generation);
        klock_release(&vfs_klock);
        return result;
    }
    // The ramfs keeps its bytes in memory only, so a durability call has
    // nothing further to push.
    return 0;
}

int vfs_special(struct kernel_object *file, u32 *special) {
    struct vfs_file_state *state = file_for(file);
    struct vfs_node_state *node = state ? node_for(state->node) : 0;
    if (!node || !special) return -1;
    *special = node->special;
    return 0;
}

int vfs_stat(struct kernel_object *object, struct vfs_node_info *info) {
    struct vfs_node_state *node = node_for(object);
    if (!node) {
        struct vfs_file_state *file = file_for(object);
        node = file ? node_for(file->node) : 0;
    }
    if (!node || !node_backing_live(node) || !info) return -1;
    info->type = node->type;
    info->generation = node->generation;
    info->size = node->size;
    info->child_count = node->type == VFS_NODE_DIRECTORY ?
        child_count(node_index(node)) : 0;
    info->linked = node->linked;
    info->filesystem = node->filesystem;
    info->readonly = node->readonly;
    info->mode = node->mode;
    info->links = node->type == VFS_NODE_DIRECTORY ? 2u :
        1u + alias_count(node_index(node));
    info->uid = node->uid;
    info->gid = node->gid;
    info->atime = node->atime;
    info->mtime = node->mtime;
    info->ctime = node->ctime;
    info->atime_nsec = node->atime_nsec;
    info->mtime_nsec = node->mtime_nsec;
    // The on-disk inode is the source of truth for an adytumfs node: link
    // count, ownership, and times are read live through the window staging
    // rather than cached in the node.
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS) {
        u16 links = 0;
        if (adytumfs_inode_meta(node->mount, node->fs_id,
                                node->fs_generation, &links, &info->uid,
                                &info->gid, &info->atime, &info->mtime,
                                &info->ctime, &info->atime_nsec,
                                &info->mtime_nsec, 0))
            return -1;
        info->links = links;
    }
    // A directory reports 2 at creation (self plus the parent entry) plus
    // one per subdirectory, counted from the live table both filesystems
    // keep in sync.
    if (node->type == VFS_NODE_DIRECTORY)
        info->links = 2u + directory_children(node_index(node));
    for (u32 index = 0; index <= VFS_NAME_MAX; index++)
        info->name[index] = node->name[index];
    return 0;
}

static int vfs_chmod_locked(struct kernel_object *object, u32 mode) {
    struct vfs_node_state *node = node_for(object);
    if (!node) {
        struct vfs_file_state *file = file_for(object);
        node = file ? node_for(file->node) : 0;
    }
    if (!node || !node_backing_live(node) || (mode & ~VFS_MODE_MASK))
        return -1;
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS)
        return adytumfs_inode_update(node->mount, node->fs_id,
                                     node->fs_generation, ADYTUMFS_SET_MODE,
                                     mode, 0, 0);
    node->mode = mode;
    node->ctime = rtc64_wall_clock();
    node->ctime_nsec = rtc64_wall_clock_nsec();
    return 0;
}

int vfs_chmod(struct kernel_object *object, u32 mode) {
    klock_acquire(&vfs_klock);
    int result = vfs_chmod_locked(object, mode);
    klock_release(&vfs_klock);
    return result;
}

static int vfs_chown_locked(struct kernel_object *object, u32 uid, u32 gid) {
    struct vfs_node_state *node = node_for(object);
    if (!node) {
        struct vfs_file_state *file = file_for(object);
        node = file ? node_for(file->node) : 0;
    }
    if (!node || !node_backing_live(node)) return -1;
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS)
        return adytumfs_inode_update(node->mount, node->fs_id,
                                     node->fs_generation,
                                     ADYTUMFS_SET_UID | ADYTUMFS_SET_GID, 0,
                                     uid, gid);
    // chown to the ids the node already carries is a no-op, so the posix
    // create path can stamp ownership without dirtying a fresh node.
    if (node->uid == uid && node->gid == gid) return 0;
    node->uid = uid;
    node->gid = gid;
    node->ctime = rtc64_wall_clock();
    node->ctime_nsec = rtc64_wall_clock_nsec();
    return 0;
}

int vfs_chown(struct kernel_object *object, u32 uid, u32 gid) {
    klock_acquire(&vfs_klock);
    int result = vfs_chown_locked(object, uid, gid);
    klock_release(&vfs_klock);
    return result;
}

static int vfs_set_times_locked(struct kernel_object *object, u32 flags,
                                u64 atime, u32 atime_nsec, u64 mtime,
                                u32 mtime_nsec) {
    struct vfs_node_state *node = node_for(object);
    if (!node) {
        struct vfs_file_state *file = file_for(object);
        node = file ? node_for(file->node) : 0;
    }
    if (!node || !node_backing_live(node) ||
        (flags & ~(VFS_TIME_SET_ATIME | VFS_TIME_SET_MTIME)))
        return -1;
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS)
        return adytumfs_set_times(node->mount, node->fs_id,
                                  node->fs_generation, flags, atime,
                                  atime_nsec, mtime, mtime_nsec);
    u32 changed = 0;
    if ((flags & VFS_TIME_SET_ATIME) &&
        (node->atime != atime || node->atime_nsec != atime_nsec)) {
        node->atime = atime;
        node->atime_nsec = atime_nsec;
        changed = 1;
    }
    if ((flags & VFS_TIME_SET_MTIME) &&
        (node->mtime != mtime || node->mtime_nsec != mtime_nsec)) {
        node->mtime = mtime;
        node->mtime_nsec = mtime_nsec;
        changed = 1;
    }
    // Restating the stored values is a no-op, so ctime only moves when a
    // timestamp really changed, the rule the adytumfs backend holds too.
    if (!changed) return 0;
    node->ctime = rtc64_wall_clock();
    node->ctime_nsec = rtc64_wall_clock_nsec();
    return 0;
}

int vfs_set_times(struct kernel_object *object, u32 flags, u64 atime,
                  u32 atime_nsec, u64 mtime, u32 mtime_nsec) {
    klock_acquire(&vfs_klock);
    int result = vfs_set_times_locked(object, flags, atime, atime_nsec, mtime,
                                      mtime_nsec);
    klock_release(&vfs_klock);
    return result;
}

int vfs_read_dir(struct kernel_object *object, u64 *cursor, char *name,
                 u32 *name_len, u64 *inode_out, u32 *type_out) {
    struct vfs_file_state *file = file_for(object);
    struct vfs_node_state *node = file ? node_for(file->node) : 0;
    if (!node || !node_backing_live(node) ||
        node->type != VFS_NODE_DIRECTORY || !cursor || !name || !name_len ||
        !inode_out || !type_out)
        return -1;
    // A mountpoint lists the mounted tree, the same redirect lookup does.
    struct vfs_mount_state *mount = mount_for_point(node->self);
    if (mount) {
        struct vfs_node_state *root = node_for(mount->root);
        if (!root || root->type != VFS_NODE_DIRECTORY) return -1;
        node = root;
    }
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS)
        return adytumfs_dir_read(node->mount, node->fs_id,
                                 node->fs_generation, cursor, name, name_len,
                                 inode_out, type_out);
    // Ramfs and bootfs children live in the node table, so the cursor is
    // the node index the previous call stopped at.
    u32 parent = node_index(node);
    for (u32 index = (u32)*cursor; index < VFS_NODE_MAX; index++) {
        struct vfs_node_state *child = &nodes[index];
        if (!child->active || !child->linked || child->parent != parent)
            continue;
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            name[byte] = child->name[byte];
        *name_len = 0;
        while (name[*name_len]) (*name_len)++;
        *inode_out = index + 1;
        *type_out = child->type;
        *cursor = index + 1;
        return 0;
    }
    // Hard-link names continue the cursor past the node table and report
    // the inode number of the node they name.
    u32 alias_cursor = (u32)*cursor;
    alias_cursor = alias_cursor > VFS_NODE_MAX ?
        alias_cursor - VFS_NODE_MAX : 0;
    for (u32 index = alias_cursor; index < VFS_ALIAS_MAX; index++) {
        struct vfs_alias_state *alias = &aliases[index];
        if (!alias->active || alias->parent != parent) continue;
        for (u32 byte = 0; byte <= VFS_NAME_MAX; byte++)
            name[byte] = alias->name[byte];
        *name_len = 0;
        while (name[*name_len]) (*name_len)++;
        *inode_out = alias->node + 1;
        *type_out = nodes[alias->node].type;
        *cursor = VFS_NODE_MAX + index + 1;
        return 0;
    }
    *cursor = VFS_NODE_MAX + VFS_ALIAS_MAX;
    return 1;
}

struct kernel_object *vfs_file_pages(struct kernel_object *object,
                                     u32 *size) {
    struct vfs_file_state *file = file_for(object);
    struct vfs_node_state *node = file ? node_for(file->node) : 0;
    if (!node || !node_backing_live(node) || !size) return 0;
    if (node->filesystem == VFS_FILESYSTEM_ADYTUMFS) {
        // A mapping exposes the whole extent, so every page has to hold disk
        // contents before userspace can reach it.
        klock_acquire(&vfs_klock);
        int ready = adytumfs_pages_ready(node, node->size ? node->size : 4096);
        klock_release(&vfs_klock);
        if (ready) return 0;
    }
    if (!node->pages || object_retain(node->pages)) return 0;
    *size = node->size;
    return node->pages;
}

struct kernel_object *vfs_node_pages(struct kernel_object *object,
                                     u32 *size) {
    struct vfs_node_state *node = node_for(object);
    if (!node || !node->pages || !node_backing_live(node) || !size)
        return 0;
    // Senders get their own reference; the node keeps its backing until
    // both the link and every loan die.
    if (object_retain(node->pages)) return 0;
    *size = node->size;
    return node->pages;
}

u32 vfs_node_active_count(void) {
    u32 count = 0;
    for (u32 index = 0; index < VFS_NODE_MAX; index++)
        if (nodes[index].active) count++;
    return count;
}

u32 vfs_file_active_count(void) {
    u32 count = 0;
    for (u32 index = 0; index < VFS_FILE_MAX; index++)
        if (files[index].active) count++;
    return count;
}

u32 vfs_mount_active_count(void) {
    u32 count = 0;
    for (u32 index = 0; index < VFS_MOUNT_MAX; index++)
        if (mounts[index].active) count++;
    return count;
}
