#include "posix_profile.h"
#include "posix_pledge.h"
#include "task.h"
#include "object.h"
#include "spinlock.h"

struct posix_profile_state {
    struct kernel_object *cwd;
    u32 active;
    u32 vfs_authority;
    u32 detached;
    char cwd_path[VFS_PATH_MAX];
};

static struct posix_profile_state profiles[MAX_TASKS];
static struct spinlock posix_profile_lock = SPINLOCK_INIT;

static int task_slot(const struct task *task) {
    uptr_t address = (uptr_t)task;
    uptr_t base = (uptr_t)task_pool;
    if (!task || address < base || address >= base + sizeof(task_pool) ||
        (address - base) % sizeof(struct task))
        return -1;
    return (int)((address - base) / sizeof(struct task));
}

static int copy_path(char *destination, const char *source) {
    if (!destination || !source || !source[0]) return POSIX_PROFILE_EINVAL;
    for (u32 index = 0; index < VFS_PATH_MAX; index++) {
        destination[index] = source[index];
        if (!source[index]) return 0;
    }
    return POSIX_PROFILE_ENAMETOOLONG;
}

static void clear_profile(struct posix_profile_state *profile) {
    profile->cwd = 0;
    profile->active = 0;
    profile->vfs_authority = 0;
    profile->detached = 0;
    for (u32 index = 0; index < VFS_PATH_MAX; index++)
        profile->cwd_path[index] = 0;
}

static int profile_snapshot(struct task *task, int relative,
                            struct kernel_object **cwd, char *cwd_path) {
    int slot = task_slot(task);
    if (slot < 0 || !cwd || !cwd_path) return POSIX_PROFILE_EINVAL;
    spin_lock(&posix_profile_lock);
    struct posix_profile_state *profile = &profiles[slot];
    int denied = !profile->active || !profile->vfs_authority;
    int detached = relative && profile->detached;
    if (denied || detached || (relative && object_retain(profile->cwd))) {
        spin_unlock(&posix_profile_lock);
        return denied ? POSIX_PROFILE_EACCES : POSIX_PROFILE_ENOENT;
    }
    int result = relative ? copy_path(cwd_path, profile->cwd_path) : 0;
    if (result && relative) object_release(profile->cwd);
    if (relative) *cwd = result ? 0 : profile->cwd;
    else *cwd = 0;
    spin_unlock(&posix_profile_lock);
    return result;
}

static int append_component(char *path, u32 *length, const char *component,
                            u32 component_length) {
    if (!path || !length || !component || !component_length ||
        component_length > VFS_NAME_MAX)
        return POSIX_PROFILE_ENAMETOOLONG;
    if (*length > 1 && *length + 1 >= VFS_PATH_MAX)
        return POSIX_PROFILE_ENAMETOOLONG;
    if (*length > 1) path[(*length)++] = '/';
    if (*length + component_length >= VFS_PATH_MAX)
        return POSIX_PROFILE_ENAMETOOLONG;
    for (u32 index = 0; index < component_length; index++)
        path[*length + index] = component[index];
    *length += component_length;
    path[*length] = 0;
    return 0;
}

static void remove_component(char *path, u32 *length) {
    if (*length <= 1) return;
    while (*length > 1 && path[*length - 1] != '/') (*length)--;
    if (*length > 1) (*length)--;
    path[*length] = 0;
}

static int append_normalized(char *path, u32 *length, const char *source,
                             u32 *components) {
    u32 offset = 0;
    while (source[offset]) {
        while (source[offset] == '/') offset++;
        if (!source[offset]) break;
        char component[VFS_NAME_MAX + 1];
        u32 component_length = 0;
        while (source[offset] && source[offset] != '/') {
            if (component_length >= VFS_NAME_MAX)
                return POSIX_PROFILE_ENAMETOOLONG;
            component[component_length++] = source[offset++];
        }
        component[component_length] = 0;
        (*components)++;
        if (*components > VFS_PATH_COMPONENT_MAX)
            return POSIX_PROFILE_ENAMETOOLONG;
        if (component_length == 1 && component[0] == '.') continue;
        if (component_length == 2 && component[0] == '.' &&
            component[1] == '.') {
            remove_component(path, length);
            continue;
        }
        int result = append_component(path, length, component, component_length);
        if (result) return result;
    }
    return 0;
}

static int path_terminated(const char *path) {
    if (!path || !path[0]) return POSIX_PROFILE_EINVAL;
    for (u32 index = 0; index < VFS_PATH_MAX; index++)
        if (!path[index]) return 0;
    return POSIX_PROFILE_ENAMETOOLONG;
}

static int normalize_path(const char *base, const char *path, char *normalized) {
    if (!normalized) return POSIX_PROFILE_EINVAL;
    int path_result = path_terminated(path);
    if (path_result) return path_result;
    u32 length = 1;
    u32 components = 0;
    normalized[0] = '/';
    normalized[1] = 0;
    if (path[0] != '/') {
        if (!base || base[0] != '/') return POSIX_PROFILE_ENOENT;
        int result = append_normalized(normalized, &length, base, &components);
        if (result) return result;
    }
    return append_normalized(normalized, &length, path, &components);
}

// The honest three columns: owner, group, other. A single gid, no
// supplementary groups, and no root override, so the columns are the whole
// story and every task gets the same arithmetic.
int posix_mode_allows(const struct vfs_node_info *info,
                      const struct task *task, u32 want) {
    // want arrives in owner-column notation (0100 is X, 0300 is W+X), the
    // way POSIX writes permission bits, and slides into the caller's column.
    u32 shift = info->uid == task->uid ? 6u :
        info->gid == task->gid ? 3u : 0u;
    u32 column = (info->mode >> shift) & 7u;
    u32 bits = (want >> 6) & 7u;
    return (column & bits) == bits;
}

// Splice a symlink target into the walk: an absolute target restarts the
// walk at the root, a relative one takes the place of the component the
// link was found under. The hop budget is the POSIX symloop bound.
//
// The splice happens in place rather than through follow_link. That shape
// recursed, and the recursion was not one the compiler collapsed into a
// jump, so every hop stacked four path buffers; at the real path bound a
// symloop chain ran past the syscall stack instead of returning ELOOP.
static int walk_path(struct task *task, const char *path,
                     struct kernel_object **node) {
    char work[VFS_PATH_MAX];
    char base[VFS_PATH_MAX];
    // The spliced string can outgrow the path bound before normalization
    // shrinks it back, so the splice buffer is twice as wide.
    char splice[VFS_PATH_MAX * 2];
    u32 length = 0;
    while (path[length] && length + 1u < sizeof(work)) {
        work[length] = path[length];
        length++;
    }
    if (path[length]) return POSIX_PROFILE_ENAMETOOLONG;
    work[length] = 0;
    u32 depth = 0;
    struct kernel_object *current = vfs_root();
    if (!current) return POSIX_PROFILE_ENOMEM;
    u32 offset = 1;
    for (;;) {
        struct vfs_node_info info;
        if (vfs_stat(current, &info) || !info.linked) {
            object_release(current);
            return POSIX_PROFILE_ENOENT;
        }
        if (!work[offset]) {
            *node = current;
            return 0;
        }
        if (info.type != VFS_NODE_DIRECTORY) {
            object_release(current);
            return POSIX_PROFILE_ENOTDIR;
        }
        if (!posix_mode_allows(&info, task, 0100u)) {
            object_release(current);
            return POSIX_PROFILE_EACCES;
        }
        char component[VFS_NAME_MAX + 1];
        u32 component_length = 0;
        u32 start = offset;
        while (work[offset] && work[offset] != '/') {
            if (component_length >= VFS_NAME_MAX) {
                object_release(current);
                return POSIX_PROFILE_ENAMETOOLONG;
            }
            component[component_length++] = work[offset++];
        }
        component[component_length] = 0;
        struct kernel_object *next = vfs_lookup(current, component);
        object_release(current);
        if (!next) return POSIX_PROFILE_ENOENT;
        struct vfs_node_info link_info;
        if (vfs_stat(next, &link_info)) {
            object_release(next);
            return POSIX_PROFILE_EIO;
        }
        if (link_info.type != VFS_NODE_SYMLINK) {
            current = next;
            if (work[offset] == '/') offset++;
            continue;
        }
        // The target lands at the front of the splice buffer, then the
        // unconsumed tail of the walk is appended after it. Both reads
        // finish before work is overwritten with the normalized result.
        u32 used = 0;
        int broken = vfs_readlink(next, splice, sizeof(splice), &used);
        object_release(next);
        if (broken) return POSIX_PROFILE_EIO;
        if (depth >= 8u) return POSIX_PROFILE_ELOOP;
        u32 kept = start > 1u ? start - 1u : 1u;
        for (u32 index = 0; index < kept; index++) base[index] = work[index];
        base[kept] = 0;
        const char *rest = work + offset;
        while (*rest == '/') rest++;
        if (rest[0] && used + 1u < sizeof(splice)) {
            splice[used++] = '/';
            while (*rest && used < sizeof(splice)) splice[used++] = *rest++;
        }
        if (used >= sizeof(splice)) return POSIX_PROFILE_ENAMETOOLONG;
        splice[used] = 0;
        int result = normalize_path(splice[0] == '/' ? "/" : base, splice,
                                    work);
        if (result) return result;
        depth++;
        offset = 1;
        current = vfs_root();
        if (!current) return POSIX_PROFILE_ENOMEM;
    }
}

static int resolve_path(struct task *task, const char *path,
                        struct kernel_object **node, char *normalized) {
    if (!node || !normalized || !path || !path[0]) return POSIX_PROFILE_EINVAL;
    struct kernel_object *cwd = 0;
    char cwd_path[VFS_PATH_MAX];
    for (u32 index = 0; index < VFS_PATH_MAX; index++) cwd_path[index] = 0;
    int relative = path[0] != '/';
    int result = profile_snapshot(task, relative, &cwd, cwd_path);
    if (result) return result;
    result = normalize_path(relative ? cwd_path : "/", path, normalized);
    if (cwd) object_release(cwd);
    if (result) return result;
    return walk_path(task, normalized, node);
}

void posix_profile_init(void) {
    posix_profile_lock.ticket = 0;
    posix_profile_lock.served = 0;
    for (u32 index = 0; index < MAX_TASKS; index++)
        clear_profile(&profiles[index]);
}

int posix_profile_admit(struct task *task) {
    int slot = task_slot(task);
    if (slot < 0) return POSIX_PROFILE_EINVAL;
    struct kernel_object *root = vfs_root();
    if (!root) return POSIX_PROFILE_ENOMEM;
    spin_lock(&posix_profile_lock);
    struct posix_profile_state *profile = &profiles[slot];
    if (profile->active) {
        spin_unlock(&posix_profile_lock);
        object_release(root);
        return POSIX_PROFILE_EBUSY;
    }
    profile->cwd = root;
    profile->active = 1;
    profile->vfs_authority = 1;
    profile->detached = 0;
    profile->cwd_path[0] = '/';
    profile->cwd_path[1] = 0;
    spin_unlock(&posix_profile_lock);
    // Credentials are seeded at admit, the POSIX birth of a task: the
    // single-credential world starts every process at uid 0 with the 022
    // umask POSIX defaults to.
    task->uid = 0;
    task->gid = 0;
    task->umask = 022u;
    return 0;
}

int posix_profile_fork(struct task *parent, struct task *child) {
    int parent_slot = task_slot(parent);
    int child_slot = task_slot(child);
    if (parent_slot < 0 || child_slot < 0 || parent_slot == child_slot)
        return POSIX_PROFILE_EINVAL;
    spin_lock(&posix_profile_lock);
    struct posix_profile_state *source = &profiles[parent_slot];
    struct posix_profile_state *target = &profiles[child_slot];
    if (target->active || !source->active) {
        spin_unlock(&posix_profile_lock);
        return target->active ? POSIX_PROFILE_EBUSY : 0;
    }
    if (!source->cwd || object_retain(source->cwd)) {
        spin_unlock(&posix_profile_lock);
        return POSIX_PROFILE_ENOMEM;
    }
    target->cwd = source->cwd;
    target->active = 1;
    target->vfs_authority = source->vfs_authority;
    target->detached = source->detached;
    for (u32 index = 0; index < VFS_PATH_MAX; index++)
        target->cwd_path[index] = source->cwd_path[index];
    spin_unlock(&posix_profile_lock);
    return 0;
}

void posix_profile_release(struct task *task) {
    int slot = task_slot(task);
    if (slot < 0) return;
    spin_lock(&posix_profile_lock);
    struct posix_profile_state *profile = &profiles[slot];
    struct kernel_object *cwd = profile->cwd;
    clear_profile(profile);
    spin_unlock(&posix_profile_lock);
    if (cwd) object_release(cwd);
}

int posix_profile_admitted(const struct task *task) {
    int slot = task_slot(task);
    if (slot < 0) return 0;
    spin_lock(&posix_profile_lock);
    int admitted = profiles[slot].active;
    spin_unlock(&posix_profile_lock);
    return admitted;
}

int posix_profile_vfs_authorized(const struct task *task) {
    int slot = task_slot(task);
    if (slot < 0) return 0;
    spin_lock(&posix_profile_lock);
    int authorized = profiles[slot].active && profiles[slot].vfs_authority;
    spin_unlock(&posix_profile_lock);
    return authorized;
}

int posix_profile_resolve(struct task *task, const char *path,
                          struct kernel_object **node) {
    if (!node) return POSIX_PROFILE_EINVAL;
    *node = 0;
    char normalized[VFS_PATH_MAX];
    return resolve_path(task, path, node, normalized);
}

int posix_profile_parent(struct task *task, const char *path,
                         struct kernel_object **parent,
                         char name[VFS_NAME_MAX + 1]) {
    if (!parent || !name || !path || !path[0]) return POSIX_PROFILE_EINVAL;
    *parent = 0;
    char normalized[VFS_PATH_MAX];
    struct kernel_object *cwd = 0;
    char cwd_path[VFS_PATH_MAX];
    for (u32 index = 0; index < VFS_PATH_MAX; index++) cwd_path[index] = 0;
    int relative = path[0] != '/';
    int result = profile_snapshot(task, relative, &cwd, cwd_path);
    if (result) return result;
    result = normalize_path(relative ? cwd_path : "/", path, normalized);
    if (cwd) object_release(cwd);
    if (result) return result;
    u32 length = 0;
    while (length < VFS_PATH_MAX && normalized[length]) length++;
    if (length <= 1 || length == VFS_PATH_MAX)
        return POSIX_PROFILE_EINVAL;
    u32 leaf = length;
    while (leaf > 1 && normalized[leaf - 1] != '/') leaf--;
    u32 name_length = length - leaf;
    if (!name_length || name_length > VFS_NAME_MAX)
        return POSIX_PROFILE_ENAMETOOLONG;
    for (u32 index = 0; index <= VFS_NAME_MAX; index++) name[index] = 0;
    for (u32 index = 0; index < name_length; index++)
        name[index] = normalized[leaf + index];
    char parent_path[VFS_PATH_MAX];
    for (u32 index = 0; index < VFS_PATH_MAX; index++) parent_path[index] = 0;
    if (leaf == 1) {
        parent_path[0] = '/';
        parent_path[1] = 0;
    } else {
        for (u32 index = 0; index < leaf - 1; index++)
            parent_path[index] = normalized[index];
    }
    return walk_path(task, parent_path, parent);
}

int posix_profile_chdir(struct task *task, const char *path) {
    int veiled = posix_pledge_veil_check(task, path, POSIX_VEIL_READ, 0);
    if (veiled) return veiled;
    struct kernel_object *node = 0;
    char normalized[VFS_PATH_MAX];
    int result = resolve_path(task, path, &node, normalized);
    if (result) return result;
    struct vfs_node_info info;
    if (vfs_stat(node, &info) || !info.linked) {
        object_release(node);
        return POSIX_PROFILE_ENOENT;
    }
    if (info.type != VFS_NODE_DIRECTORY) {
        object_release(node);
        return POSIX_PROFILE_ENOTDIR;
    }
    if (!posix_mode_allows(&info, task, 0100u)) {
        object_release(node);
        return POSIX_PROFILE_EACCES;
    }
    int slot = task_slot(task);
    if (slot < 0) {
        object_release(node);
        return POSIX_PROFILE_EINVAL;
    }
    spin_lock(&posix_profile_lock);
    struct posix_profile_state *profile = &profiles[slot];
    if (!profile->active || !profile->vfs_authority) {
        spin_unlock(&posix_profile_lock);
        object_release(node);
        return POSIX_PROFILE_EACCES;
    }
    struct kernel_object *old = profile->cwd;
    profile->cwd = node;
    profile->detached = 0;
    for (u32 index = 0; index < VFS_PATH_MAX; index++)
        profile->cwd_path[index] = normalized[index];
    spin_unlock(&posix_profile_lock);
    if (old) object_release(old);
    return 0;
}

int posix_profile_getcwd(struct task *task, char path[VFS_PATH_MAX]) {
    if (!path) return POSIX_PROFILE_EINVAL;
    struct kernel_object *cwd = 0;
    char cwd_path[VFS_PATH_MAX];
    int result = profile_snapshot(task, 1, &cwd, cwd_path);
    if (result) return result;
    struct vfs_node_info info;
    int detached = vfs_stat(cwd, &info) || !info.linked;
    if (detached) {
        int slot = task_slot(task);
        if (slot >= 0) {
            spin_lock(&posix_profile_lock);
            if (profiles[slot].cwd == cwd) profiles[slot].detached = 1;
            spin_unlock(&posix_profile_lock);
        }
        object_release(cwd);
        return POSIX_PROFILE_ENOENT;
    }
    object_release(cwd);
    for (u32 index = 0; index < VFS_PATH_MAX; index++) {
        path[index] = cwd_path[index];
        if (!cwd_path[index]) return 0;
    }
    return POSIX_PROFILE_ENAMETOOLONG;
}
