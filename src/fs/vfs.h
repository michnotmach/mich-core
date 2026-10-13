#ifndef VFS_H
#define VFS_H

#include "types.h"
#include "object.h"
#include "resource.h"

#define VFS_NODE_MAX 512
// Hard-link names beyond the primary dentry: one alias table entry per extra
// name, shared by every filesystem the VFS fronts.
#define VFS_ALIAS_MAX 16u
#define VFS_FILE_MAX 32
#define VFS_MOUNT_MAX 8
// Longest path component, POSIX NAME_MAX; name buffers hold one more
// byte for the terminator.
#define VFS_NAME_MAX 255
// Ramfs regular files are page-backed, so the bound is the page resource.
#define VFS_FILE_SIZE_MAX (RESOURCE_PAGE_PAGES_MAX * 4096u)
#define VFS_PATH_MAX 256
#define VFS_PATH_COMPONENT_MAX 32

#define VFS_NODE_REGULAR 1
#define VFS_NODE_DIRECTORY 2
#define VFS_NODE_SYMLINK 3

// Special nodes generate their content at read time instead of storing
// it, so size and offset carry no meaning for them.
#define VFS_SPECIAL_NONE 0u
#define VFS_SPECIAL_URANDOM 1u
#define VFS_SPECIAL_NULL 2u
#define VFS_SPECIAL_CONSOLE 3u
// The controlling terminal of the calling process. One line exists in the
// profile, so the node resolves to it and the open refuses when the
// caller's group does not hold the line.
#define VFS_SPECIAL_TTY 4u

#define VFS_FILESYSTEM_RAMFS 1
#define VFS_FILESYSTEM_BOOTFS 2
#define VFS_FILESYSTEM_ADYTUMFS 3
#define VFS_BOOTFS_ENTRY_MAX 16
#define VFS_BOOTFS_FILE_SIZE_MAX 0x100000

#define VFS_MODE_MASK 0777u
#define VFS_MODE_REGULAR_DEFAULT 0666u
#define VFS_MODE_DIRECTORY_DEFAULT 0777u
// POSIX ignores the mode a symlink is created with, so it keeps the
// permissive default rather than a second meaning of the same bits.
#define VFS_MODE_SYMLINK_DEFAULT 0777u
#define VFS_MODE_REGULAR_READONLY 0444u
#define VFS_MODE_DIRECTORY_READONLY 0555u

struct vfs_node_info {
    u32 type;
    u32 generation;
    u32 size;
    u32 child_count;
    u32 linked;
    u32 filesystem;
    u32 readonly;
    u32 mode;
    u32 links;
    u32 uid;
    u32 gid;
    u64 atime;
    u64 mtime;
    u64 ctime;
    // Nanoseconds inside the atime and mtime seconds. ctime stays a kernel
    // secret: no POSIX stat consumer reads it, so the record does not carry
    // what nobody asks for.
    u32 atime_nsec;
    u32 mtime_nsec;
    char name[VFS_NAME_MAX + 1];
};

struct vfs_bootfs_entry {
    const char *name;
    const void *data;
    u32 size;
};

void vfs_init(void);
struct kernel_object *vfs_root(void);
struct kernel_object *vfs_mount_root(void);
int vfs_mount_bootfs(struct kernel_object *directory,
                     const struct vfs_bootfs_entry *entries, u32 count);
int vfs_mount_adytumfs(struct kernel_object *directory,
                      struct kernel_object *device);
int vfs_unmount(struct kernel_object *directory);
struct kernel_object *vfs_create(struct kernel_object *directory,
                                 const char *name, u32 type);
struct kernel_object *vfs_create_urandom(struct kernel_object *directory);
struct kernel_object *vfs_create_null(struct kernel_object *directory);
struct kernel_object *vfs_create_console(struct kernel_object *directory);
struct kernel_object *vfs_create_tty(struct kernel_object *directory);
struct kernel_object *vfs_create_mode(struct kernel_object *directory,
                                      const char *name, u32 type, u32 mode);
struct kernel_object *vfs_lookup(struct kernel_object *directory,
                                 const char *name);
struct kernel_object *vfs_resolve(struct kernel_object *start,
                                  const char *path);
// Resolves path relative to start with start as the top of the namespace: any
// ".." that would ascend past start, and any absolute path, fails closed.
struct kernel_object *vfs_resolve_beneath(struct kernel_object *start,
                                          const char *path);
struct kernel_object *vfs_create_path(struct kernel_object *start,
                                      const char *path, u32 type);
int vfs_unlink_path(struct kernel_object *start, const char *path);
int vfs_unlink(struct kernel_object *directory, const char *name);
int vfs_link(struct kernel_object *node, struct kernel_object *directory,
             const char *name);
int vfs_rename(struct kernel_object *old_directory, const char *name,
               struct kernel_object *new_directory, const char *new_name);
struct kernel_object *vfs_symlink(struct kernel_object *directory,
                                  const char *name, const char *target);
int vfs_readlink(struct kernel_object *node, char *buffer, u32 size,
                 u32 *length);
struct kernel_object *vfs_open(struct kernel_object *node);
int vfs_image(struct kernel_object *node, const u8 **data, u32 *size);
int vfs_read(struct kernel_object *file, u32 offset,
             void *buffer, u32 length, u32 *transferred);
int vfs_write(struct kernel_object *file, u32 offset,
              const void *buffer, u32 length, u32 *transferred);
int vfs_append(struct kernel_object *file, const void *buffer, u32 length,
               u32 *transferred, u32 *position);
int vfs_truncate(struct kernel_object *file, u32 size);
int vfs_fsync(struct kernel_object *file);
int vfs_sync(struct kernel_object *file);
int vfs_stat(struct kernel_object *object, struct vfs_node_info *info);
// The special-node kind behind an open file: the posix layer routes reads,
// writes and ioctls by it without reaching into the vfs state itself.
int vfs_special(struct kernel_object *file, u32 *special);
// One used directory entry per call into name: 0 for an entry, 1 at the
// end, -1 on error. The cursor is opaque and advances past the entry.
int vfs_read_dir(struct kernel_object *file, u64 *cursor, char *name,
                 u32 *name_len, u64 *inode, u32 *type);
int vfs_chmod(struct kernel_object *object, u32 mode);
int vfs_chown(struct kernel_object *object, u32 uid, u32 gid);
// Explicit atime and mtime edits, the vfs face of utimensat and futimens.
// The flags name the pair to replace and ctime moves when anything did.
#define VFS_TIME_SET_ATIME 1u
#define VFS_TIME_SET_MTIME 2u
int vfs_set_times(struct kernel_object *object, u32 flags, u64 atime,
                  u32 atime_nsec, u64 mtime, u32 mtime_nsec);
struct kernel_object *vfs_node_pages(struct kernel_object *node,
                                      u32 *size);
struct kernel_object *vfs_file_pages(struct kernel_object *file,
                                      u32 *size);
// Identity of a live node for the POSIX unveil veil: the stable
// (slot, generation) pair, the parent link, and the leaf name. A slot is
// reused only with a new generation, so a remembered pair never names a
// different node. parent is VFS_NODE_MAX for namespace roots; a mount
// root climbs to its mountpoint through vfs_node_parent so veil walks do
// not stop at a filesystem boundary.
struct vfs_node_identity {
    u32 slot;
    u32 generation;
    u32 parent;
    u32 parent_generation;
    u32 type;
    char name[VFS_NAME_MAX + 1];
};

int vfs_node_identity(struct kernel_object *object,
                      struct vfs_node_identity *identity);
// The retained parent of a node: the containing directory, the
// mountpoint for a mount root, or 0 at the global root.
struct kernel_object *vfs_node_parent(struct kernel_object *object);

u32 vfs_node_active_count(void);
u32 vfs_file_active_count(void);
u32 vfs_mount_active_count(void);

#endif
