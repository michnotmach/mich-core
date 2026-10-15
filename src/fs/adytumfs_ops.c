#include "adytumfs_format.h"
#include "adytumfs_tree.h"

int adytumfs_path_resolve(struct kernel_object *device,
                          struct adytumfs_superblock *super,
                          struct adytumfs_cas *store, const char *path,
                          u64 *out_inode) {
    if (!path || !out_inode || path[0] != '/') return -1;
    u64 current = super->root_inode;
    u32 index = 1;
    while (path[index]) {
        u32 start = index;
        while (path[index] && path[index] != '/') index++;
        u32 length = index - start;
        if (length > ADYTUMFS_NAME_MAX) return -1;
        // Empty components (a leading, trailing, or doubled slash) are skipped.
        if (length > 0) {
            u64 child;
            if (adytumfs_dir_lookup(device, super, store, current, path + start, length,
                                    &child))
                return -1;
            current = child;
        }
        if (path[index] == '/') index++;
    }
    *out_inode = current;
    return 0;
}

int adytumfs_create_at(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u64 parent_inode,
                       const char *name, u32 name_len, u16 mode,
                       u64 *out_inode) {
    if (mode == 0 || name_len == 0 || name_len > ADYTUMFS_NAME_MAX) return -1;
    struct adytumfs_inode parent;
    if (adytumfs_inode_read(device, super, parent_inode, &parent)) return -1;
    if ((parent.mode & ADYTUMFS_MODE_DIR) == 0) return -1;

    u64 target;
    if (adytumfs_inode_alloc(device, super, mode, &target)) return -1;
    u8 type = (mode & ADYTUMFS_MODE_DIR) ? (u8)ADYTUMFS_DTYPE_DIR :
        (mode & ADYTUMFS_MODE_LNK) ? (u8)ADYTUMFS_DTYPE_LNK :
        (u8)ADYTUMFS_DTYPE_REG;
    // dir_add rejects a duplicate name; roll the inode back so a failed create
    // does not leak an allocated slot.
    if (adytumfs_dir_add(device, super, store, parent_inode, name, name_len, target,
                         type)) {
        adytumfs_inode_free(device, super, target);
        return -1;
    }
    if (out_inode) *out_inode = target;
    return 0;
}

int adytumfs_unlink_at(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u64 parent_inode,
                       const char *name, u32 name_len) {
    if (name_len == 0 || name_len > ADYTUMFS_NAME_MAX) return -1;
    u64 target;
    if (adytumfs_dir_lookup(device, super, store, parent_inode, name, name_len,
                            &target))
        return -1;
    struct adytumfs_inode inode;
    if (adytumfs_inode_read(device, super, target, &inode)) return -1;
    // Directory removal has its own emptiness rules and belongs to rmdir; this
    // path handles regular files only.
    if ((inode.mode & ADYTUMFS_MODE_REG) == 0) return -1;
    // Reclaim the file's data blocks before the directory entry and inode go.
    if (adytumfs_inode_truncate(device, super, store, &inode, target, 0))
        return -1;
    if (adytumfs_dir_remove(device, super, store, parent_inode, name, name_len))
        return -1;
    return adytumfs_inode_free(device, super, target);
}
