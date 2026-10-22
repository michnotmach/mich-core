#ifndef ADYTUMFS_H
#define ADYTUMFS_H

#include "types.h"
#include "object.h"

// Files are addressed by their on-disk inode number, which the superblock
// allocates upward and never reuses inside a generation, so there is no
// renumbering table to rebuild at attach and no bound on how many files a
// volume may hold. This is the bound on how many of them keep a page cache
// open at once.
#define ADYTUMFS_CACHE_MAX 256
#define ADYTUMFS_FILE_PAGES 256
#define ADYTUMFS_FILE_SIZE_MAX (ADYTUMFS_FILE_PAGES * 4096u)

int adytumfs_format(struct kernel_object *device);
// Attach reads the superblock and opens the content store. Nothing walks the
// namespace: a mount is usable as soon as the volume's root inode resolves,
// and the caller meets files one directory entry at a time.
int adytumfs_attach(u32 mount, struct kernel_object *device);
void adytumfs_detach(u32 mount);
// The directory every path on this volume starts from.
int adytumfs_root_inode(u32 mount, u64 *inode, u64 *generation);
// The on-disk inode behind a number. A number nothing uses, or one the
// volume has since retired, reports used as zero rather than failing, so a
// caller probing a stale handle can tell the two apart.
int adytumfs_inode_get(u32 mount, u64 inode, u32 *used, u32 *type, u32 *size,
                       u32 *mode, u64 *generation);
// One name in a directory, resolved through the item tree by name hash
// rather than by walking the directory's entries.
int adytumfs_dir_find(u32 mount, u64 inode, u64 generation, const char *name,
                      u32 name_len, u64 *entry_inode, u32 *type);
int adytumfs_inode_create(u32 mount, const char *name, u64 parent, u32 type,
                          u32 mode, u64 *inode, u64 *generation);
// Roll back a create that never became reachable: the name and the inode go
// together, since the caller is the only one holding both.
int adytumfs_inode_remove(u32 mount, u64 inode, u64 generation, u64 parent,
                          const char *name);
// Add a directory name for a regular inode. The on-disk link count rises
// before the name lands, so a crash between the two leaves a stale-high
// count rather than a name the count cannot vouch for.
int adytumfs_inode_link(u32 mount, u64 inode, u64 generation, u64 parent,
                        const char *name);
// Remove one directory name and drop the link count with it. A regular
// inode with names left keeps them; the last name reclaims the inode
// unless last_close defers that to the final descriptor close.
int adytumfs_unlink(u32 mount, u64 inode, u64 generation, u64 parent,
                    const char *name, int last_close);
// Move one directory name, and the inode times with it, inside a single
// mount. The caller removes any replaced target first through unlink, so
// both edits land in the one staging window this commits at the end.
int adytumfs_rename(u32 mount, u64 inode, u64 generation, u64 old_parent,
                    const char *name, u64 new_parent,
                    const char *new_name);
// Write a fresh symlink inode's target string into its file body and land
// the whole link under one commit, or read that string back when a node for
// the link is materialised.
int adytumfs_symlink_write(u32 mount, u64 inode, u64 generation,
                           const char *target);
int adytumfs_symlink_target(u32 mount, u64 inode, u64 generation,
                            char *target);
// The deferred reclaim an unlinked inode's final close triggers; a number
// already reclaimed or since reused makes it a no-op.
int adytumfs_inode_release(u32 mount, u64 inode, u64 generation);
// Stamp inode times through the open window. MTIME and CTIME follow data
// writes and metadata edits; ATIME applies the relatime-lite rule and only
// refreshes while atime trails mtime, so a steady-state read stages nothing.
#define ADYTUMFS_TOUCH_ATIME 1u
#define ADYTUMFS_TOUCH_MTIME 2u
#define ADYTUMFS_TOUCH_CTIME 4u
int adytumfs_touch(u32 mount, u64 inode, u64 generation, u32 flags);
// Permission and ownership edits through the same window. The flags name
// the fields to replace, and a call that changes nothing stages no write.
#define ADYTUMFS_SET_MODE 1u
#define ADYTUMFS_SET_UID 2u
#define ADYTUMFS_SET_GID 4u
int adytumfs_inode_update(u32 mount, u64 inode, u64 generation, u32 flags,
                          u32 mode, u32 uid, u32 gid);
// Explicit timestamp edits through the same window. The flags name the
// seconds pair to replace, ctime always moves when anything did, and a call
// that changes nothing stages no write, mirroring inode_update.
#define ADYTUMFS_TIME_SET_ATIME 1u
#define ADYTUMFS_TIME_SET_MTIME 2u
int adytumfs_set_times(u32 mount, u64 inode, u64 generation, u32 flags,
                       u64 atime, u32 atime_nsec, u64 mtime, u32 mtime_nsec);
// The live ownership, link count, and time picture of one inode, read
// through the window staging.
int adytumfs_inode_meta(u32 mount, u64 inode, u64 generation, u16 *links,
                        u32 *uid, u32 *gid, u64 *atime, u64 *mtime,
                        u64 *ctime, u32 *atime_nsec, u32 *mtime_nsec,
                        u32 *ctime_nsec);
// One used on-disk directory entry per call, mirroring vfs_read_dir: the
// cursor is a byte offset in the directory blocks and the returned inode is
// the on-disk number.
int adytumfs_dir_read(u32 mount, u64 inode, u64 generation, u64 *cursor,
                      char *name, u32 *name_len, u64 *entry_inode,
                      u32 *type);
int adytumfs_truncate(u32 mount, u64 inode, u64 generation, u32 size,
                     u32 *new_size);
int adytumfs_pages_attach(u32 mount, u64 inode, u64 generation,
                          struct kernel_object *pages);
int adytumfs_pages_fault(u32 mount, u64 inode, u64 generation, u32 page);
int adytumfs_pages_dirty(u32 mount, u64 inode, u64 generation, u32 page,
                         u32 size);
int adytumfs_pages_sync(u32 mount, u64 inode, u64 generation);
void adytumfs_pages_detach(u32 mount, u64 inode, u64 generation);

#endif
