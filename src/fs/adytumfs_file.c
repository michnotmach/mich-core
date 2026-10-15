#include "adytumfs_format.h"
#include "adytumfs_tree.h"
#include "rtc64.h"

// One staging block for partial-block read-modify-write; single-CPU filesystem.
static u8 adytumfs_file_scratch[ADYTUMFS_BLOCK_SIZE];

int adytumfs_file_read(struct kernel_object *device,
                       struct adytumfs_superblock *super,
                       struct adytumfs_cas *store, u64 inode_num,
                       u64 offset, void *buffer, u64 length, u64 *out_read) {
    if (!out_read) return -1;
    struct adytumfs_inode inode;
    if (adytumfs_inode_read(device, super, inode_num, &inode)) return -1;
    if ((inode.mode & ADYTUMFS_MODE_REG) == 0) return -1;
    if (offset >= inode.size) {
        *out_read = 0;
        return 0;
    }
    u64 available = inode.size - offset;
    u64 want = length < available ? length : available;
    u8 *out = (u8 *)buffer;
    u64 done = 0;
    while (done < want) {
        u64 position = offset + done;
        u64 logical = position / ADYTUMFS_BLOCK_SIZE;
        u32 within = (u32)(position % ADYTUMFS_BLOCK_SIZE);
        u32 chunk = ADYTUMFS_BLOCK_SIZE - within;
        if (chunk > want - done) chunk = (u32)(want - done);
        u64 physical;
        if (adytumfs_inode_map(device, super, store, &inode, logical, &physical)) return -1;
        if (adytumfs_data_read(device, super, physical, adytumfs_file_scratch))
            return -1;
        for (u32 index = 0; index < chunk; index++)
            out[done + index] = adytumfs_file_scratch[within + index];
        done += chunk;
    }
    *out_read = done;
    return 0;
}

int adytumfs_file_write(struct kernel_object *device,
                        struct adytumfs_superblock *super,
                        struct adytumfs_cas *store, u64 inode_num,
                        u64 offset, const void *buffer, u64 length,
                        u64 *out_written) {
    if (!out_written) return -1;
    struct adytumfs_inode inode;
    if (adytumfs_inode_read(device, super, inode_num, &inode)) return -1;
    if ((inode.mode & ADYTUMFS_MODE_REG) == 0) return -1;
    if (length == 0) {
        *out_written = 0;
        return 0;
    }
    u64 end = offset + length;
    if (end < offset) return -1;
    u64 need = (end + ADYTUMFS_BLOCK_SIZE - 1) / ADYTUMFS_BLOCK_SIZE;
    if (need > inode.blocks &&
        adytumfs_inode_grow(device, super, store, &inode, inode_num, need))
        return -1;

    const u8 *in = (const u8 *)buffer;
    u64 done = 0;
    while (done < length) {
        u64 position = offset + done;
        u64 logical = position / ADYTUMFS_BLOCK_SIZE;
        u32 within = (u32)(position % ADYTUMFS_BLOCK_SIZE);
        u32 chunk = ADYTUMFS_BLOCK_SIZE - within;
        if (chunk > length - done) chunk = (u32)(length - done);
        u64 physical;
        if (adytumfs_inode_map(device, super, store, &inode, logical, &physical)) return -1;
        // A partial block keeps its surrounding bytes; a full-block overwrite
        // does not need the prior contents.
        if ((within != 0 || chunk != ADYTUMFS_BLOCK_SIZE) &&
            adytumfs_data_read(device, super, physical, adytumfs_file_scratch))
            return -1;
        for (u32 index = 0; index < chunk; index++)
            adytumfs_file_scratch[within + index] = in[done + index];
        // Every block goes through a remap, grown ones included. A hole is
        // not a block this file owns: every hole on the volume resolves to
        // one shared image of zeroes, so writing through the mapping would
        // rewrite that image for everyone. The remap lands the bytes in a
        // block of the file's own and repoints only this entry.
        if (adytumfs_inode_remap(device, super, store, &inode, inode_num,
                                 logical, adytumfs_file_scratch))
            return -1;
        done += chunk;
    }
    if (end > inode.size) inode.size = end;
    // The inode is persisted at the end of this write anyway, so the time
    // stamp for the data change rides along. The read path makes no inode
    // write and deliberately stamps nothing; atime policy lives in the VFS.
    u64 now = rtc64_wall_clock();
    inode.mtime = now;
    inode.ctime = now;
    if (adytumfs_inode_write(device, super, inode_num, &inode)) return -1;
    *out_written = done;
    return 0;
}
