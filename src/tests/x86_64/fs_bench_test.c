#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs.h"
#include "adytumfs_format.h"
#include "vfs.h"
#include "serial64.h"
#include "apic64.h"

// The device has to hold the throughput file and then the capacity check at
// ADYTUMFS_FILE_SIZE_MAX, so it is sized for the larger of the two.
#define FS_BENCH_SECTORS 4096u
#define FS_BENCH_CHUNK 4096u
#define FS_BENCH_CHUNKS 32u
#define FS_BENCH_NAME "throughput"

static u8 fs_bench_buffer[FS_BENCH_CHUNK];

// Throughput of the write, flush and read paths over one adytumfs file, in
// guest cycles. The window covers the syscalls a caller would actually make:
// the flush is timed on its own because a write that only reached the cache
// and one that reached the block device are different claims, and folding
// them into one number would hide which one moved.
int test_fs_bench(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    u32 devices = block_active_count();
    struct kernel_object *root = vfs_root();
    struct kernel_object *mnt = root ?
        vfs_create(root, "bench", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *dev = block_create(FS_BENCH_SECTORS, 0);
    struct kernel_object *disk = 0;
    struct kernel_object *node = 0;
    struct kernel_object *file = 0;
    u32 transferred = 0;
    int reason = 0;
    if (!root || !mnt || !dev) reason = 1;
    if (!reason && adytumfs_format(dev)) reason = 2;
    if (!reason && vfs_mount_adytumfs(mnt, dev)) reason = 3;
    if (!reason) {
        disk = vfs_lookup(root, "bench");
        if (disk)
            node = vfs_create_mode(disk, FS_BENCH_NAME, VFS_NODE_REGULAR,
                                   0600);
        if (node) file = vfs_open(node);
        if (!disk || !node || !file) reason = 4;
    }
    // Every chunk carries its own pattern, so a read that returned a stale
    // or neighbouring block fails instead of reporting a rate for data that
    // was never stored. The fill and the compare sit outside the windows.
    u64 wrote_at = 0;
    u64 flushed_at = 0;
    u64 read_at = 0;
    for (u32 index = 0; !reason && index < FS_BENCH_CHUNKS; index++) {
        for (u32 byte = 0; byte < FS_BENCH_CHUNK; byte++)
            fs_bench_buffer[byte] = (u8)(index + byte);
        transferred = 0;
        u64 call_at = apic64_tsc_now();
        if (vfs_write(file, index * FS_BENCH_CHUNK, fs_bench_buffer,
                      FS_BENCH_CHUNK, &transferred) ||
            transferred != FS_BENCH_CHUNK)
            reason = 5;
        wrote_at += apic64_tsc_now() - call_at;
    }
    if (!reason) {
        u64 dirty_at = apic64_tsc_now();
        if (vfs_fsync(file)) reason = 6;
        flushed_at = apic64_tsc_now() - dirty_at;
    }
    for (u32 index = 0; !reason && index < FS_BENCH_CHUNKS; index++) {
        transferred = 0;
        u64 call_at = apic64_tsc_now();
        if (vfs_read(file, index * FS_BENCH_CHUNK, fs_bench_buffer,
                     FS_BENCH_CHUNK, &transferred) ||
            transferred != FS_BENCH_CHUNK)
            reason = 7;
        read_at += apic64_tsc_now() - call_at;
        for (u32 byte = 0; !reason && byte < FS_BENCH_CHUNK; byte++)
            if (fs_bench_buffer[byte] != (u8)(index + byte)) reason = 8;
    }
    if (!reason && (!wrote_at || !flushed_at || !read_at)) reason = 9;
    if (!reason) {
        u64 bytes = (u64)FS_BENCH_CHUNKS * FS_BENCH_CHUNK;
        serial64_write("Mich x86_64: fsbench bytes=");
        serial64_dec(bytes);
        serial64_write(" write=0x");
        serial64_hex(wrote_at);
        serial64_write(" flush=0x");
        serial64_hex(flushed_at);
        serial64_write(" read=0x");
        serial64_hex(read_at);
        serial64_write(" cycles-per-4096B w/r=");
        serial64_dec(wrote_at / FS_BENCH_CHUNKS);
        serial64_write("/");
        serial64_dec(read_at / FS_BENCH_CHUNKS);
        serial64_write("\n");
    }
    // Grow to the ceiling and read the size back. Truncating moves no data,
    // so this proves the file can reach the limit without spending the
    // guest budget on a megabyte of copies; the grow and the reclaim both
    // run, because the truncate back down frees what it just took.
    if (!reason) {
        struct vfs_node_info grown;
        if (vfs_truncate(file, ADYTUMFS_FILE_SIZE_MAX)) reason = 12;
        if (!reason && (vfs_stat(file, &grown) ||
                        grown.size != ADYTUMFS_FILE_SIZE_MAX))
            reason = 13;
        if (!reason && vfs_truncate(file, 0)) reason = 14;
        if (!reason && (vfs_stat(file, &grown) || grown.size)) reason = 15;
    }
    if (file) object_release(file);
    if (node) object_release(node);
    if (disk) object_release(disk);
    if (!reason && vfs_unmount(mnt)) reason = 10;
    if (root) vfs_unlink(root, "bench");
    if (mnt) object_release(mnt);
    if (root) object_release(root);
    if (dev) object_release(dev);
    if (!reason && (object_active_count() != objects ||
                    vfs_node_active_count() != nodes ||
                    vfs_file_active_count() != files ||
                    vfs_mount_active_count() != mounts ||
                    block_active_count() != devices))
        reason = 11;
    if (reason) {
        serial64_write("Mich x86_64: fsbench check failed: ");
        serial64_dec((u64)reason);
        serial64_write("\n");
        return -1;
    }
    return 0;
}
