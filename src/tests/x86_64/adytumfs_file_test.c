#include "types.h"
#include "object.h"
#include "block.h"
#include "adytumfs_format.h"
#include "adytumfs_cas.h"

int test_adytumfs_file64(void) {
    u32 objects = object_active_count();
    u32 devices = block_active_count();
    struct kernel_object *dev = block_create(512, 0);   // 64 filesystem blocks

    // A 4 KiB block is too big for a modest stack, and the test is single
    // threaded, so the scratch blocks are static.
    static u8 block[ADYTUMFS_BLOCK_SIZE];
    struct adytumfs_superblock super;
    // The content store every extent tree resolves through. A test that
    // touches a file's blocks needs one, exactly as a mount does.
    static struct adytumfs_cas store;
    int valid = dev && adytumfs_make(dev) == 0 &&
        adytumfs_block_read(dev, 0, block) == 0 &&
        adytumfs_super_unpack(&super, block) == 0;
    adytumfs_cas_open(&store, super.index_start, super.index_blocks);

    u64 num = 0;
    valid = valid &&
        adytumfs_inode_alloc(dev, &super, ADYTUMFS_MODE_REG | 0644u, &num) == 0;

    // Write a 70000-byte file, past the old 64 KiB cap, in 512-byte chunks so no
    // huge buffer is needed. The byte at file position p is deterministic.
    static u8 chunk[512];
    const u64 total = 70000;
    for (u64 offset = 0; offset < total && valid; offset += sizeof(chunk)) {
        u64 span = total - offset < sizeof(chunk) ? total - offset : sizeof(chunk);
        for (u64 index = 0; index < span; index++)
            chunk[index] = (u8)((offset + index) * 131u + 7u);
        u64 written = 0;
        valid = valid &&
            adytumfs_file_write(dev, &super, &store, num, offset, chunk, span,
                                &written) == 0 && written == span;
    }

    struct adytumfs_inode inode;
    valid = valid && adytumfs_inode_read(dev, &super, num, &inode) == 0 &&
        inode.size == total && inode.blocks >= 18;

    // Read it back in chunks and verify the pattern survived the extents.
    for (u64 offset = 0; offset < total && valid; offset += sizeof(chunk)) {
        u64 span = total - offset < sizeof(chunk) ? total - offset : sizeof(chunk);
        u64 got = 0;
        valid = valid &&
            adytumfs_file_read(dev, &super, &store, num, offset, chunk, span, &got) == 0 &&
            got == span;
        for (u64 index = 0; index < span && valid; index++)
            if (chunk[index] != (u8)((offset + index) * 131u + 7u)) valid = 0;
    }

    // A partial overwrite touches only the three targeted bytes.
    static const u8 patch[3] = { 'X', 'Y', 'Z' };
    u64 transferred = 0;
    u8 window[5];
    valid = valid &&
        adytumfs_file_write(dev, &super, &store, num, 100, patch, 3, &transferred) == 0 &&
        transferred == 3 &&
        adytumfs_file_read(dev, &super, &store, num, 99, window, 5, &transferred) == 0 &&
        transferred == 5 &&
        window[0] == (u8)(99u * 131u + 7u) && window[1] == 'X' &&
        window[2] == 'Y' && window[3] == 'Z' &&
        window[4] == (u8)(103u * 131u + 7u);

    // Reading at end of file returns nothing.
    valid = valid &&
        adytumfs_file_read(dev, &super, &store, num, total, window, 5, &transferred) == 0 &&
        transferred == 0;

    adytumfs_window_discard(dev);
    if (dev) object_release(dev);
    valid = valid && object_active_count() == objects &&
        block_active_count() == devices;
    return valid ? 0 : -1;
}
