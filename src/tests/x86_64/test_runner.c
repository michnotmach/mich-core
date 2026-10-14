#include "tests64.h"
#include "bootinfo.h"
#include "test_report.h"
#include "serial64.h"

int tests64_run(const struct test64_env *env) {
    if (!env || !env->owner || !env->target || !env->target_result)
        return -1;
    if (test_report_record(TEST_ID_OBJECT, test_object64(env->owner, env->target))) return -1;
    serial64_write("Mich test64: kernel object layer pass\n");
    serial64_write("Mich test64: 24-bit handle generation stress pass\n");
    if (test_report_record(TEST_ID_VFS, test_vfs64())) return -1;
    serial64_write("Mich test64: VFS vnode and mount objects pass\n");
    serial64_write("Mich test64: VFS ramfs backend pass\n");
    serial64_write("Mich test64: VFS immutable bootfs pass\n");
    serial64_write("Mich test64: VFS mount traversal pass\n");
    serial64_write("Mich test64: firmware lookup service pass\n");
    serial64_write("Mich test64: VFS file lifetime pass\n");
    serial64_write("Mich test64: VFS unlink-open semantics pass\n");
    serial64_write("Mich test64: VFS append transaction pass\n");
    serial64_write("Mich test64: VFS absolute and relative paths pass\n");
    serial64_write("Mich test64: VFS root escape protection pass\n");
    serial64_write("Mich test64: VFS path component bounds pass\n");
    serial64_write("Mich test64: VFS path mutation stress pass\n");
    if (test_report_record(TEST_ID_VFS_PAGES, test_vfs_pages64()))
        return -1;
    serial64_write("Mich test64: VFS page-backed files pass\n");
    if (test_report_record(TEST_ID_POSIX_FD,
                           test_posix_fd64(env->owner, env->target)))
        return -1;
    serial64_write("Mich test64: POSIX FD/OFD substrate pass\n");
    serial64_write("Mich test64: POSIX FD lifecycle cleanup pass\n");
    // test_posix_profile64 asserts that the init module was already admitted
    // to the POSIX profile at boot, which only holds when it was spawned with
    // BD_MODULE_POSIX_PROFILE. The hardware and panic profiles start init
    // without it, so running the test there fails on a condition that is not
    // a defect.
    if (env->module_flags & BD_MODULE_POSIX_PROFILE) {
        if (test_report_record(TEST_ID_POSIX_PROFILE,
                               test_posix_profile64(env->owner, env->target)))
            return -1;
        serial64_write("Mich test64: POSIX profile cwd and authority pass\n");
    }
    if (test_report_record(TEST_ID_POSIX_VFS,
                           test_posix_vfs64(env->owner, env->target)))
        return -1;
    serial64_write("Mich test64: POSIX VFS authority and mode pass\n");
    if (test_report_record(TEST_ID_POSIX_PROCESS, test_posix_process64()))
        return -1;
    serial64_write("Mich test64: POSIX process stack layout pass\n");
    if (test_report_record(TEST_ID_POSIX_TIME, test_posix_time64()))
        return -1;
    serial64_write("Mich test64: POSIX clocks and sleep pass\n");
    if (test_report_record(TEST_ID_POSIX_SIGNAL, test_posix_signal64()))
        return -1;
    serial64_write("Mich test64: POSIX signal delivery pass\n");
    if (test_report_record(TEST_ID_POSIX_PLEDGE, test_posix_pledge64()))
        return -1;
    serial64_write("Mich test64: POSIX pledge and unveil pass\n");
    if (test_report_record(TEST_ID_POSIX_PIPE, test_posix_pipe64()))
        return -1;
    serial64_write("Mich test64: POSIX pipe pool and gate pass\n");
    if (test_report_record(TEST_ID_POSIX_SOCKET, test_posix_socket64(env)))
        return -1;
    serial64_write("Mich test64: POSIX socket substrate pass\n");
    if (test_report_record(TEST_ID_POSIX_POLL, test_posix_poll64(env->owner)))
        return -1;
    serial64_write("Mich test64: POSIX poll readiness pass\n");
    if (test_report_record(TEST_ID_POSIX_TTY, test_posix_tty64(env->owner))) return -1;
    serial64_write("Mich test64: POSIX tty line discipline pass\n");
    if (test_report_record(TEST_ID_POSIX_JOB, test_posix_job64(env->owner)))
        return -1;
    serial64_write("Mich test64: POSIX job control pass\n");
    if (test_report_record(TEST_ID_BLOCK, test_block64())) return -1;
    serial64_write("Mich test64: block device objects pass\n");
    serial64_write("Mich test64: ramdisk read and write pass\n");
    serial64_write("Mich test64: block request generation pass\n");
    serial64_write("Mich test64: block bounds and revoke pass\n");
    serial64_write("Mich test64: deferred block service pass\n");
    if (test_report_record(TEST_ID_CACHE, test_cache64())) return -1;
    serial64_write("Mich test64: block page cache pass\n");
    if (test_report_record(TEST_ID_ENTROPY, test_entropy64())) return -1;
    serial64_write("Mich test64: ChaCha20 DRBG pass\n");
    if (test_report_record(TEST_ID_RTC, test_rtc64())) return -1;
    serial64_write("Mich test64: RTC civil date conversion pass\n");
    if (test_report_record(TEST_ID_SIPHASH, test_siphash64())) return -1;
    serial64_write("Mich test64: SipHash-2-4 pass\n");
    if (test_report_record(TEST_ID_CRC32C, test_crc32c64())) return -1;
    serial64_write("Mich test64: crc32c and little-endian helpers pass\n");
    if (test_report_record(TEST_ID_BLAKE2B, test_blake2b64())) return -1;
    serial64_write("Mich test64: BLAKE2b pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_SUPER, test_adytumfs_super64()))
        return -1;
    serial64_write("Mich test64: adytumfs superblock pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_VOLUME, test_adytumfs_volume64()))
        return -1;
    serial64_write("Mich test64: adytumfs format pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_ALLOC, test_adytumfs_alloc64()))
        return -1;
    serial64_write("Mich test64: adytumfs block allocator pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_CAS, test_adytumfs_cas64()))
        return -1;
    serial64_write("Mich test64: adytumfs content addressed blocks pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_TREE, test_adytumfs_tree64()))
        return -1;
    serial64_write("Mich test64: adytumfs tree nodes pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_TREE_WALK,
                           test_adytumfs_tree_traverse64()))
        return -1;
    serial64_write("Mich test64: adytumfs tree walk pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_TREE_GC,
                           test_adytumfs_tree_gc64()))
        return -1;
    serial64_write("Mich test64: adytumfs tree gc pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_INDEX, test_adytumfs_index64()))
        return -1;
    serial64_write("Mich test64: adytumfs disk index pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_VERIFY, test_adytumfs_verify64()))
        return -1;
    serial64_write("Mich test64: adytumfs mount audit pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_INODE, test_adytumfs_inode64()))
        return -1;
    serial64_write("Mich test64: adytumfs inode table pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_EXTENT, test_adytumfs_extent64()))
        return -1;
    serial64_write("Mich test64: adytumfs extents pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_DIR, test_adytumfs_dir64()))
        return -1;
    serial64_write("Mich test64: adytumfs directories pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_DIRITER, test_adytumfs_diriter64()))
        return -1;
    serial64_write("Mich test64: adytumfs directory iteration pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_FILE, test_adytumfs_file64()))
        return -1;
    serial64_write("Mich test64: adytumfs file read write pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_OPS, test_adytumfs_ops64()))
        return -1;
    serial64_write("Mich test64: adytumfs path operations pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS, test_adytumfs64())) return -1;
    if (test_report_record(TEST_ID_FS_BENCH, test_fs_bench())) return -1;
    if (test_report_record(TEST_ID_TIME64, test_time64())) return -1;
    serial64_write("Mich test64: calibrated time base pass\n");
    if (test_report_record(TEST_ID_TASK_RUNTIME, test_task_runtime()))
        return -1;
    serial64_write("Mich test64: task runtime accounting pass\n");
    if (test_report_record(TEST_ID_EEVDF, test_eevdf())) return -1;
    serial64_write("Mich test64: eevdf policy pass\n");
    serial64_write("Mich test64: adytumfs format and mount pass\n");
    serial64_write("Mich test64: adytumfs file io pass\n");
    serial64_write("Mich test64: adytumfs busy unmount lifetime pass\n");
    serial64_write("Mich test64: adytumfs stale vnode generation pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_PAGES, test_adytumfs_pages64()))
        return -1;
    serial64_write("Mich test64: adytumfs page-backed write-back pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_POLICY, test_adytumfs_policy64()))
        return -1;
    serial64_write("Mich test64: adytumfs mount policies pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_REUSE, test_adytumfs_reuse64()))
        return -1;
    serial64_write("Mich test64: adytumfs slot reuse pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_INTEGRITY,
                           test_adytumfs_integrity64()))
        return -1;
    serial64_write("Mich test64: adytumfs mount integrity pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_CHECKSUM,
                           test_adytumfs_checksum64()))
        return -1;
    serial64_write("Mich test64: adytumfs data checksum pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_COW, test_adytumfs_cow64()))
        return -1;
    serial64_write("Mich test64: adytumfs copy-on-write pass\n");
    if (test_report_record(TEST_ID_ADYTUMFS_CRASH, test_adytumfs_crash64()))
        return -1;
    serial64_write("Mich test64: adytumfs crash windows pass\n");
    if (test_report_record(TEST_ID_RESOURCE, test_resource64())) return -1;
    serial64_write("Mich test64: resource object layer pass\n");
    if (test_report_record(TEST_ID_PAGE, test_page64(env))) return -1;
    serial64_write("Mich test64: page and shared memory objects pass\n");
    if (test_report_record(TEST_ID_PAGE_GROW, test_page_grow64()))
        return -1;
    serial64_write("Mich test64: page grow and trim pass\n");
    if (test_report_record(TEST_ID_SG, test_sg64())) return -1;
    serial64_write("Mich test64: scatter-gather objects pass\n");
    serial64_write("Mich test64: scatter-gather rollback pass\n");
    if (test_report_record(TEST_ID_RING, test_ring64(env))) return -1;
    serial64_write("Mich test64: shared zero-copy rings pass\n");
    serial64_write("Mich test64: ring index validation pass\n");
    serial64_write("Mich test64: ring generation revoke pass\n");
    if (test_report_record(TEST_ID_ASYNC, test_async64(env))) return -1;
    serial64_write("Mich test64: completion objects pass\n");
    serial64_write("Mich test64: completion cancel and timeout pass\n");
    serial64_write("Mich test64: timer objects pass\n");
    serial64_write("Mich test64: wait-many pass\n");
    if (test_report_record(TEST_ID_FPU, test_fpu64())) return -1;
    serial64_write("Mich test64: FPU save/load cost measured\n");
    return 0;
}
