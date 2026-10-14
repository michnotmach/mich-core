#ifndef TESTS64_H
#define TESTS64_H

#include "types.h"
#include "task.h"
#include "driver_supervisor.h"

struct test64_env {
    struct task *owner;
    struct task *target;
    // Capability flags the init module was spawned with. Tests that assert on
    // boot-time state have to know which subsystems the profile actually
    // started; see BD_MODULE_* in bootinfo.h.
    u32 module_flags;
    u32 owner_space;
    u32 target_space;
    u32 owner_slot;
    u32 target_slot;
    u64 *target_result;
    struct kernel_object *platform_mmio;
    driver_resource_provider_fn resource_provider;
    driver_domain_spawn_fn spawn;
    driver_domain_quiesce_fn quiesce;
    driver_domain_reset_fn reset;
    driver_domain_revoke_fn revoke;
    driver_domain_terminate_fn terminate;
};

int test_vfs64(void);
int test_vfs_pages64(void);
int test_posix_fd64(struct task *owner, struct task *child);
int test_posix_profile64(struct task *owner, struct task *child);
int test_posix_vfs64(struct task *owner, struct task *child);
int test_posix_process64(void);
int test_posix_time64(void);
int test_posix_signal64(void);
int test_posix_pledge64(void);
int test_posix_pipe64(void);
int test_posix_socket64(const struct test64_env *env);
int test_posix_poll64(struct task *owner);
int test_posix_tty64(struct task *owner);
int test_posix_job64(struct task *owner);
int test_block64(void);
int test_cache64(void);
int test_entropy64(void);
int test_rtc64(void);
int test_siphash64(void);
int test_crc32c64(void);
int test_blake2b64(void);
int test_adytumfs_super64(void);
int test_adytumfs_volume64(void);
int test_adytumfs_alloc64(void);
int test_adytumfs_cas64(void);
int test_adytumfs_tree64(void);
int test_adytumfs_tree_traverse64(void);
int test_adytumfs_tree_gc64(void);
int test_adytumfs_index64(void);
int test_adytumfs_verify64(void);
int test_adytumfs_inode64(void);
int test_adytumfs_extent64(void);
int test_adytumfs_dir64(void);
int test_adytumfs_diriter64(void);
int test_adytumfs_file64(void);
int test_adytumfs_ops64(void);
int test_adytumfs64(void);
int test_fs_bench(void);
int test_time64(void);
int test_task_runtime(void);
int test_eevdf(void);
int test_adytumfs_pages64(void);
int test_adytumfs_policy64(void);
int test_adytumfs_reuse64(void);
int test_adytumfs_integrity64(void);
int test_adytumfs_checksum64(void);
int test_adytumfs_cow64(void);
int test_adytumfs_crash64(void);
int tests64_run_crash(void);
int test_nvme64(const struct test64_env *env);
int test_object64(struct task *owner, struct task *target);
int test_resource64(void);
int test_page64(const struct test64_env *env);
int test_page_grow64(void);
int test_sg64(void);
int test_ring64(const struct test64_env *env);
int test_async64(const struct test64_env *env);
int test_fpu64(void);
int test_net_foundation(void);
int test_ethernet(void);
int test_arp(void);
int test_ipv4(void);
int test_ipv6(void);
int test_icmpv6(void);
int test_udpv6(void);
int test_tcp(void);
int test_tcp_pages64(void);
int test_icmp(void);
int test_loopback(void);
int test_udp(void);
int test_dns_message(void);
int test_route_socket(const struct test64_env *env);
int test_stream_route(const struct test64_env *env);
int test_network_revoke(const struct test64_env *env);
int test_net_interface(const struct test64_env *env);
int test_socket_send_file(const struct test64_env *env);
int test_socket_send_disk_file(const struct test64_env *env);
int test_socket_receive_file(const struct test64_env *env);
int test_network_fuzz(void);
int test_net_bench(void);
int tests64_run(const struct test64_env *env);
int tests64_run_network(const struct test64_env *env);
int tests64_run_driver(const struct test64_env *env);
int test_vtd64_tables(struct kernel_object *pci);
int test_iommu64_forbidden_dma(void);
int test_vtd64_interrupt_remapping(void);
int tests64_run_hardware(const struct test64_env *env,
                         int destructive, int *msi, int *msix);
int tests64_run_irq(const struct test64_env *env,
                    int msi, int msix);
int tests64_run_smp(void);
int tests64_run_nvme(const struct test64_env *env);

#endif
