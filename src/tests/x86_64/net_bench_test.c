#include "net_test.h"
#include "serial64.h"
#include "kernel64_internal.h"

int test_net_bench(void) {
    u32 free_pages = pmm_free_pages();
    u32 objects = object_active_count();
    u32 pools = packet_pool_active_count();
    u32 vnics = vnic_active_count();
    u32 rings = ring_active_count();
    struct kernel_object *vnic = vnic_create(64, 32);
    struct vnic_bench64_result result;
    if (!vnic) return -1;
    int valid = 1;
    u64 sw0 = scheduler64_switch_count();
    const char *names[3] = {"rx", "tx", "echo"};
    u32 sizes[3] = {64, 512, 1500};
    for (u32 direction = 0; direction < 3 && valid; direction++)
        for (u32 index = 0; index < 3; index++) {
            if (vnic_bench64_run(vnic, direction, sizes[index], &result) ||
                !result.min_cycles ||
                result.p50_cycles < result.min_cycles ||
                result.p99_cycles < result.p50_cycles ||
                result.avg_cycles < result.min_cycles) {
                valid = 0;
                break;
            }
            serial64_write("Mich x86_64: netbench ");
            serial64_write(names[direction]);
            serial64_write(" size=");
            serial64_dec(sizes[index]);
            serial64_write("B min=");
            serial64_hex(result.min_cycles);
            serial64_write(" avg=");
            serial64_hex(result.avg_cycles);
            serial64_write(" p50=");
            serial64_hex(result.p50_cycles);
            serial64_write(" p99=");
            serial64_hex(result.p99_cycles);
            serial64_write(" cycles/packet\n");
        }
    // netbench is a single-threaded VNIC benchmark: report how many real
    // context switches it caused (0 => it does not exercise the per-switch
    // FPU save/restore, so that cost lives in multi-threaded workloads).
    serial64_write("Mich x86_64: netbench context-switches=0x");
    serial64_hex(scheduler64_switch_count() - sw0);
    serial64_write("\n");
    object_release(vnic);
    valid = valid && pmm_free_pages() == free_pages &&
        object_active_count() == objects &&
        packet_pool_active_count() == pools &&
        vnic_active_count() == vnics && ring_active_count() == rings;
    return valid ? 0 : -1;
}
