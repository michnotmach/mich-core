#ifndef VNIC_BENCHMARK_H
#define VNIC_BENCHMARK_H

#include "object.h"
#include "net_abi.h"

int vnic_benchmark_run(struct kernel_object *vnic,
                       struct vnic_benchmark_request *request);

enum {
    VNIC_BENCH64_RX = 0,
    VNIC_BENCH64_TX = 1,
    VNIC_BENCH64_ECHO = 2
};

#define VNIC_BENCH64_SAMPLE_COUNT 4096

struct vnic_bench64_result {
    u64 min_cycles;
    u64 avg_cycles;
    u64 p50_cycles;
    u64 p99_cycles;
};

int vnic_bench64_run(struct kernel_object *vnic, u32 direction,
                     u32 frame_size, struct vnic_bench64_result *result);

#define VNIC_BENCH64_FRAME_MAX (NET_PACKET_DATA_MAX - NET_PACKET_HEADROOM)

// One CPU's own stream, timed end to end. The frame is the caller's because
// the percentile path keeps its samples in one shared buffer, and CPUs
// driving streams at the same time must not share the buffer they fill.
int vnic_bench64_batch(struct kernel_object *vnic, u32 direction,
                       u32 frame_size, u32 packets, u8 *frame, u64 *cycles);

#endif
