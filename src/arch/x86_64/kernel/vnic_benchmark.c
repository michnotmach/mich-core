#include "types.h"
#include "vnic_benchmark.h"
#include "vnic.h"
#include "net_buffer.h"
#include "ring.h"

static u64 benchmark_cycles(void) {
    u32 low;
    u32 high;
    __asm__ volatile("lfence; rdtsc" : "=a"(low), "=d"(high) :: "memory");
    return ((u64)high << 32) | low;
}

int vnic_benchmark_run(struct kernel_object *vnic,
                            struct vnic_benchmark_request *request) {
    if (!vnic || !request || !request->packets || request->packets > 1000000 ||
        !request->batch_size || request->batch_size > RING_CAPACITY_MAX ||
        !request->payload_size || request->payload_size > 512)
        return -1;
    struct kernel_object *pool = vnic_pool(vnic);
    struct ring_resource *rx = ring_resource_get(vnic_rx_ring(vnic));
    if (!pool || !rx || request->batch_size > rx->capacity ||
        request->batch_size > packet_pool_free_count(pool))
        return -1;
    u8 frame[512];
    for (u32 index = 0; index < request->payload_size; index++)
        frame[index] = (u8)index;
    request->completed = 0;
    u64 start = benchmark_cycles();
    while (request->completed < request->packets) {
        u32 remaining = request->packets - request->completed;
        u32 batch = remaining < request->batch_size
            ? remaining : request->batch_size;
        for (u32 index = 0; index < batch; index++)
            if (vnic_inject(vnic, frame, request->payload_size)) return -1;
        for (u32 index = 0; index < batch; index++) {
            struct net_packet_descriptor descriptor;
            if (vnic_receive(vnic, &descriptor) ||
                vnic_release_rx(vnic, descriptor.buffer_id))
                return -1;
            request->completed++;
        }
    }
    request->cycles = benchmark_cycles() - start;
    return request->cycles ? 0 : -1;
}

#define VNIC_BENCH64_WARMUP 512
static u8 bench_frame[VNIC_BENCH64_FRAME_MAX];
static u64 bench_samples[VNIC_BENCH64_SAMPLE_COUNT];

static void bench_sort_range(u64 *a, u32 lo, u32 hi) {
    while (hi - lo > 16) {
        u64 pivot = a[(lo + hi) / 2];
        u32 i = lo;
        u32 j = hi;
        while (i <= j) {
            while (a[i] < pivot) i++;
            while (a[j] > pivot) j--;
            if (i <= j) {
                u64 t = a[i];
                a[i] = a[j];
                a[j] = t;
                i++;
                j--;
            }
        }
        if (j - lo < hi - i) {
            if (i < hi) bench_sort_range(a, i, hi);
            hi = j;
        } else {
            if (lo < j) bench_sort_range(a, lo, j);
            lo = i;
        }
    }
    for (u32 i = lo + 1; i <= hi; i++) {
        u64 t = a[i];
        u32 j = i;
        while (j > lo && a[j - 1] > t) {
            a[j] = a[j - 1];
            j--;
        }
        a[j] = t;
    }
}

static int bench_one(struct kernel_object *vnic, const u8 *frame,
                     u32 direction, u32 frame_size, u64 *cycles) {
    struct net_packet_descriptor descriptor;
    u64 rx_id = 0;
    u64 start = benchmark_cycles();
    if (direction == VNIC_BENCH64_RX || direction == VNIC_BENCH64_ECHO) {
        if (vnic_inject(vnic, frame, frame_size)) return -1;
        if (vnic_receive(vnic, &descriptor)) return -1;
        rx_id = descriptor.buffer_id;
    }
    if (direction != VNIC_BENCH64_RX) {
        u64 id = vnic_acquire_tx(vnic);
        u8 *data = id ? (u8 *)packet_pool_data(
            vnic_pool(vnic), id, NET_BUFFER_TX) : 0;
        if (!data) return -1;
        for (u32 index = 0; index < frame_size; index++)
            data[NET_PACKET_HEADROOM + index] = frame[index];
        if (vnic_submit_tx(vnic, id, NET_PACKET_HEADROOM, frame_size, 0) ||
            vnic_drain_tx(vnic, &descriptor))
            return -1;
    }
    if (direction == VNIC_BENCH64_RX || direction == VNIC_BENCH64_ECHO)
        if (vnic_release_rx(vnic, rx_id)) return -1;
    u64 elapsed = benchmark_cycles() - start;
    if (cycles) *cycles = elapsed;
    return elapsed ? 0 : -1;
}

int vnic_bench64_run(struct kernel_object *vnic, u32 direction,
                     u32 frame_size, struct vnic_bench64_result *result) {
    if (!vnic || !result || direction > VNIC_BENCH64_ECHO ||
        !frame_size || frame_size > VNIC_BENCH64_FRAME_MAX)
        return -1;
    for (u32 index = 0; index < frame_size; index++)
        bench_frame[index] = (u8)index;
    for (u32 index = 0; index < VNIC_BENCH64_WARMUP; index++)
        if (bench_one(vnic, bench_frame, direction, frame_size, 0))
            return -1;
    u64 total = 0;
    for (u32 index = 0; index < VNIC_BENCH64_SAMPLE_COUNT; index++) {
        u64 elapsed;
        if (bench_one(vnic, bench_frame, direction, frame_size, &elapsed))
            return -1;
        bench_samples[index] = elapsed;
        total += elapsed;
    }
    bench_sort_range(bench_samples, 0, VNIC_BENCH64_SAMPLE_COUNT - 1);
    result->min_cycles = bench_samples[0];
    result->avg_cycles = total / VNIC_BENCH64_SAMPLE_COUNT;
    result->p50_cycles = bench_samples[VNIC_BENCH64_SAMPLE_COUNT / 2];
    result->p99_cycles = bench_samples[(VNIC_BENCH64_SAMPLE_COUNT * 99 + 99) / 100 - 1];
    return result->min_cycles ? 0 : -1;
}

int vnic_bench64_batch(struct kernel_object *vnic, u32 direction,
                       u32 frame_size, u32 packets, u8 *frame, u64 *cycles) {
    if (!vnic || !frame || !cycles || !packets ||
        direction > VNIC_BENCH64_ECHO || !frame_size ||
        frame_size > VNIC_BENCH64_FRAME_MAX)
        return -1;
    for (u32 index = 0; index < frame_size; index++)
        frame[index] = (u8)index;
    u64 start = benchmark_cycles();
    for (u32 index = 0; index < packets; index++)
        if (bench_one(vnic, frame, direction, frame_size, 0)) return -1;
    *cycles = benchmark_cycles() - start;
    return *cycles ? 0 : -1;
}
