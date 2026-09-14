#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

/* Hash map to track wakeup timestamp per PID */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   /* PID */
    __type(value, __u64); /* Wakeup timestamp (ns) */
} t_wakeup SEC(".maps");

/* Latency histogram: log2 index -> count */
#define MAX_SLOTS 32
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} telemetry_latency_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} normal_latency_hist SEC(".maps");

/* Target PID to isolate (0 = all) */
const volatile __u32 target_telemetry_pid = 0;

static __always_inline void update_hist(void *map, __u64 lat_us)
{
    __u32 slot = 0;
    __u64 val = lat_us;

    /* Simple log2 slot calculation */
    while (val > 0 && slot < MAX_SLOTS - 1) {
        slot++;
        val >>= 1;
    }

    __u64 *cnt = bpf_map_lookup_elem(map, &slot);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&t_wakeup, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    __u32 next_pid = BPF_CORE_READ(next, pid);
    __u64 *ts_ptr = bpf_map_lookup_elem(&t_wakeup, &next_pid);
    if (!ts_ptr)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 delta_ns = now - *ts_ptr;
    __u64 delta_us = delta_ns / 1000;

    bpf_map_delete_elem(&t_wakeup, &next_pid);

    if (target_telemetry_pid != 0 && next_pid == target_telemetry_pid) {
        update_hist(&telemetry_latency_hist, delta_us);
    } else {
        update_hist(&normal_latency_hist, delta_us);
    }

    return 0;
}
