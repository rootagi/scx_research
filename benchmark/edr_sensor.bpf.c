#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "edr_sensor.h"

char _license[] SEC("license") = "GPL";

/* Ring buffer for event telemetry delivery */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024); /* 64 KB capacity */
} events_rb SEC(".maps");

/* Counters: [0] = total generated events, [1] = ringbuffer drops */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters_map SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key_total = 0, key_drop = 1;
    __u64 *cnt = bpf_map_lookup_elem(&counters_map, &key_total);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    struct edr_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        __u64 *drop_cnt = bpf_map_lookup_elem(&counters_map, &key_drop);
        if (drop_cnt)
            __sync_fetch_and_add(drop_cnt, 1);
        return 0;
    }

    e->ktime_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->event_type = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename_ptr = (const char *)ctx->args[1];
    if (filename_ptr)
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key_total = 0, key_drop = 1;
    __u64 *cnt = bpf_map_lookup_elem(&counters_map, &key_total);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    struct edr_event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
    if (!e) {
        __u64 *drop_cnt = bpf_map_lookup_elem(&counters_map, &key_drop);
        if (drop_cnt)
            __sync_fetch_and_add(drop_cnt, 1);
        return 0;
    }

    e->ktime_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->event_type = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename_ptr = (const char *)ctx->args[0];
    if (filename_ptr)
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}
