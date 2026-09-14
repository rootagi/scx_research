#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "scx_guard_lsm.h"

char _license[] SEC("license") = "GPL";

#define EPERM 1

/*
 * Ring buffer map for streaming security telemetry events to userspace
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB ring buffer */
} scx_lsm_events SEC(".maps");

/*
 * Configuration Map:
 * Index 0: enforce_mode (0 = passive audit/telemetry, 1 = active block unknown)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} scx_guard_cfg SEC(".maps");

/*
 * Allowlist hash map: maps scheduler name -> struct scx_allowlist_entry
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SCX_MAX_ALLOWLIST_ENTRIES);
    __type(key, char[SCX_MAP_NAME_LEN]);
    __type(value, struct scx_allowlist_entry);
} scx_allowlist SEC(".maps");

/*
 * Counters for evaluation and metrics
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} scx_guard_stats SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&scx_guard_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/*
 * Primary BPF LSM Detection Hook: bpf_map_create
 * Intercepts BPF map creation, specifically gating on BPF_MAP_TYPE_STRUCT_OPS
 * which is required for loading any sched_ext scheduler.
 */
SEC("lsm/bpf_map_create")
int BPF_PROG(scx_guard_map_create, struct bpf_map *map, union bpf_attr *attr,
             struct bpf_token *token, bool kernel)
{
    enum bpf_map_type map_type = BPF_CORE_READ(map, map_type);

    /* Index 0 = total map creations observed */
    inc_stat(0);

    /* Filter strictly for struct_ops maps (value 26 in enum bpf_map_type) */
    if (map_type != BPF_MAP_TYPE_STRUCT_OPS)
        return 0;

    /* Index 1 = total struct_ops registrations */
    inc_stat(1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)pid_tgid;
    __u32 uid = (__u32)uid_gid;
    __u32 gid = (__u32)(uid_gid >> 32);
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    char map_name[SCX_MAP_NAME_LEN] = {0};
    bpf_probe_read_kernel_str(&map_name, sizeof(map_name), &map->name);

    /* Check allowlist */
    struct scx_allowlist_entry *entry = bpf_map_lookup_elem(&scx_allowlist, &map_name);
    bool is_allowed = (entry != NULL);

    /* Check enforce mode */
    __u32 cfg_key = 0;
    __u32 *enforce_mode = bpf_map_lookup_elem(&scx_guard_cfg, &cfg_key);
    bool should_block = (enforce_mode && *enforce_mode == 1 && !is_allowed);

    /* Allocate ring buffer space */
    struct scx_lsm_event *e = bpf_ringbuf_reserve(&scx_lsm_events, sizeof(*e), 0);
    if (e) {
        e->timestamp_ns = bpf_ktime_get_ns();
        e->event_type = SCX_EVENT_STRUCT_OPS_REG;
        e->severity = is_allowed ? SCX_SEV_INFO : (should_block ? SCX_SEV_BLOCK : SCX_SEV_ALERT);
        e->pid = pid;
        e->tgid = tgid;
        e->uid = uid;
        e->gid = gid;
        e->cgroup_id = cgroup_id;
        e->map_type = map_type;
        e->map_id = BPF_CORE_READ(map, id);
        e->btf_vmlinux_value_type_id = BPF_CORE_READ(map, btf_vmlinux_value_type_id);
        e->is_allowed = is_allowed ? 1 : 0;
        e->blocked = should_block ? 1 : 0;

        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(&e->map_name, &map_name, sizeof(e->map_name));

        bpf_ringbuf_submit(e, 0);
    }

    if (is_allowed) {
        inc_stat(2); /* allowed */
    } else {
        inc_stat(3); /* unauthorized / anomalous */
    }

    if (should_block) {
        inc_stat(4); /* blocked */
        bpf_printk("scx_guard_lsm: BLOCKED unauthorized struct_ops '%s' from PID %d (UID %d)\n",
                   map_name, pid, uid);
        return -EPERM;
    }

    bpf_printk("scx_guard_lsm: Detected struct_ops '%s' from PID %d (UID %d, allowed=%d)\n",
               map_name, pid, uid, is_allowed ? 1 : 0);

    return 0;
}
