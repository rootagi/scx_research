#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "scx_telemetry.h"

char _license[] SEC("license") = "GPL";

/*
 * Map: Target PIDs for dynamic telemetry routing
 * Key: PID (or TGID)
 * Value: struct task_config
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TARGET_PIDS);
    __type(key, __u32);
    __type(value, struct task_config);
} target_pids SEC(".maps");

/*
 * Map: Per-CPU statistics map for lockless high-throughput telemetry
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sched_telemetry_stats);
} stats_map SEC(".maps");

/* Helper to access per-cpu statistics */
static __always_inline struct sched_telemetry_stats *get_stats(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&stats_map, &zero);
}

/*
 * .select_cpu callback
 * Called when a task wakes up. Delegates to default idle CPU selection.
 */
SEC("struct_ops/telemetry_select_cpu")
s32 BPF_PROG(telemetry_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

/*
 * .enqueue callback
 * Routes tasks to either the high-priority telemetry DSQ or the standard DSQ.
 */
SEC("struct_ops/telemetry_enqueue")
void BPF_PROG(telemetry_enqueue, struct task_struct *p, u64 enq_flags)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u32 tgid = BPF_CORE_READ(p, tgid);
    struct task_config *cfg = NULL;
    struct sched_telemetry_stats *stats = get_stats();

    /* Check PID first (thread-level), then TGID (process-level) */
    cfg = bpf_map_lookup_elem(&target_pids, &pid);
    if (!cfg)
        cfg = bpf_map_lookup_elem(&target_pids, &tgid);

    if (cfg && cfg->priority > 0) {
        __u64 slice = cfg->custom_slice_ns ? cfg->custom_slice_ns : SLICE_TELEMETRY_NS;

        /* Enqueue to isolated DSQ_TELEMETRY with SCX_ENQ_HEAD */
        scx_bpf_dsq_insert(p, DSQ_TELEMETRY, slice, SCX_ENQ_HEAD | enq_flags);

        if (stats)
            stats->nr_enqueued_telemetry++;
    } else {
        /* Enqueue standard workload to DSQ_NORMAL */
        scx_bpf_dsq_insert(p, DSQ_NORMAL, SLICE_NORMAL_NS, enq_flags);

        if (stats)
            stats->nr_enqueued_normal++;
    }
}

/*
 * .dispatch callback
 * Strict priority draining: telemetry tasks are always consumed first.
 */
SEC("struct_ops/telemetry_dispatch")
void BPF_PROG(telemetry_dispatch, s32 cpu, struct task_struct *prev)
{
    struct sched_telemetry_stats *stats = get_stats();

    /* Priority Stage 1: Drain isolated Telemetry DSQ */
    if (scx_bpf_dsq_move_to_local(DSQ_TELEMETRY)) {
        if (stats)
            stats->nr_consumed_telemetry++;
        return;
    }

    /* Priority Stage 2: Drain standard workload DSQ */
    if (scx_bpf_dsq_move_to_local(DSQ_NORMAL)) {
        if (stats)
            stats->nr_consumed_normal++;
        return;
    }
}

/*
 * .running callback
 */
SEC("struct_ops/telemetry_running")
void BPF_PROG(telemetry_running, struct task_struct *p)
{
}

/*
 * .stopping callback
 */
SEC("struct_ops/telemetry_stopping")
void BPF_PROG(telemetry_stopping, struct task_struct *p, bool runnable)
{
}

/*
 * .init callback (sleepable struct_ops callback)
 * Initializes the dual custom DSQs upon scheduler registration.
 */
SEC("struct_ops.s/telemetry_init")
s32 BPF_PROG(telemetry_init)
{
    s32 err;

    /* Create isolated Telemetry DSQ */
    err = scx_bpf_create_dsq(DSQ_TELEMETRY, -1);
    if (err) {
        bpf_printk("scx_telemetry: failed to create DSQ_TELEMETRY: %d\n", err);
        return err;
    }

    /* Create Standard Workload DSQ */
    err = scx_bpf_create_dsq(DSQ_NORMAL, -1);
    if (err) {
        bpf_printk("scx_telemetry: failed to create DSQ_NORMAL: %d\n", err);
        scx_bpf_destroy_dsq(DSQ_TELEMETRY);
        return err;
    }

    bpf_printk("scx_telemetry: dual DSQs initialized successfully\n");
    return 0;
}

/*
 * .exit callback (sleepable struct_ops callback)
 */
SEC("struct_ops.s/telemetry_exit")
void BPF_PROG(telemetry_exit, struct scx_exit_info *ei)
{
    bpf_printk("scx_telemetry: scheduler detached\n");
}

/*
 * Sched_ext operations struct registration
 */
SEC(".struct_ops.link")
struct sched_ext_ops telemetry_ops = {
    .select_cpu         = (void *)telemetry_select_cpu,
    .enqueue            = (void *)telemetry_enqueue,
    .dispatch           = (void *)telemetry_dispatch,
    .running            = (void *)telemetry_running,
    .stopping           = (void *)telemetry_stopping,
    .init               = (void *)telemetry_init,
    .exit               = (void *)telemetry_exit,
    .name               = "scx_telemetry",
    .timeout_ms         = 5000,
};
