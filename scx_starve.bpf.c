#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "scx_starve.h"

char _license[] SEC("license") = "GPL";

/*
 * Map: Target PIDs to starve
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TARGET_PIDS);
    __type(key, __u32);
    __type(value, struct starve_target);
} target_pids SEC(".maps");

/*
 * Map: Global starvation configuration (single entry, index 0)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct starve_config);
} config_map SEC(".maps");

/*
 * Map: Per-CPU statistics
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct starve_stats);
} stats_map SEC(".maps");

static __always_inline struct starve_stats *get_stats(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&stats_map, &zero);
}

static __always_inline struct starve_config *get_config(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&config_map, &zero);
}

/*
 * Returns the starvation slice for the current intensity level.
 */
static __always_inline __u64 get_starve_slice(struct starve_config *cfg)
{
    if (cfg->custom_slice_ns > 0)
        return cfg->custom_slice_ns;

    switch (cfg->intensity) {
    case STARVE_INTENSITY_MILD:
        return SLICE_STARVE_MILD_NS;
    case STARVE_INTENSITY_MODERATE:
        return SLICE_STARVE_MOD_NS;
    case STARVE_INTENSITY_HEAVY:
    case STARVE_INTENSITY_DENY:
        return SLICE_STARVE_HEAVY_NS;
    default:
        return SLICE_DEFAULT_NS;
    }
}

/*
 * .select_cpu — delegate to kernel default idle CPU selection
 */
SEC("struct_ops/starve_select_cpu")
s32 BPF_PROG(starve_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

/*
 * .enqueue — the core offensive primitive
 *
 * Target PIDs → DSQ_STARVE (minimal slice, SCX_ENQ_LAST)
 * Everything else → DSQ_DEFAULT (normal slice, SCX_ENQ_HEAD for priority)
 */
SEC("struct_ops/starve_enqueue")
void BPF_PROG(starve_enqueue, struct task_struct *p, u64 enq_flags)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u32 tgid = BPF_CORE_READ(p, tgid);
    struct starve_target *target = NULL;
    struct starve_config *cfg = get_config();
    struct starve_stats *stats = get_stats();

    if (!cfg) {
        /* Fallback: dispatch normally if config unavailable */
        scx_bpf_dsq_insert(p, DSQ_DEFAULT, SLICE_DEFAULT_NS, enq_flags);
        return;
    }

    /* Intensity 0 = no starvation, everything goes to default */
    if (cfg->intensity == STARVE_INTENSITY_NONE) {
        scx_bpf_dsq_insert(p, DSQ_DEFAULT, SLICE_DEFAULT_NS, enq_flags);
        if (stats)
            stats->nr_enqueued_default++;
        return;
    }

    /* Check if this task is a starvation target */
    target = bpf_map_lookup_elem(&target_pids, &pid);
    if (!target)
        target = bpf_map_lookup_elem(&target_pids, &tgid);

    if (target && target->active) {
        __u64 slice = get_starve_slice(cfg);

        /*
         * OFFENSIVE PRIMITIVE:
         * Route to DSQ_STARVE with minimal slice.
         * NO SCX_ENQ_HEAD — these tasks sit at the back of the queue.
         * The dispatch callback will deprioritize or skip this queue entirely.
         */
        scx_bpf_dsq_insert(p, DSQ_STARVE, slice, enq_flags);

        if (stats)
            stats->nr_enqueued_starve++;
    } else {
        /*
         * Non-target tasks get full priority treatment:
         * SCX_ENQ_HEAD ensures they jump ahead of any starved tasks.
         */
        scx_bpf_dsq_insert(p, DSQ_DEFAULT, SLICE_DEFAULT_NS,
                            SCX_ENQ_HEAD | enq_flags);

        if (stats)
            stats->nr_enqueued_default++;
    }
}

/*
 * .dispatch — inverted priority consumption
 *
 * DSQ_DEFAULT is ALWAYS consumed first (normal workloads get all CPU).
 * DSQ_STARVE is consumed last, or skipped entirely based on intensity:
 *   Level 1: Always consumed last (mild starvation)
 *   Level 2: Consumed only 50% of dispatch cycles
 *   Level 3: Consumed only 25% of dispatch cycles
 *   Level 4: NEVER consumed (complete CPU denial)
 */
SEC("struct_ops/starve_dispatch")
void BPF_PROG(starve_dispatch, s32 cpu, struct task_struct *prev)
{
    struct starve_config *cfg = get_config();
    struct starve_stats *stats = get_stats();

    if (stats)
        stats->nr_dispatch_cycles++;

    /* Stage 1: Always drain normal workloads first */
    if (scx_bpf_dsq_move_to_local(DSQ_DEFAULT)) {
        if (stats)
            stats->nr_consumed_default++;
        return;
    }

    /*
     * Stage 2: Only reach here if DSQ_DEFAULT is empty.
     * Apply starvation policy to DSQ_STARVE.
     */
    if (!cfg) {
        /* Fallback: consume starve queue if config unavailable */
        if (scx_bpf_dsq_move_to_local(DSQ_STARVE)) {
            if (stats)
                stats->nr_consumed_starve++;
        }
        return;
    }

    switch (cfg->intensity) {
    case STARVE_INTENSITY_NONE:
    case STARVE_INTENSITY_MILD:
        /* Level 0-1: Consume starved tasks when nothing else is available */
        if (scx_bpf_dsq_move_to_local(DSQ_STARVE)) {
            if (stats)
                stats->nr_consumed_starve++;
        }
        break;

    case STARVE_INTENSITY_MODERATE:
        /* Level 2: Skip ~50% of dispatch cycles for starved tasks */
        if (bpf_ktime_get_ns() % 2 == 0) {
            if (scx_bpf_dsq_move_to_local(DSQ_STARVE)) {
                if (stats)
                    stats->nr_consumed_starve++;
            }
        } else {
            if (stats)
                stats->nr_dispatch_skipped++;
        }
        break;

    case STARVE_INTENSITY_HEAVY:
        /* Level 3: Skip ~75% of dispatch cycles for starved tasks */
        if (bpf_ktime_get_ns() % 4 == 0) {
            if (scx_bpf_dsq_move_to_local(DSQ_STARVE)) {
                if (stats)
                    stats->nr_consumed_starve++;
            }
        } else {
            if (stats)
                stats->nr_dispatch_skipped++;
        }
        break;

    case STARVE_INTENSITY_DENY:
        /* Level 4: NEVER consume — complete CPU denial */
        if (stats)
            stats->nr_dispatch_skipped++;
        break;
    }
}

/*
 * .running / .stopping — reserved for future per-task time tracking
 */
SEC("struct_ops/starve_running")
void BPF_PROG(starve_running, struct task_struct *p)
{
}

SEC("struct_ops/starve_stopping")
void BPF_PROG(starve_stopping, struct task_struct *p, bool runnable)
{
}

/*
 * .init — create dual DSQs (sleepable)
 */
SEC("struct_ops.s/starve_init")
s32 BPF_PROG(starve_init)
{
    s32 err;

    err = scx_bpf_create_dsq(DSQ_STARVE, -1);
    if (err) {
        bpf_printk("scx_starve: failed to create DSQ_STARVE: %d\n", err);
        return err;
    }

    err = scx_bpf_create_dsq(DSQ_DEFAULT, -1);
    if (err) {
        bpf_printk("scx_starve: failed to create DSQ_DEFAULT: %d\n", err);
        scx_bpf_destroy_dsq(DSQ_STARVE);
        return err;
    }

    bpf_printk("scx_starve: adversarial scheduler initialized\n");
    return 0;
}

/*
 * .exit — teardown (sleepable)
 */
SEC("struct_ops.s/starve_exit")
void BPF_PROG(starve_exit, struct scx_exit_info *ei)
{
    bpf_printk("scx_starve: scheduler detached\n");
}

/*
 * struct_ops registration
 */
SEC(".struct_ops.link")
struct sched_ext_ops starve_ops = {
    .select_cpu         = (void *)starve_select_cpu,
    .enqueue            = (void *)starve_enqueue,
    .dispatch           = (void *)starve_dispatch,
    .running            = (void *)starve_running,
    .stopping           = (void *)starve_stopping,
    .init               = (void *)starve_init,
    .exit               = (void *)starve_exit,
    .name               = "scx_starve",
    .timeout_ms         = 5000,
};
