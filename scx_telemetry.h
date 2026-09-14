#ifndef __SCX_TELEMETRY_H
#define __SCX_TELEMETRY_H

#if !defined(__bpf__) && !defined(__KERNEL__)
#include <linux/types.h>
#include <stdbool.h>
#endif

/*
 * Dispatch Queue (DSQ) Identifiers
 * Custom DSQs must use 64-bit IDs that do not conflict with built-in DSQs.
 */
#define DSQ_TELEMETRY           1001ULL   /* Dedicated high-priority queue for telemetry daemons */
#define DSQ_NORMAL              1002ULL   /* Standard queue for general system workloads */

/*
 * Default Scheduling Slices (Nanoseconds)
 */
#define SLICE_TELEMETRY_NS      (20ULL * 1000 * 1000)   /* 20 ms */
#define SLICE_NORMAL_NS         (5ULL * 1000 * 1000)    /* 5 ms */

#define MAX_TARGET_PIDS         1024
#define TASK_COMM_LEN           16

/*
 * Dynamic Task Configuration struct passed from userspace control plane
 */
struct task_config {
    __u32 priority;             /* 1 = Telemetry/High-Prio, 0 = Normal */
    __u64 custom_slice_ns;      /* Optional custom time slice override (0 = use default) */
    char  comm[TASK_COMM_LEN];  /* Process name for diagnostics and logging */
};

/*
 * Aggregate Statistics per-CPU and global
 */
struct sched_telemetry_stats {
    __u64 nr_enqueued_telemetry;
    __u64 nr_enqueued_normal;
    __u64 nr_consumed_telemetry;
    __u64 nr_consumed_normal;
    __u64 nr_direct_dispatches;
    __u64 nr_kicks;
};

#endif /* __SCX_TELEMETRY_H */
