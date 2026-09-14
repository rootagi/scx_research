#ifndef __SCX_STARVE_H
#define __SCX_STARVE_H

#if !defined(__bpf__) && !defined(__KERNEL__)
#include <linux/types.h>
#include <stdbool.h>
#endif

/*
 * Dispatch Queue (DSQ) Identifiers — Adversarial Scheduler
 */
#define DSQ_STARVE              2001ULL   /* Starvation queue — consumed LAST, minimal slice */
#define DSQ_DEFAULT             2002ULL   /* Normal workload — consumed FIRST, standard slice */

/*
 * Starvation Intensity Levels
 *
 * Level 0: No starvation (control baseline) — target gets normal 5ms slice
 * Level 1: Mild — 500 µs slice, always consumed last
 * Level 2: Moderate — 100 µs slice, skip consumption 50% of dispatch cycles
 * Level 3: Heavy — 50 µs slice, skip 75% of dispatch cycles
 * Level 4: Deny — never consume from DSQ_STARVE (complete CPU denial)
 */
#define STARVE_INTENSITY_NONE     0
#define STARVE_INTENSITY_MILD     1
#define STARVE_INTENSITY_MODERATE 2
#define STARVE_INTENSITY_HEAVY    3
#define STARVE_INTENSITY_DENY     4

/*
 * Time slices per intensity level (nanoseconds)
 */
#define SLICE_DEFAULT_NS        (5ULL * 1000 * 1000)        /* 5 ms */
#define SLICE_STARVE_MILD_NS    (500ULL * 1000)             /* 500 µs */
#define SLICE_STARVE_MOD_NS     (100ULL * 1000)             /* 100 µs */
#define SLICE_STARVE_HEAVY_NS   (50ULL * 1000)              /* 50 µs */

#define MAX_TARGET_PIDS         1024
#define TASK_COMM_LEN           16

/*
 * Per-target starvation configuration
 */
struct starve_target {
    __u32 active;               /* 1 = actively starving this PID */
    char  comm[TASK_COMM_LEN];  /* Process name for logging */
};

/*
 * Global scheduler configuration — writable from userspace
 */
struct starve_config {
    __u32 intensity;            /* 0–4 starvation level */
    __u64 custom_slice_ns;      /* Override slice (0 = use intensity default) */
};

/*
 * Aggregate statistics
 */
struct starve_stats {
    __u64 nr_enqueued_starve;       /* Tasks routed to starvation queue */
    __u64 nr_enqueued_default;      /* Tasks routed to default queue */
    __u64 nr_consumed_starve;       /* Starved tasks actually dispatched */
    __u64 nr_consumed_default;      /* Normal tasks dispatched */
    __u64 nr_dispatch_skipped;      /* Dispatch cycles where starvation queue was intentionally skipped */
    __u64 nr_dispatch_cycles;       /* Total dispatch cycles */
};

#endif /* __SCX_STARVE_H */
