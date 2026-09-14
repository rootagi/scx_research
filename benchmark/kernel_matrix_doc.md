# Kernel Version Compatibility & Exploitability Matrix

## Overview

The `sched_ext` (BPF Extensible Scheduler Class) infrastructure was merged into the upstream Linux kernel tree in Linux 6.12. This document analyzes the evolution of `sched_ext` APIs, architectural invariants, and exploitability of adversarial starvation primitives across mainline kernel releases.

---

## Version-by-Version Analysis

| Kernel Version | Merge Status | `sched_ext` API State | DSQ Invariant Enforcement | Exploitability of `scx_starve` | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Linux 6.12** | **Initial Merge** | Initial `struct sched_ext_ops` (commit `f0e1a0643a59`) | No slice floor; `scx_bpf_dsq_insert` permits 0–50µs slices without capability checks on target task | **Fully Exploitable (100% telemetry drop at Level 3–4)** | Primitive established; BPF verifier enforces type safety but no fairness bounds |
| **Linux 6.13** | **Stabilization** | DSQ API consolidation, `scx_bpf_select_cpu_dfl` optimizations | DSQ priority ordering remains unpoliced in userspace struct_ops | **Fully Exploitable** | Core dispatch semantics unchanged; `SCX_ENQ_HEAD` / `SCX_ENQ_LAST` usable arbitrarily |
| **Linux 7.0** | **Refinements** | Sleepable callback lifecycle enhancements (`init`/`exit`), core struct_ops updates | Default watchdog timer (5000ms) prevents total kernel lockup, but fine-grained starvation (e.g. 50µs) evades watchdog | **Fully Exploitable** | Sub-millisecond slices still valid; watchdog only triggers if task never runs for 5s |
| **Linux 7.1.9** | **Current Baseline** | Current stable `sched_ext` API | No kernel-level minimum slice floor for security/monitoring daemons | **Fully Exploitable (Demonstrated empirically)** | Baseline for empirical results in Table 1; drops verified across levels 1–4 |

---

## Key Technical Invariants & Gaps

### 1. The Watchdog Evasion Gap
Linux `sched_ext` includes a task stall watchdog (`.timeout_ms = 5000`). However:
- **Watchdog Trigger Condition**: A task must be starved completely for longer than `timeout_ms` (5 seconds).
- **Adversarial Exploitation**: `scx_starve` Levels 1–3 allocate microscopic time slices ($50\,\mu\text{s}$ to $500\,\mu\text{s}$) or skip dispatch cycles intermittently (50%–75% skip rate).
- **Result**: The victim task *does* run periodically (e.g., once every 100–300ms for $50\,\mu\text{s}$), continuously resetting the kernel watchdog timer while starving the userspace ring buffer consumer below the ingestion throughput threshold.

### 2. Lack of Invariant Floor in `scx_bpf_dispatch`
In all current kernel versions (6.12 through 7.1.9):
```c
/* kernel/sched/ext.c */
void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags)
{
    /* No validation against sysctl_sched_min_granularity */
    /* No check on task's cgroup, CAP_SYS_PTRACE, or security daemon status */
    ...
}
```
The kernel accepts arbitrary `slice` values down to $1\,\text{ns}$, enabling fine-grained starvation.

### 3. Structural Lack of LSM Mediation
Registration of a `sched_ext_ops` scheduler occurs via `BPF_MAP_TYPE_STRUCT_OPS` map creation and link attachment. In mainline kernels 6.12–7.1.9:
- No dedicated LSM hook (`security_sched_ext_register`) exists.
- General `bpf_map_create` / `bpf_link_create` LSM hooks do not differentiate between normal BPF maps and whole-system scheduler takeovers unless explicitly inspected by custom BPF LSM programs (addressed in our Phase 1 defensive engineering).
