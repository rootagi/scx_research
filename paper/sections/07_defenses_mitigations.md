# Section 7: Defensive Engineering & Kernel Mitigations

To address the vulnerabilities identified in this work, we propose, implement, and evaluate a multi-layered defense architecture comprising:
1. An eBPF LSM detection engine (`scx_guard_lsm`).
2. A userspace security monitor daemon (`scx_monitor`).
3. An upstream Linux kernel patch enforcing minimum quantum floors (`patches/0001-...`).
4. An upstream Linux kernel tracepoint RFC proposal (`patches/0002-...`).

---

## 7.1 Real-Time LSM Detection Hook (`scx_guard_lsm`)
Because all `sched_ext` schedulers must instantiate a `struct sched_ext_ops` map, we hook into the Linux Security Module (LSM) framework at the map creation boundary:
```c
SEC("lsm/bpf_map_create")
int BPF_PROG(scx_guard_map_create, struct bpf_map *map, union bpf_attr *attr, ...)
{
    if (map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
        // Intercept registration, inspect caller credentials, emit ringbuf telemetry
    }
}
```

### Telemetry Extraction & False Positive Mitigation
For every registration event, `scx_guard_lsm` extracts:
- Caller `uid`, `gid`, `pid`, `tgid`, `cgroup_id`.
- Caller executable `comm` and target `map_name`.
- Cryptographic hash / allowlist verification against known benign schedulers (`scx_lavd`, `scx_rusty`, `scx_bpfland`, `scx_simple`).

### Active Enforcement vs Passive Audit
- **Audit Mode (Default)**: Emits structured events to `/dev/scx_lsm_events` without interrupting scheduling operations.
- **Enforcement Mode (`-e`)**: Returns `-EPERM` from the LSM hook if the scheduler binary or name is not present in the allowlist, preventing rogue scheduler attachment at the kernel boundary.

---

## 7.2 Userspace Security Monitor Daemon (`scx_monitor`)
To guarantee detection even if BPF ring buffers experience momentary backpressure, `scx_monitor` implements a dual-engine architecture:
1. **Interrupt-Driven Ring Buffer Consumer**: Processes LSM events with sub-millisecond latency.
2. **Periodic Active Poller (500ms fallback)**: Periodically queries `bpftool struct_ops list -j` to detect any active schedulers loaded before daemon start or through auxiliary interfaces.

---

## 7.3 Kernel Starvation Floor Patch
In `kernel/sched/ext.c`, we introduce an invariant floor in `scx_bpf_dsq_insert()`:
```c
if (unlikely(scx_task_is_protected(p))) {
    u64 min_floor = (u64)sysctl_sched_min_granularity;
    if (slice < min_floor)
        slice = min_floor;
}
```
Where `scx_task_is_protected(p)` identifies tasks holding `CAP_SYS_PTRACE` or located within protected cgroup slices (`memory.oom.group`). This prevents arbitrary user schedulers from assigning micro-quantums ($<750\,\mu\text{s}$) to critical observability daemons.

---

## 7.4 Upstream Tracepoints Proposal
We define two new tracepoints in `include/trace/events/sched_ext.h`:
- `trace_scx_scheduler_load(p, name, prog_id, map_id)`
- `trace_scx_dsq_dispatch(p, dsq_id, slice_ns, enq_flags)`

These tracepoints provide fine-grained, zero-overhead observability for existing tracing frameworks (e.g., eBPF, SystemTap, LTTng).
