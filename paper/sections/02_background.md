# Section 2: Background & Related Work

## 2.1 The `sched_ext` Extensible Scheduler Infrastructure
Linux's scheduler subsystem traditionally relied on the Completely Fair Scheduler (CFS) and more recently the Earliest Eligible Virtual Deadline First (EEVDF) scheduler. `sched_ext` introduces a new scheduling class (`ext_sched_class`) positioned directly between `stop_sched_class` / `dl_sched_class` / `rt_sched_class` and `fair_sched_class`.

When enabled, `sched_ext` routes scheduling decisions through an instantiated `struct sched_ext_ops` containing core eBPF callbacks:
- `.select_cpu(task, prev_cpu, wake_flags)`: Determines the CPU core on which a waking task should execute.
- `.enqueue(task, enq_flags)`: Inserts a runnable task into a dispatch queue (DSQ). BPF programs invoke `scx_bpf_dsq_insert(p, dsq_id, slice_ns, flags)` to set the queue destination and the execution quantum.
- `.dispatch(cpu, prev)`: Invoked when a CPU requires a new task. BPF programs call `scx_bpf_dsq_move_to_local(dsq_id)` to transfer tasks into the CPU's local execution queue.
- `.running(task)` / `.stopping(task, runnable)`: Lifecycle accounting hooks for tracking CPU consumption.
- `.init()` / `.exit()`: Sleepable setup and teardown callbacks.

### Dispatch Queues (DSQs)
Tasks reside in either:
- **Global DSQs (`SCX_DSQ_GLOBAL`)**: Shared across all CPUs in FIFO order.
- **Local DSQs (`SCX_DSQ_LOCAL`)**: Per-CPU runqueues dispatched immediately.
- **User-Defined Custom DSQs**: Arbitrary 64-bit ID queues (`scx_bpf_create_dsq()`) managed entirely by the BPF scheduler logic.

---

## 2.2 Kernel BPF Ring Buffers & Telemetry Dropping
Linux eBPF provides two primary ring buffer data structures for kernel-to-userspace communication:
1. `BPF_MAP_TYPE_PERF_EVENT_ARRAY`: Legacy per-CPU circular memory buffers.
2. `BPF_MAP_TYPE_RINGBUF`: Global multi-producer single-consumer circular memory buffers with lockless memory-mapped ring heads and tails.

When an in-kernel probe emits telemetry:
```c
struct event *e = bpf_ringbuf_reserve(&events_rb, sizeof(*e), 0);
if (!e) {
    /* Ring buffer is saturated -> event dropped silently */
    return;
}
bpf_ringbuf_submit(e, 0);
```
If `bpf_ringbuf_reserve` fails due to insufficient buffer head room, the event is permanently discarded in kernel memory. The Linux audit subsystem (`auditd`) exhibits an identical structural limitation: when the netlink backlog limit (`audit_backlog_limit`) is exceeded, events are marked `lost` and discarded.

---

## 2.3 EDR & Host Observability Architectures
Enterprise security sensors (e.g., Falco, Datadog Agent, CrowdStrike Falcon, Microsoft Defender for Endpoint) rely on real-time event deserialization to maintain process tree graphs, detect process injection, and flag anomalous network sockets. Because the volume of security events under standard server workloads reaches 10,000–100,000 events/sec, userspace daemons require consistent CPU scheduling slices to keep buffer consumption ahead of emission.
