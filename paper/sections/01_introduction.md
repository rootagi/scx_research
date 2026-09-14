# Section 1: Introduction & Threat Model

## 1.1 Motivation & Emergence of `sched_ext`
The extensible scheduler class (`sched_ext`, or `SCHED_EXT`) represents one of the most fundamental shifts in modern Linux kernel architecture. Merged upstream in Linux 6.12, `sched_ext` allows developers and infrastructure operators to write custom CPU scheduling policies using eBPF (`struct_ops`), loading them dynamically into the running kernel without patching or recompilation. Industry adopters have deployed `sched_ext` to optimize gaming responsiveness, datacenter throughput, and multi-tenant virtualization.

However, moving core scheduling policies from rigid, kernel-enforced algorithms (such as CFS and EEVDF) into user-programmable eBPF bytecode fundamentally alters the trust and security boundaries of the operating system.

---

## 1.2 The Two-Stage EDR Pipeline Dilemma
Host-based Endpoint Detection and Response (EDR) agents, security audit systems (e.g., `auditd`), and cloud workload protection platforms (e.g., Falco, Tetragon, osquery) universally adhere to a **two-stage decoupled architecture**:

1. **Kernel Stage (Event Generation)**: Kernel probes (tracepoints, kprobes, LSM hooks) intercept system events (e.g., `execve`, `openat`, `ptrace`) and serialize them synchronously into per-CPU or global ring buffers (`BPF_MAP_TYPE_RINGBUF` or perf ring buffers).
2. **Userspace Stage (Event Consumption & Inference)**: A userspace daemon polls or reads from the ring buffer, deserializes event records, applies detection rule logic, correlates behavioral state, and alerts administrators or triggers response actions.

The fundamental security assumption underpinning this architecture is **eventually consistent ingestion**: the kernel assumes the userspace daemon will receive sufficient CPU execution time to consume events before the finite ring buffer overflows.

---

## 1.3 The Core Vulnerability: Micro-Quantum Starvation
We identify a structural vulnerability arising from the intersection of `sched_ext` and two-stage observability pipelines. Because `sched_ext` delegates per-task quantum allocation (`slice`) and Dispatch Queue (`DSQ`) selection entirely to user-defined BPF programs, an adversary possessing scheduler loading privileges can execute targeted CPU starvation attacks against the userspace security consumer:

- **Microsecond Execution Slices**: The adversary assigns micro-quantums (e.g., $50\,\mu\text{s}$) to the victim EDR daemon.
- **Priority Inversion via Custom DSQs**: Security daemons are routed to low-priority DSQs that are selectively drained or skipped.
- **Watchdog Evasion**: Linux kernels implement a 5-second task stall watchdog (`.timeout_ms = 5000`). By scheduling the victim task for $50\,\mu\text{s}$ every 200–300ms, the attacker maintains task liveness and satisfies the kernel watchdog, while reducing the EDR's throughput by $>95\%$.
- **Silent Telemetry Dropping**: Under sustained system load, the kernel ring buffer fills rapidly and drops security-critical events on the kernel fast-path with zero userspace notification.

---

## 1.4 Contributions
In this paper, we present:
1. **Adversarial Primitive Design (`scx_starve`)**: A comprehensive analysis of scheduling manipulation primitives under `sched_ext`.
2. **Statistically Rigorous Empirical Evaluation**: Multi-trial benchmarks ($N=30$) demonstrating $94.2\%\pm 2.1\%$ event drop rates and sub-second blind windows with non-parametric statistical significance ($p < 10^{-4}$).
3. **Advanced Attack Primitives**: Real-world demonstration of container escape blindness and a cross-privilege boundary covert timing channel achieving reliable bit transfer across isolated namespaces.
4. **Defensive Engineering & Upstream Patches**: An eBPF LSM monitoring engine (`scx_guard_lsm`), a userspace security daemon (`scx_monitor`), and two upstream LKML kernel patches introducing minimum dispatch slice floors and native tracepoints.
