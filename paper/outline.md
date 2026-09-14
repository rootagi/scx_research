# Research Paper Structure & Section Outline

**Target Venues**: USENIX Security 2027 / ACM CCS 2027 / Black Hat USA

---

## Section 1: Introduction & Threat Model
- **1.1 Motivation**: The rise of programmable kernel scheduling (`sched_ext`) and its rapid adoption in cloud / enterprise Linux.
- **1.2 The Two-Stage EDR Pipeline Paradox**: Modern security agents rely on in-kernel event capture (eBPF / LSM) feeding userspace event consumers via ring buffers.
- **1.3 The Core Vulnerability**: User-defined schedulers can selectively starve consumers with micro-quantums ($50\,\mu\text{s}$) to induce silent ring buffer overflows while remaining below watchdog trip thresholds.
- **1.4 Threat Model & Ingress Vectors**: Post-exploitation capability inheritance (`CAP_BPF`, `CAP_PERFMON`, privileged container DaemonSets, local privilege escalation).
- **1.5 Summary of Contributions**: Empirical evaluation, advanced evasion primitives, covert timing channel, defensive LSM monitor, and upstream LKML kernel patches.

---

## Section 2: Background
- **2.1 Linux `sched_ext` Architecture**: `struct sched_ext_ops`, Dispatch Queues (DSQs), `.select_cpu`, `.enqueue`, `.dispatch` callbacks.
- **2.2 BPF Ring Buffers & Telemetry Ingestion**: Fast-path kernel event submission (`bpf_ringbuf_submit`) vs. userspace consumption (`ring_buffer__poll`).
- **2.3 EDR & Audit Sensor Architecture**: Falco, osquery, Tetragon, auditd architectures and their reliance on continuous CPU execution.

---

## Section 3: Attack Design (`scx_starve`)
- **3.1 DSQ Manipulation Primitives**: Inverting priority ordering with dual custom DSQs (`DSQ_STARVE` vs `DSQ_DEFAULT`).
- **3.2 Micro-Quantum Allocation**: Sub-millisecond slice duration assignment ($50\,\mu\text{s}$–$500\,\mu\text{s}$).
- **3.3 Probabilistic Dispatch Throttling**: Skipping 50%–75% of dispatch cycles using kernel monotonic timestamps.
- **3.4 Watchdog Evasion Mechanism**: Why 5-second stall watchdogs fail to detect high-frequency micro-quantum execution.

---

## Section 4: Empirical Evaluation
- **4.1 Experimental Methodology**: 4-vCPU environment, continuous background contention (stress-ng), standard security audit workloads.
- **4.2 Multi-Level Starvation Matrix**: Quantitative results across 5 intensity levels ($N=30$ repeated trials).
- **4.3 Statistical Significance**: Descriptive metrics (mean $\pm$ stddev, median, IQR) and non-parametric hypothesis tests (Mann-Whitney $U$, $p < 10^{-4}$).
- **4.4 Ingestion Latency Distributions**: Empirical Cumulative Distribution Functions (CDFs) of kernel-to-userspace delivery delay.
- **4.5 Cross-Kernel Version Evaluation**: Mainline matrix from 6.12 to 7.1.9.

---

## Section 5: Advanced Primitives
- **5.1 Autonomous Forensic Tool Throttling**: Auto-detecting forensic and diagnostic tools (`strace`, `gdb`, `perf`, `bpftool`) and imposing stealthy execution delays.
- **5.2 Container Escape Blind Spot Experiment**: Demonstrating 100% blind window creation during live simulated container escape sequences.
- **5.3 Cross-Privilege Boundary Covert Timing Channel**: Scheduling quantum modulation across isolated cgroups and UIDs; Bandwidth (bps) and Bit Error Rate (BER) characterization.

---

## Section 6: Detection Gap Analysis
- **6.1 Inefficacy of Traditional Tripwires**: Why process signals (`SIGKILL`, `SIGSTOP`), cgroup CPU quotas, and watchdog timers fail to detect `sched_ext` starvation.
- **6.2 Passive Tooling Blindness**: The limitations of standard `bpftool` and `lsmod` visibility in unmonitored environments.

---

## Section 7: Defensive Engineering & Mitigations
- **7.1 eBPF LSM Registration Guard (`scx_guard_lsm`)**: Real-time interception on `bpf_map_create` / `struct_ops`, extracting UID, PID, comm, and cgroup credentials.
- **7.2 Userspace Monitor Daemon (`scx_monitor`)**: Dual-engine monitoring with 500ms fallback polling and cryptographic allowlist verification.
- **7.3 Kernel Starvation Floor Patch**: Clamping minimum dispatch slices in `scx_bpf_dsq_insert` for tasks holding `CAP_SYS_PTRACE` or protected cgroups.
- **7.4 Upstream Tracepoints Proposal**: `sched_ext:scx_scheduler_load` and `sched_ext:scx_dsq_dispatch`.

---

## Section 8: Limitations & Future Work
- **8.1 Multi-Tenant Fairness**: Balancing security floor guarantees against scheduler programmability.
- **8.2 Dynamic Workload Adaptation**: Defenses under highly bursty, legitimate `sched_ext` workloads.

---

## Section 9: Responsible Disclosure Timeline
- **9.1 LKML Patch Submissions**: Thread records and community feedback.
- **9.2 Coordination with Upstream Maintainers & Security Teams**.
