# Section 6: Advanced Primitives & Extended Evaluation

## 6.1 Autonomous Diagnostic & Forensic Throttling
Beyond targeting specific security PIDs, `scx_starve` can operate autonomously by inspecting the `task_struct.comm` string during `.enqueue()` callbacks (`benchmark/scx_forensic_delay.bpf.c`).

When a system administrator or incident responder initiates live forensic investigation by executing diagnostic binaries (`strace`, `gdb`, `perf`, `bpftool`, `lsof`, `ausearch`), the scheduler dynamically routes the tool's threads to `DSQ_STARVE`.
- The forensic tool experiences extreme slowdowns (e.g., `strace` taking 30–60 seconds to trace a single process).
- The investigator observes erratic system performance without identifying code tampering or process kills.

---

## 6.2 Container Escape Blind Spot Experiment
To demonstrate concrete end-to-end security impact, we deployed an EDR sensor in a simulated Kubernetes node environment.

### Experimental Setup & Attack Flow
1. The EDR sensor actively monitors syscall invocations across all containers.
2. An unprivileged container escapes to the host via a known namespace/cgroup traversal technique (`experiments/container_escape_eval/run_escape_blindspot_bench.sh`).
3. Under CFS (Baseline), 100% of the container escape telemetry events (file touches in `/proc/1/root`, mounting cgroups, canary writes) are ingested and alerted on.
4. Under `scx_starve` (Level 3), the EDR userspace agent is starved. During the 5.5-second blind window:
   - Kernel ring buffer drops reach $96.8\%$.
   - The entire escape sequence completes before the EDR recovers.
   - Zero alerts or canary detections reach userspace logs.

---

## 6.3 Cross-Privilege Boundary Covert Timing Channel
We implement a cross-privilege communication channel between two unprivileged processes running in distinct UIDs and cgroups without shared memory, sockets, or files:
- **Transmitter (Tx)**: Modulates CPU contention across fixed time slots ($T_{\text{slot}} \in [10\text{ms}, 100\text{ms}]$) to transmit binary bits ('1' = busy spin, '0' = sleep).
- **Receiver (Rx)**: Samples sleep-wakeup jitter ($\Delta t = t_{\text{actual}} - t_{\text{sleep}}$). Under contention (Bit 1), $\Delta t$ exceeds $150\,\mu\text{s}$; under idle (Bit 0), $\Delta t \approx 10\,\mu\text{s}$.

### Channel Bandwidth & Accuracy
- At $T_{\text{slot}} = 50\,\text{ms}$, the channel achieves $20\,\text{bps}$ with $0.0\%\,\text{BER}$.
- At $T_{\text{slot}} = 10\,\text{ms}$, the channel achieves $100\,\text{bps}$ with $<4.2\%\,\text{BER}$.
