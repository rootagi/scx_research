# Section 4: Attack Design (`scx_starve`)

## 4.1 Dual-DSQ Inverted Priority Architecture
The core mechanism of `scx_starve` is the establishment of asymmetric Dispatch Queues that decouple target security processes from background workloads:

- **`DSQ_DEFAULT` (Workload / Attacker Queue)**: Assigned standard execution quantums (`SLICE_DEFAULT_NS = 5ms`) and tagged with `SCX_ENQ_HEAD` to ensure preemption and immediate dispatch.
- **`DSQ_STARVE` (Victim Queue)**: Assigned microscopic quantums (`SLICE_STARVE = 50µs`–`500µs`) and placed at the tail of the dispatch queue without head-of-line priority.

```
       Task Enqueue (.enqueue)
                  │
        ┌─────────┴─────────┐
        │  Target PID/Comm? │
        └──┬─────────────┬──┘
      Yes  │             │  No
           ▼             ▼
   ┌───────────────┐ ┌───────────────┐
   │  DSQ_STARVE   │ │  DSQ_DEFAULT  │
   │  (50µs slice, │ │  (5ms slice,  │
   │   tail order) │ │   head-of-line)
   └───────┬───────┘ └───────┬───────┘
           │                 │
           │  Priority Drain │
           └─────────┬───────┘
                     ▼
           CPU Dispatch (.dispatch)
```

---

## 4.2 Multi-Intensity Starvation Spectrum

We parameterize `scx_starve` into five distinct operational levels:

| Level | Name | Quantum Slice ($\tau$) | Dispatch Strategy | Intended Operational Effect |
| :---: | :--- | :---: | :--- | :--- |
| **0** | **Baseline (Control)** | $5000\,\mu\text{s}$ | 100% normal FIFO dispatch | Standard CFS equivalent baseline |
| **1** | **Mild Starvation** | $500\,\mu\text{s}$ | Drained strictly after `DSQ_DEFAULT` | Telemetry delays; low drop rate (~5–15%) |
| **2** | **Moderate Starvation** | $100\,\mu\text{s}$ | Skipped on 50% of dispatch cycles | Severe ingestion delay; ~40–60% drop rate |
| **3** | **Heavy Starvation** | $50\,\mu\text{s}$ | Skipped on 75% of dispatch cycles | **Telemetry collapse (>90% drop rate); blind window** |
| **4** | **Complete Denial** | $0\,\mu\text{s}$ | 0% dispatch (Never drained) | Complete CPU denial (triggers watchdog after 5s) |

---

## 4.3 Overcoming the Kernel Task Stall Watchdog
Linux `sched_ext` embeds a safety watchdog:
```c
struct sched_ext_ops starve_ops = {
    ...
    .timeout_ms = 5000,
};
```
If any runnable task is neglected for longer than `timeout_ms`, the kernel generates an `SCX_ECODE_ACT_WATCHDOG` kernel panic/detach and reverts to CFS.

**Adversarial Evasion Strategy**:
By setting the starvation level to **Level 3 (Heavy Starvation)** rather than Level 4:
1. The victim process runs every 150–250ms for a tiny $50\,\mu\text{s}$ slice.
2. Each dispatch invocation updates `p->scx.slice` and the task's execution timestamp, perpetually resetting the kernel watchdog timer.
3. The victim process remains in state `TASK_RUNNING`, evading process status tripwires (`/proc/[pid]/status` shows `R`).
4. Over a 10-second interval, the victim receives $<15\,\text{ms}$ of total CPU time (an effective CPU allocation of $\approx 0.15\%$), creating an uninterrupted 10-second telemetry blind window.
