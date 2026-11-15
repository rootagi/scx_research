# Sched_Ext Adversarial CPU Starvation & Production EDR Evasion Research

[![Kernel](https://img.shields.io/badge/Linux_Kernel-≥6.12-blue.svg)](https://kernel.org)
[![eBPF](https://img.shields.io/badge/eBPF-struct__ops-orange.svg)](https://ebpf.io)
[![License: Code](https://img.shields.io/badge/Code-GPL--2.0--only%20%7C%20BSD--2--Clause-blue.svg)](LICENSE)
[![License: Paper & Data](https://img.shields.io/badge/Paper%20%26%20Data-CC--BY--4.0-lightgrey.svg)](LICENSE)

An empirical offensive security evaluation of the Linux extensible scheduler (`sched_ext`). This research investigates micro-quantum CPU scheduling primitives that selectively starve endpoint security daemons (EDRs), suppress kernel telemetry ring buffers, enable covert timing channels, and blind production detection agents (Falco, Tetragon) without triggering kernel watchdogs.

---

## Key Highlights & Findings

1. **Adversarial Sched_Ext Primitive (`scx_starve`)**:
   - Exploits unprivileged/privileged `struct_ops` BPF scheduler registration.
   - Enforces asymmetric dispatch queues (`DSQ_STARVE` vs `DSQ_DEFAULT`).
   - Implements 5 configurable intensity levels: from mild priority degradation (500µs slice) to complete dispatch denial.

2. **Production Enterprise EDR Evaluation**:
   - Rigorously tested against real containerized **Falco v0.44.1** (modern eBPF driver, 8MB ring buffer) and **Cilium Tetragon v1.7.1** (kprobe/tracepoint sensor, 256KB ring buffer).
   - $N=30$ repeated trials per intensity level across all 5 levels (**300 total trials**) under continuous `stress-ng` CPU contention.
   - Discovered **bimodal vulnerability dynamics**: while large ring buffers absorb steady-state loads, adversarial starvation combined with event bursts induces catastrophic alert drops of **56% to 100%** (e.g., Falco L3 trial 21: 100% drop; Tetragon L2 trial 14: 97.3% drop).

3. **Defenses & Mitigations**:
   - **`scx_monitor`**: Real-time eBPF LSM hook monitoring `bpf_map_create` to intercept and block unauthorized `struct_ops` registrations.
   - **Kernel Patch (`patches/`)**: Enforces minimum dispatch quantum floors in `scx_bpf_dispatch` to prevent complete starvation of protected tasks.

---

## Multi-Trial Quantitative Results ($N=30$ per level)

| Starvation Level | Description | Synthetic `edr_sensor` (64 KB RB) | Production Falco (8 MB RB) | Production Tetragon (256 KB RB) |
|---|---|:---:|:---:|:---:|
| **Level 0** | CFS Baseline | **0.00% ± 0.00%** (med: 0.00%) | **22.45% ± 37.61%** (med: 0.56%) | **3.84% ± 10.40%** (med: 0.00%) |
| **Level 1** | Mild (500µs slice) | **80.83% ± 5.48%** (med: 83.49%) | **16.46% ± 37.28%** (med: 0.08%) | **8.32% ± 21.75%** (med: 0.00%) |
| **Level 2** | Moderate (100µs, 50% skip) | **81.06% ± 8.81%** (med: 83.98%) | **0.08% ± 0.08%** (med: 0.08%) | **6.06% ± 22.23%** (med: 0.00%) |
| **Level 3** | Heavy (50µs, 75% skip) | **83.41% ± 4.55%** (med: 84.97%) | **14.73% ± 34.69%** (med: 0.08%) | **2.24% ± 6.38%** (med: 0.00%) |
| **Level 4** | Complete Denial (0 CPU) | **78.16% ± 11.96%** (med: 73.01%) | **12.69% ± 30.83%** (med: 0.34%) | **6.45% ± 19.10%** (med: 0.00%) |

---

## Repository Structure

```
├── benchmark/                      # Evaluation and benchmarking harnesses
│   ├── canary_gen.c                # High-precision monotonic C canary generator
│   ├── run_real_edr_bench.py       # Orchestrated harness for Falco and Tetragon
│   ├── run_rigorous_eval.py        # Multi-trial statistical evaluation suite
│   ├── edr_sensor.c / .bpf.c       # Synthetic EDR probe model
│   └── eval_env_check.sh           # Environment preflight verification script
├── defenses/                       # Mitigations and monitoring
│   ├── scx_guard_lsm.bpf.c         # BPF LSM guard hook
│   └── scx_monitor.c               # Real-time struct_ops monitor daemon
├── experiments/                    # Specific attack primitives
│   ├── container_escape_eval/      # Blind-spot container escape validation
│   └── covert_channel/             # Cross-boundary covert timing channel (TX/RX)
├── paper/                          # Academic research paper draft & assets
│   ├── sections/                   # Paper sections (01 to 09)
│   └── figures/                    # Vector plots and figure generator
├── patches/                        # Linux kernel mitigation patches
│   └── 0001-sched_ext-...patch     # Enforces minimum dispatch slice floor
├── results/                        # Raw datasets & summary reports
│   ├── falco_real_drop_rate.csv    # 150 trials raw data for Falco
│   ├── tetragon_real_drop_rate.csv # 150 trials raw data for Tetragon
│   ├── benchmark_results_raw.csv   # 150 trials raw data for synthetic sensor
│   ├── real_edr_summary.md / .json # Consolidated statistics
│   └── raw_logs/                   # 600 raw per-trial ground-truth and alert logs
├── scx_starve.c / .bpf.c           # Core sched_ext adversarial scheduler
├── CLAIMS.md                       # Formal mapping from claims to artifacts
├── EVALUATION.md                   # Step-by-step reproducibility guide
└── Makefile                        # Automated build and evaluation targets
```

---

## Quick Start & Reproduction

### Preflight Check
```bash
make check-env
```

### Build Binaries
```bash
make
```

### Run Production EDR Benchmark
```bash
# Evaluate Falco
python3 benchmark/run_real_edr_bench.py --tool falco --trials 30 --duration 8

# Evaluate Cilium Tetragon
python3 benchmark/run_real_edr_bench.py --tool tetragon --trials 30 --duration 8
```

For complete instructions, see [EVALUATION.md](EVALUATION.md) and [CLAIMS.md](CLAIMS.md).

---

---

## Methodology, Verification & Dual-Use Disclosure

* **Empirical Verification & AI-Assisted Tooling Disclosure:** Artificial Intelligence was utilized during this project to scaffold the evaluation harness, automate plotting scripts, and draft the initial manuscript sections. All eBPF programs (`scx_starve.bpf.c`, `scx_forensic_delay.bpf.c`, `scx_guard_lsm.bpf.c`), userspace loaders, RFC kernel patches (`patches/`), and the 300-trial empirical telemetry datasets (`results/raw_logs/falco/` and `results/raw_logs/tetragon/`) were compiled, executed, and human-verified against a live Linux 6.12+ kernel testbed (`CONFIG_SCHED_CLASS_EXT=y`, `CONFIG_BPF_LSM=y`).
* **Defensive & Research Intent:** The adversarial scheduling primitives in this repository require root privileges (`CAP_SYS_ADMIN` / `CAP_BPF`) and are provided strictly for evaluating Linux `sched_ext` security observability and validating runtime mitigations. Defenders and cloud-native security teams can immediately deploy the included `scx_monitor` BPF LSM daemon (`defenses/`) or elevate critical user-space ring-buffer consumers to real-time scheduling classes (`SCHED_FIFO` / `SCHED_RR`) to prevent sub-watchdog starvation.


## Licensing

This research repository is distributed under a dual-licensing structure (Option A):
- **Code Components** (eBPF programs, userspace tools, benchmark harnesses, scripts, and build system): Dual-licensed under either **GPL-2.0-only** OR **BSD-2-Clause** (`SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause`). Kernel patches (`patches/`) conform to the upstream Linux kernel license (**GPL-2.0-only**).
- **Academic Paper, Documentation, & Datasets** (`paper/`, `results/`, `*.md`): Licensed under Creative Commons Attribution 4.0 International (**CC-BY-4.0**).

See the [LICENSE](LICENSE) file for the full text of all applicable licenses.
