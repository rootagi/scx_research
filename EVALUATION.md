# Artifact Evaluation & Reproducibility Guide

## System Requirements

- **Linux Kernel**: $\ge 6.12$ with `CONFIG_SCHED_CLASS_EXT=y` and `CONFIG_DEBUG_INFO_BTF=y`.
- **BPF LSM Support**: `CONFIG_BPF_LSM=y` (verify with `cat /sys/kernel/security/lsm`).
- **Compiler Toolchain**: `clang` ($\ge 14$), `bpftool`, `gcc`, `make`.
- **System Utilities**: `stress-ng`, `auditctl`, `python3` ($\ge 3.9$).
- **Python Libraries**: `numpy`, `scipy`, `matplotlib`.
- **Privileges**: Root access (`sudo` or root shell) to load eBPF `struct_ops` and LSM programs.

---

## Step 0: Preflight Validation

Before launching evaluation targets, run the automated environment check:
```bash
make check-env
# Or directly:
bash benchmark/eval_env_check.sh
```
Expected output:
```
======================================================================
        sched_ext Security Research: Artifact Preflight Check         
======================================================================
[*] Checking Linux kernel version (7.1.9-arch1-2)... PASS (>= 6.12 sched_ext merge)
[*] Verifying CONFIG_SCHED_CLASS_EXT=y... PASS (CONFIG_SCHED_CLASS_EXT is enabled)
[*] Verifying Kernel BTF (/sys/kernel/btf/vmlinux)... PASS
[*] Checking dependency: Clang C/BPF Compiler (clang)... PASS
[*] Checking dependency: BPF Tooling (bpftool)... PASS
[*] Checking dependency: GNU C Compiler (gcc)... PASS
[*] Checking dependency: GNU Make (make)... PASS
[*] Checking dependency: Stress-ng Workload Generator (stress-ng)... PASS
[*] Checking dependency: Linux Audit Control (auditctl)... PASS
[*] Checking dependency: Python 3 Interpreter (python3)... PASS
[*] Checking Python scipy, numpy, matplotlib... PASS
[*] Checking runtime permissions... PASS
======================================================================
[+] Preflight checks PASSED with 0 warning(s). Ready for evaluation.
```

---

## Step 1: Quick Verification (Smoke Test, ~1–2 min)

To verify the complete build and run a short 5-trial benchmark smoke test:
```bash
make eval-quick
```
This runs 5 trials per intensity level at 4s duration, verifies statistical computation, and produces summary tables in `results/`.

---

## Step 2: Full Statistical Evaluation ($N=30$ trials, ~15–20 min)

To produce the primary empirical evaluation tables for the paper:
```bash
make eval-full
```
This executes:
- 30 repeated trials across Levels 0, 1, 2, 3, and 4.
- Collects raw telemetry ingestion metrics.
- Runs Mann-Whitney U hypothesis testing against Level 0.
- Writes:
  - `results/benchmark_results_raw.csv`
  - `results/benchmark_summary.json`
  - `results/benchmark_summary.md`
  - `results/benchmark_table.tex`

---

## Step 3: Container Escape Blind Spot Evaluation

To run the container escape blind spot experiment:
```bash
make eval-escape
```

---

## Step 4: Covert Timing Channel Benchmark

To measure cross-privilege communication bandwidth and BER:
```bash
make eval-covert
```

---

## Step 5: Production EDR Evaluation (Falco & Tetragon)

To evaluate real enterprise EDRs under `scx_starve` with ground-truth canary generation:
```bash
# Evaluate Falco (v0.44.1, 8MB ring buffer)
python3 benchmark/run_real_edr_bench.py --tool falco --trials 30 --duration 8

# Evaluate Cilium Tetragon (v1.7.1, 256KB ring buffer)
python3 benchmark/run_real_edr_bench.py --tool tetragon --trials 30 --duration 8
```
Outputs saved in `results/`:
- `results/falco_real_drop_rate.csv` (150 trials)
- `results/tetragon_real_drop_rate.csv` (150 trials)
- `results/real_edr_summary.md` and `results/real_edr_summary.json`
- Raw per-trial ground-truth and alert logs in `results/raw_logs/{falco,tetragon}/`

---

## Step 6: Generate Publication Figures

To render all publication-ready vector figures (`.pdf` and `.png`):
```bash
make figures
```
Outputs saved in `paper/figures/`:
- `fig_latency_cdf.pdf` / `fig_latency_cdf.png`
- `fig_blind_window_timeline.pdf` / `fig_blind_window_timeline.png`
- `fig_covert_channel.pdf` / `fig_covert_channel.png`

---

## Step 6: All-in-One Full Evaluation

To execute all steps in sequence:
```bash
make eval
```
