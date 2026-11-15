# Artifact Claims & Benchmark Evaluation Mapping

This document explicitly maps each empirical and technical claim presented in the research paper to the corresponding benchmark script, configuration, output dataset, and figure generator.

---

## Claims to Artifacts Mapping Table

| # | Paper Claim | Source Section | Reproducing Script / Command | Target Output Artifact | Validation Metric |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **C1** | **Micro-quantum scheduling ($50\,\mu\text{s}$ slice) induces >90% kernel ring buffer telemetry drops without triggering kernel watchdogs.** | Section 4, Table 1 | `python3 benchmark/run_rigorous_eval.py --trials 30 --duration 8` | `results/benchmark_summary.json`<br>`results/benchmark_summary.md` | Mean Drop Rate $\ge 90\%$, $p < 10^{-4}$ vs Level 0 |
| **C2** | **Statistical significance of starvation impact holds across 30 repeated trials under non-parametric Mann-Whitney U testing.** | Section 4, Table 1 | `python3 benchmark/run_rigorous_eval.py --trials 30` | `results/benchmark_table.tex`<br>`results/benchmark_results_raw.csv` | MW-$U$ $p$-value $< 10^{-4}$ across Levels 1–4 |
| **C3** | **Container escape payloads executed under `scx_starve` Level 3 remain completely undetected in user-space telemetry.** | Section 5.1 | `bash experiments/container_escape_eval/run_escape_blindspot_bench.sh` | Terminal log / `results/escape_eval.log` | 0 escape canary alerts delivered during blind window |
| **C4** | **Cross-privilege boundary covert communication achieves up to 100 bps with 0.0% BER under quiet conditions and $>20$ bps under heavy contention.** | Section 5.2 | `python3 experiments/covert_channel/run_covert_bench.py` | `paper/figures/fig_covert_channel.pdf` | Measured $\text{BER} < 1\%$ for $\text{slot} \ge 25\text{ms}$ |
| **C5** | **eBPF LSM hook on `bpf_map_create` intercepts 100% of unauthorized `struct_ops` registrations in real-time with negligible overhead.** | Section 7.1 | `./defenses/scx_monitor -e &`<br>`./scx_starve -I 1` | `scx_monitor` audit logs | Event emitted synchronously, return code `-EPERM` |
| **C6** | **Enforcing minimum dispatch quantum floor in `scx_bpf_dispatch` neutralizes ringbuffer starvation for protected tasks.** | Section 7.2 | Kernel patch verification | `patches/0001-sched_ext-Enforce-minimum-dispatch-slice-floor-for-p.patch` | Code review / LKML submission |
| **C7** | **Adversarial CPU starvation induces catastrophic alert drops (up to 100% in Falco, 97.3% in Tetragon) in production enterprise EDR daemons.** | Section 5.5 | `python3 benchmark/run_real_edr_bench.py --tool {falco,tetragon}` | `results/falco_real_drop_rate.csv`<br>`results/tetragon_real_drop_rate.csv`<br>`results/real_edr_summary.md` | Bimodal drop spikes (56%–100%) during saturation |

---

## One-Command Full Evaluation
To evaluate all claims in sequence and generate the complete paper artifact package:
```bash
make eval
```
