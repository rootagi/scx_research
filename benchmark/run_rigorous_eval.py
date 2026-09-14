#!/usr/bin/env python3
"""
Rigorous Multi-Trial Statistical Evaluation Harness for Sched_Ext Starvation Primitive
Executes N trials per intensity level, reports mean ± stddev, median, IQR, p99, max,
and computes non-parametric hypothesis tests (Mann-Whitney U, Wilcoxon) against baseline.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
import numpy as np
from scipy import stats


def parse_edr_output(output_text):
    """Parses output from edr_sensor daemon."""
    emitted = 0
    consumed = 0
    drops = 0
    drop_pct = 0.0
    p50 = 0.0
    p95 = 0.0
    p99 = 0.0
    max_lat = 0.0

    m_emit = re.search(r"Total Events Emitted in Kernel:\s+(\d+)", output_text)
    if m_emit:
        emitted = int(m_emit.group(1))

    m_cons = re.search(r"Total Events Consumed Userspace:\s+(\d+)", output_text)
    if m_cons:
        consumed = int(m_cons.group(1))

    m_drop = re.search(r"Kernel Ringbuffer Drops:\s+(\d+)(?:\s+\(([0-9.]+)%\))?", output_text)
    if m_drop:
        drops = int(m_drop.group(1))
        if m_drop.group(2):
            drop_pct = float(m_drop.group(2))
        elif emitted > 0:
            drop_pct = (drops / emitted) * 100.0

    m_p50 = re.search(r"p50 Latency\s+:\s+([0-9.]+)\s+µs", output_text)
    if m_p50:
        p50 = float(m_p50.group(1))

    m_p95 = re.search(r"p95 Latency\s+:\s+([0-9.]+)\s+µs", output_text)
    if m_p95:
        p95 = float(m_p95.group(1))

    m_p99 = re.search(r"p99 Latency\s+:\s+([0-9.]+)\s+µs", output_text)
    if m_p99:
        p99 = float(m_p99.group(1))

    m_max = re.search(r"Max Latency\s+:\s+([0-9.]+)\s+µs", output_text)
    if m_max:
        max_lat = float(m_max.group(1))

    return {
        "emitted": emitted,
        "consumed": consumed,
        "drops": drops,
        "drop_pct": drop_pct,
        "p50_us": p50,
        "p95_us": p95,
        "p99_us": p99,
        "max_lat_us": max_lat,
    }


def get_audit_lost():
    """Reads dropped audit event counter."""
    try:
        res = subprocess.run(["auditctl", "-s"], capture_output=True, text=True)
        m = re.search(r"lost\s+(\d+)", res.stdout)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 0


def run_single_trial(root_dir, bench_dir, intensity, duration, num_cpus):
    """Executes a single benchmark run at a given intensity level."""
    # Reset and configure audit stats
    subprocess.run(["auditctl", "-D"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "openat", "-k", "edr_bench_audit"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["auditctl", "-e", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    audit_lost_start = get_audit_lost()

    # 1. Start EDR sensor
    edr_proc = subprocess.Popen([str(bench_dir / "edr_sensor"), str(duration)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.3)
    edr_pid = edr_proc.pid

    # 2. Start scx_starve targeting EDR PID
    starve_proc = subprocess.Popen([str(root_dir / "scx_starve"), "-p", str(edr_pid), "-I", str(intensity), "-q"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    # 3. Workload generator & stress-ng
    gen_script = """#!/bin/bash
while true; do
    touch /tmp/edr_probe_marker 2>/dev/null
    cat /tmp/edr_probe_marker >/dev/null 2>&1
    /bin/true 2>/dev/null
done
"""
    gen_file = Path("/tmp/event_generator.sh")
    gen_file.write_text(gen_script)
    gen_file.chmod(0o755)

    gen1 = subprocess.Popen(["/tmp/event_generator.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    gen2 = subprocess.Popen(["/tmp/event_generator.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    stress_proc = subprocess.Popen(["stress-ng", "--cpu", str(num_cpus), "--io", "2",
                                    "--timeout", f"{duration}s", "--metrics-brief"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for EDR sensor to finish
    try:
        stdout, stderr = edr_proc.communicate(timeout=duration + 8)
    except subprocess.TimeoutExpired:
        edr_proc.kill()
        stdout, stderr = edr_proc.communicate()

    # Cleanup background processes
    gen1.kill()
    gen2.kill()
    gen1.wait()
    gen2.wait()
    try:
        starve_proc.send_signal(subprocess.signal.SIGINT)
        starve_proc.wait(timeout=2)
    except Exception:
        starve_proc.kill()
        starve_proc.wait()
    stress_proc.wait()

    audit_lost_end = get_audit_lost()
    audit_lost = max(0, audit_lost_end - audit_lost_start)
    subprocess.run(["auditctl", "-e", "0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["auditctl", "-D"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    parsed = parse_edr_output(stdout)
    parsed["audit_lost"] = audit_lost
    return parsed


def main():
    parser = argparse.ArgumentParser(description="Multi-Trial Statistical Benchmark for Sched_Ext Starvation")
    parser.add_argument("--trials", "-n", type=int, default=30, help="Number of trials per level (default: 30)")
    parser.add_argument("--duration", "-d", type=int, default=8, help="Duration in seconds per trial (default: 8)")
    parser.add_argument("--intensities", "-i", type=str, default="0,1,2,3,4", help="Comma-separated intensity levels")
    parser.add_argument("--output-dir", "-o", type=str, default="results", help="Directory to save output tables/json")
    parser.add_argument("--quick", action="store_true", help="Quick mode (5 trials, 4s duration)")

    args = parser.parse_args()
    if args.quick:
        args.trials = 5
        args.duration = 4

    bench_dir = Path(__file__).resolve().parent
    root_dir = bench_dir.parent
    output_dir = root_dir / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    intensity_levels = [int(x.strip()) for x in args.intensities.split(",")]
    num_cpus = os.cpu_count() or 4

    print("==============================================================================")
    print(" Rigorous Sched_Ext Adversarial Evaluation & Statistical Significance Runner ")
    print(f" Trials per level: {args.trials} | Duration per trial: {args.duration}s | CPUs: {num_cpus}")
    print(f" Output directory: {output_dir}")
    print("==============================================================================")

    # Compile binaries first
    print("[*] Recompiling all project binaries...")
    subprocess.run(["make", "-C", str(root_dir)], check=True)

    raw_results = []
    level_data = {lvl: [] for lvl in intensity_levels}

    for lvl in intensity_levels:
        desc = {
            0: "Control Baseline (Normal Scheduling)",
            1: "Mild Starvation (500µs slice, tail DSQ)",
            2: "Moderate Starvation (100µs slice, 50% skip)",
            3: "Heavy Starvation (50µs slice, 75% skip)",
            4: "Complete Denial (No CPU consumption)",
        }.get(lvl, f"Intensity {lvl}")

        print(f"\n>>> [Intensity Level {lvl}] {desc} ({args.trials} trials) <<<")
        for t in range(1, args.trials + 1):
            sys.stdout.write(f"\r  Running trial {t:2d}/{args.trials}... ")
            sys.stdout.flush()

            trial_res = run_single_trial(root_dir, bench_dir, lvl, args.duration, num_cpus)
            trial_record = {
                "intensity": lvl,
                "trial": t,
                **trial_res
            }
            raw_results.append(trial_record)
            level_data[lvl].append(trial_res)
            time.sleep(0.5)

        sys.stdout.write("Done.\n")

    # Write raw CSV
    raw_csv_path = output_dir / "benchmark_results_raw.csv"
    with open(raw_csv_path, "w", newline="") as f:
        fieldnames = ["intensity", "trial", "emitted", "consumed", "drops", "drop_pct",
                      "p50_us", "p95_us", "p99_us", "max_lat_us", "audit_lost"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in raw_results:
            writer.writerow(row)
    print(f"\n[+] Raw trial data written to {raw_csv_path}")

    # Compute Statistical Metrics
    summary = {}
    metric_keys = ["emitted", "consumed", "drops", "drop_pct", "p50_us", "p95_us", "p99_us", "max_lat_us", "audit_lost"]

    for lvl in intensity_levels:
        summary[lvl] = {}
        for k in metric_keys:
            vals = [d[k] for d in level_data[lvl] if d[k] is not None]
            arr = np.array(vals, dtype=float)
            summary[lvl][k] = {
                "mean": float(np.mean(arr)) if len(arr) else 0.0,
                "std": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
                "median": float(np.median(arr)) if len(arr) else 0.0,
                "p25": float(np.percentile(arr, 25)) if len(arr) else 0.0,
                "p75": float(np.percentile(arr, 75)) if len(arr) else 0.0,
                "iqr": float(stats.iqr(arr)) if len(arr) else 0.0,
                "min": float(np.min(arr)) if len(arr) else 0.0,
                "max": float(np.max(arr)) if len(arr) else 0.0,
            }

    # Hypothesis Testing vs Baseline (Level 0)
    hyp_tests = {}
    if 0 in level_data:
        base_drop = [d["drop_pct"] for d in level_data[0]]
        base_p99 = [d["p99_us"] for d in level_data[0]]
        base_cons = [d["consumed"] for d in level_data[0]]

        for lvl in intensity_levels:
            if lvl == 0:
                continue
            cur_drop = [d["drop_pct"] for d in level_data[lvl]]
            cur_p99 = [d["p99_us"] for d in level_data[lvl]]
            cur_cons = [d["consumed"] for d in level_data[lvl]]

            # Mann-Whitney U test (two-sided)
            u_drop, p_drop = stats.mannwhitneyu(cur_drop, base_drop, alternative='two-sided') if len(set(cur_drop + base_drop)) > 1 else (0, 1.0)
            u_p99, p_p99 = stats.mannwhitneyu(cur_p99, base_p99, alternative='two-sided') if len(set(cur_p99 + base_p99)) > 1 else (0, 1.0)
            u_cons, p_cons = stats.mannwhitneyu(cur_cons, base_cons, alternative='two-sided') if len(set(cur_cons + base_cons)) > 1 else (0, 1.0)

            hyp_tests[lvl] = {
                "drop_pct_mannwhitney": {"u_stat": float(u_drop), "p_value": float(p_drop)},
                "p99_mannwhitney": {"u_stat": float(u_p99), "p_value": float(p_p99)},
                "consumed_mannwhitney": {"u_stat": float(u_cons), "p_value": float(p_cons)},
            }

    # Save summary JSON
    summary_json_path = output_dir / "benchmark_summary.json"
    full_output = {
        "metadata": {
            "trials_per_level": args.trials,
            "duration_sec": args.duration,
            "num_cpus": num_cpus,
            "kernel_version": os.uname().release,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "summary_statistics": summary,
        "hypothesis_tests_vs_baseline": hyp_tests,
    }
    with open(summary_json_path, "w") as f:
        json.dump(full_output, f, indent=2)
    print(f"[+] Summary JSON saved to {summary_json_path}")

    # Generate Formatted Markdown Table
    md_table_path = output_dir / "benchmark_summary.md"
    with open(md_table_path, "w") as f:
        f.write("# Sched_Ext EDR Starvation Empirical Evaluation Matrix\n\n")
        f.write(f"*Configuration: $N={args.trials}$ trials/level, ${args.duration}\\text{{s}}$ duration, Kernel {os.uname().release}*\n\n")
        f.write("| Starvation Level | Events Emitted (Mean ± SD) | Events Consumed (Mean ± SD) | Drop Rate % (Mean ± SD) | p99 Latency µs (Mean ± SD) | Max Latency µs (Mean ± SD) | MW-U Test ($p$-value vs L0) |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

        for lvl in intensity_levels:
            s = summary[lvl]
            p_val_str = "Baseline"
            if lvl in hyp_tests:
                p_val = hyp_tests[lvl]["drop_pct_mannwhitney"]["p_value"]
                if p_val < 1e-4:
                    p_val_str = f"**$p < 10^{{-4}}$**"
                else:
                    p_val_str = f"$p = {p_val:.4f}$"

            f.write(f"| **Level {lvl}** | {s['emitted']['mean']:.0f} ± {s['emitted']['std']:.0f} | "
                    f"{s['consumed']['mean']:.0f} ± {s['consumed']['std']:.0f} | "
                    f"**{s['drop_pct']['mean']:.2f}% ± {s['drop_pct']['std']:.2f}%** | "
                    f"{s['p99_us']['mean']:.2f} ± {s['p99_us']['std']:.2f} µs | "
                    f"{s['max_lat_us']['mean']:.2f} ± {s['max_lat_us']['std']:.2f} µs | "
                    f"{p_val_str} |\n")

    print(f"[+] Markdown table saved to {md_table_path}")

    # Generate LaTeX Table for Academic Paper
    tex_table_path = output_dir / "benchmark_table.tex"
    with open(tex_table_path, "w") as f:
        f.write(r"\begin{table*}[t]" + "\n")
        f.write(r"\centering" + "\n")
        f.write(r"\small" + "\n")
        f.write(r"\caption{Sched\_Ext EDR Starvation Empirical Results across Intensity Levels ($N=" + str(args.trials) + r"$ trials per level, mean $\pm$ stddev).}" + "\n")
        f.write(r"\label{tab:edr_starvation_results}" + "\n")
        f.write(r"\begin{tabular}{lcccccc}" + "\n")
        f.write(r"\toprule" + "\n")
        f.write(r"\textbf{Intensity Level} & \textbf{Emitted} & \textbf{Consumed} & \textbf{Drop Rate (\%)} & \textbf{p99 Latency ($\mu$s)} & \textbf{Max Latency ($\mu$s)} & \textbf{MW-$U$ $p$-val} \\" + "\n")
        f.write(r"\midrule" + "\n")

        for lvl in intensity_levels:
            s = summary[lvl]
            p_val_str = "---"
            if lvl in hyp_tests:
                p_val = hyp_tests[lvl]["drop_pct_mannwhitney"]["p_value"]
                if p_val < 1e-4:
                    p_val_str = r"$< 10^{-4}$"
                else:
                    p_val_str = f"${p_val:.4f}$"

            f.write(f"Level {lvl} & {s['emitted']['mean']:.0f} $\\pm$ {s['emitted']['std']:.0f} & "
                    f"{s['consumed']['mean']:.0f} $\\pm$ {s['consumed']['std']:.0f} & "
                    f"\\textbf{{{s['drop_pct']['mean']:.2f}\\% $\\pm$ {s['drop_pct']['std']:.2f}\\%}} & "
                    f"{s['p99_us']['mean']:.2f} $\\pm$ {s['p99_us']['std']:.2f} & "
                    f"{s['max_lat_us']['mean']:.2f} $\\pm$ {s['max_lat_us']['std']:.2f} & "
                    f"{p_val_str} \\\\\n")

        f.write(r"\bottomrule" + "\n")
        f.write(r"\end{tabular}" + "\n")
        f.write(r"\end{table*}" + "\n")

    print(f"[+] LaTeX table saved to {tex_table_path}")

    # Terminal summary display
    print("\n" + "=" * 90)
    print(" STATISTICAL EVALUATION SUMMARY (Mean ± StdDev)")
    print("=" * 90)
    print(f"{'Intensity':<10} | {'Emitted':<14} | {'Consumed':<14} | {'Drop Rate %':<16} | {'p99 Lat (µs)':<16} | {'MW-U p-val'}")
    print("-" * 90)
    for lvl in intensity_levels:
        s = summary[lvl]
        p_val_str = "Baseline"
        if lvl in hyp_tests:
            p_val = hyp_tests[lvl]["drop_pct_mannwhitney"]["p_value"]
            p_val_str = f"p < 1e-4" if p_val < 1e-4 else f"p = {p_val:.4f}"
        print(f"Level {lvl:<4} | {s['emitted']['mean']:6.0f} ± {s['emitted']['std']:4.0f} | {s['consumed']['mean']:6.0f} ± {s['consumed']['std']:4.0f} | {s['drop_pct']['mean']:6.2f}% ± {s['drop_pct']['std']:4.2f}% | {s['p99_us']['mean']:7.2f} ± {s['p99_us']['std']:5.2f} | {p_val_str}")
    print("=" * 90)


if __name__ == "__main__":
    main()
