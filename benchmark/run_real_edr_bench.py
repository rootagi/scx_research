#!/usr/bin/env python3
"""
Real EDR Starvation Benchmark Harness for Falco and Tetragon.
Executes N trials per intensity level (0-4), measures real alert throughput
and event drop rate against ground-truth canary emissions.
"""

import argparse
import csv
import datetime
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

def ensure_container_running(tool):
    container_name = f"{tool}-test"
    res = subprocess.run(["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
                         capture_output=True, text=True)
    if container_name not in res.stdout:
        print(f"[*] Starting {container_name}...")
        subprocess.run(["docker", "start", container_name], check=True)
        time.sleep(4)

def get_tool_pid(tool):
    ensure_container_running(tool)
    res = subprocess.run(["pgrep", "-x", tool], capture_output=True, text=True)
    lines = res.stdout.strip().splitlines()
    if not lines or not lines[0]:
        raise RuntimeError(f"Could not find running PID for {tool}")
    return int(lines[0])

def run_single_trial(tool, intensity, trial_idx, duration, interval_ms, raw_dir):
    gt_log = raw_dir / f"trial_L{intensity}_{trial_idx:02d}_gt.log"
    alert_log = raw_dir / f"trial_L{intensity}_{trial_idx:02d}_alert.log"
    prefix = f"canary_{tool}_L{intensity}_T{trial_idx:02d}"

    # 1. Clean canary directory
    canary_dir = Path("/tmp/scx_canary")
    if canary_dir.exists():
        for f in canary_dir.glob("*.dat"):
            try: f.unlink()
            except Exception: pass
    else:
        canary_dir.mkdir(parents=True, exist_ok=True)

    # 2. Setup tool-specific logging
    pid = get_tool_pid(tool)
    start_iso = ""
    if tool == "falco":
        start_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    elif tool == "tetragon":
        with open("/tmp/tetragon_export/tetragon.log", "w") as f:
            f.truncate(0)

    # 3. Start scx_starve if intensity > 0
    starve_proc = None
    if intensity > 0:
        starve_cmd = ["/root/research/scx_starve", "-p", str(pid), "-I", str(intensity), "-q"]
        starve_proc = subprocess.Popen(starve_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)

    # 4. Start stress-ng contention
    stress_cmd = ["stress-ng", "--cpu", "4", "--io", "2", "--timeout", f"{duration}s"]
    stress_proc = subprocess.Popen(stress_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 5. Run canary generator
    canary_cmd = [
        "/root/research/benchmark/canary_gen",
        str(duration),
        str(interval_ms),
        str(gt_log),
        prefix
    ]
    gen_proc = subprocess.Popen(canary_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Wait for canary generator to complete
    try:
        gen_out, gen_err = gen_proc.communicate(timeout=duration + 5)
    except subprocess.TimeoutExpired:
        gen_proc.kill()
        gen_out, gen_err = gen_proc.communicate()

    # 6. Stop scx_starve and stress-ng
    if starve_proc:
        try:
            starve_proc.send_signal(signal.SIGINT)
            starve_proc.wait(timeout=2)
        except Exception:
            starve_proc.kill()
            starve_proc.wait()

    stress_proc.wait()
    time.sleep(2.0) # Settle I/O and flush logs

    # 7. Extract tool alerts
    if tool == "falco":
        log_res = subprocess.run(["docker", "logs", "--since", start_iso, "falco-test"],
                                 capture_output=True, text=True)
        alerts = [line for line in log_res.stdout.splitlines() if "CANARY_ALERT" in line and prefix in line]
        alert_log.write_text("\n".join(alerts) + ("\n" if alerts else ""))
    elif tool == "tetragon":
        alerts = []
        tg_log_path = Path("/tmp/tetragon_export/tetragon.log")
        if tg_log_path.exists():
            with open(tg_log_path, "r", errors="ignore") as f:
                for line in f:
                    if '"policy_name":"canary-file-open"' in line and prefix in line:
                        alerts.append(line.strip())
        alert_log.write_text("\n".join(alerts) + ("\n" if alerts else ""))

    # 8. Count emitted vs consumed
    emitted = 0
    if gt_log.exists():
        with open(gt_log, "r") as f:
            emitted = sum(1 for line in f if line.strip())

    consumed = 0
    if alert_log.exists():
        with open(alert_log, "r") as f:
            consumed = sum(1 for line in f if line.strip())

    drops = max(0, emitted - consumed)
    drop_pct = (drops / emitted * 100.0) if emitted > 0 else 0.0

    return {
        "intensity": intensity,
        "trial": trial_idx,
        "emitted": emitted,
        "consumed": consumed,
        "drops": drops,
        "drop_pct": round(drop_pct, 4)
    }

def main():
    parser = argparse.ArgumentParser(description="Real EDR Starvation Benchmark")
    parser.add_argument("--tool", choices=["falco", "tetragon"], required=True)
    parser.add_argument("--trials", "-n", type=int, default=30)
    parser.add_argument("--duration", "-d", type=int, default=8)
    parser.add_argument("--interval-ms", type=int, default=1)
    parser.add_argument("--intensities", "-i", type=str, default="0,1,2,3,4")
    parser.add_argument("--output-dir", "-o", type=str, default="/root/research/results")
    args = parser.parse_args()

    intensities = [int(x.strip()) for x in args.intensities.split(",")]
    out_dir = Path(args.output_dir)
    raw_dir = out_dir / "raw_logs" / args.tool
    raw_dir.mkdir(parents=True, exist_ok=True)

    csv_path = out_dir / f"{args.tool}_real_drop_rate.csv"

    csv_file = open(csv_path, "w", newline="")
    fieldnames = ["intensity", "trial", "emitted", "consumed", "drops", "drop_pct"]
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    csv_file.flush()

    print("=" * 80)
    print(f" Real EDR Starvation Evaluation: {args.tool.upper()}")
    print(f" Trials/Level: {args.trials} | Duration: {args.duration}s | Interval: {args.interval_ms}ms")
    print(f" Output CSV: {csv_path}")
    print(f" Raw Logs: {raw_dir}")
    print("=" * 80)

    for intensity in intensities:
        print(f"\n--- [Intensity Level {intensity}] ({args.trials} trials) ---")
        level_drops = []
        for t in range(1, args.trials + 1):
            res = run_single_trial(args.tool, intensity, t, args.duration, args.interval_ms, raw_dir)
            writer.writerow(res)
            csv_file.flush()
            level_drops.append(res["drop_pct"])
            print(f"  [{args.tool} | L{intensity} | Trial {t:02d}/{args.trials:02d}] "
                  f"Emitted: {res['emitted']:4d} | Consumed: {res['consumed']:4d} | "
                  f"Drops: {res['drops']:4d} ({res['drop_pct']:6.2f}%)")
            time.sleep(0.5)

        mean_drop = sum(level_drops) / len(level_drops) if level_drops else 0.0
        print(f">>> Level {intensity} Summary: Mean Drop Rate = {mean_drop:.2f}%")

    csv_file.close()
    print("\n" + "=" * 80)
    print(f"[+] Completed all trials for {args.tool.upper()}. Output: {csv_path}")
    print("=" * 80)

if __name__ == "__main__":
    main()
