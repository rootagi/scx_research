#!/usr/bin/env python3
"""
Covert Timing Channel Evaluation Benchmark
Measures cross-privilege communication bandwidth (bps) and Bit Error Rate (BER)
across different modulation slot durations with deterministic clock synchronization.
"""

import argparse
import subprocess
import time
import os
import re
from pathlib import Path


def run_covert_trial(tx_bin, rx_bin, payload, slot_ms, core=0):
    preamble = "10101011"
    full_expected = preamble + payload
    total_bits = len(full_expected)

    now_ms = int(time.monotonic() * 1000)
    start_ms = now_ms + 300

    # Start RX first
    rx_proc = subprocess.Popen(
        [str(rx_bin), str(total_bits), str(slot_ms), str(start_ms), str(core)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    # Start TX
    tx_proc = subprocess.Popen(
        [str(tx_bin), payload, str(slot_ms), str(start_ms), str(core)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    expected_duration_sec = ((total_bits * slot_ms) / 1000.0) + 2.0
    try:
        tx_out, _ = tx_proc.communicate(timeout=expected_duration_sec)
        rx_out, _ = rx_proc.communicate(timeout=expected_duration_sec)
    except subprocess.TimeoutExpired:
        tx_proc.kill()
        rx_proc.kill()
        tx_out, _ = tx_proc.communicate()
        rx_out, _ = rx_proc.communicate()

    m = re.search(r"Received Bitstream:\s+([01]+)", rx_out)
    if not m:
        return 1.0, 0.0, ""

    rx_bits = m.group(1)

    errors = 0
    comp_len = min(len(full_expected), len(rx_bits))
    for i in range(comp_len):
        if full_expected[i] != rx_bits[i]:
            errors += 1
    errors += abs(len(full_expected) - len(rx_bits))

    ber = errors / float(total_bits) if total_bits > 0 else 1.0
    bandwidth_bps = (1000.0 / slot_ms)

    return ber, bandwidth_bps, rx_bits


def main():
    parser = argparse.ArgumentParser(description="Covert Timing Channel Benchmark")
    parser.add_argument("--payload", default="1101001100101010", help="Binary payload to send")
    parser.add_argument("--slots", default="100,50,25,10", help="Comma-separated slot times in ms")
    parser.add_argument("--core", type=int, default=0, help="CPU core to evaluate on")
    args = parser.parse_args()

    dir_path = Path(__file__).resolve().parent
    tx_src = dir_path / "scx_covert_tx.c"
    rx_src = dir_path / "scx_covert_rx.c"
    tx_bin = dir_path / "scx_covert_tx"
    rx_bin = dir_path / "scx_covert_rx"

    print("======================================================================")
    print(" Sched_Ext Covert Timing Channel Empirical Evaluation")
    print(f" Test Payload: {args.payload} ({len(args.payload)} bits) | Core: {args.core}")
    print("======================================================================")

    # Compile
    print("[*] Compiling TX and RX binaries...")
    subprocess.run(["gcc", "-O2", str(tx_src), "-o", str(tx_bin)], check=True)
    subprocess.run(["gcc", "-O2", str(rx_src), "-o", str(rx_bin)], check=True)

    slots = [int(s.strip()) for s in args.slots.split(",")]

    print("\n----------------------------------------------------------------------")
    print(f"{'Slot Duration (ms)':<20} | {'Raw Bandwidth (bps)':<22} | {'Bit Error Rate (BER)':<20} | {'Status'}")
    print("----------------------------------------------------------------------")

    import csv
    results_dir = dir_path.parent.parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    raw_csv_path = results_dir / "covert_channel_raw.csv"
    summary_csv_path = results_dir / "covert_channel_results.csv"

    raw_records = []
    summary_records = []

    for slot in slots:
        bers = []
        for trial in range(3):
            ber, bps, rx_bits = run_covert_trial(tx_bin, rx_bin, args.payload, slot, core=args.core)
            bers.append(ber)
            raw_records.append({
                "slot_ms": slot,
                "trial": trial + 1,
                "bandwidth_bps": bps,
                "ber": ber,
                "ber_pct": ber * 100.0,
                "rx_bits": rx_bits
            })
            time.sleep(0.05)

        avg_ber = sum(bers) / len(bers)
        bps = 1000.0 / slot
        status = "EXCELLENT" if avg_ber == 0.0 else ("RELIABLE" if avg_ber < 0.05 else ("ACCEPTABLE" if avg_ber < 0.15 else "NOISY"))

        summary_records.append({
            "slot_ms": slot,
            "bandwidth_bps": bps,
            "avg_ber": avg_ber,
            "avg_ber_pct": avg_ber * 100.0,
            "status": status
        })

        print(f"{slot:<20} | {bps:<22.1f} | {avg_ber * 100.0:<19.2f}% | {status}")

    print("======================================================================")

    with open(raw_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["slot_ms", "trial", "bandwidth_bps", "ber", "ber_pct", "rx_bits"])
        writer.writeheader()
        writer.writerows(raw_records)
    print(f"[+] Raw covert trial data saved to: {raw_csv_path}")

    with open(summary_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["slot_ms", "bandwidth_bps", "avg_ber", "avg_ber_pct", "status"])
        writer.writeheader()
        writer.writerows(summary_records)
    print(f"[+] Covert summary results saved to: {summary_csv_path}")


if __name__ == "__main__":
    main()
