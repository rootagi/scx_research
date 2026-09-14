#!/usr/bin/env bash
# ==============================================================================
# Telemetry Latency & Scheduling Evaluation Benchmark
# ==============================================================================

set -e

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$BENCH_DIR")"
DURATION=${1:-15}
NUM_CPUS=$(nproc)

echo "======================================================================"
echo " sched_ext Telemetry Latency & Queue Isolation Benchmark"
echo " Cores: $NUM_CPUS | Duration per test: ${DURATION}s"
echo "======================================================================"

# Ensure root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please run benchmark as root."
    exit 1
fi

# Ensure stress-ng is installed
if ! command -v stress-ng &> /dev/null; then
    echo "[-] Installing stress-ng..."
    pacman -Sy --noconfirm stress-ng
fi

# 1. Compile project binaries if needed
echo "[*] Building scx_telemetry..."
make -C "$ROOT_DIR"

# 2. Helper synthetic telemetry workload
cat << 'EOF' > /tmp/telemetry_emitter.py
import time
import os
import sys

interval_ms = 5  # Emit every 5ms
iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
latencies = []

print(f"[Emitter] Started on PID {os.getpid()}, target {iterations} cycles...")
for _ in range(iterations):
    t_start = time.perf_counter_ns()
    time.sleep(interval_ms / 1000.0)
    t_actual = time.perf_counter_ns()
    # Jitter / scheduling delay beyond intended sleep duration
    jitter_us = ((t_actual - t_start) - (interval_ms * 1_000_000)) / 1000.0
    latencies.append(max(0.0, jitter_us))

latencies.sort()
p50 = latencies[int(len(latencies) * 0.50)]
p95 = latencies[int(len(latencies) * 0.95)]
p99 = latencies[int(len(latencies) * 0.99)]
max_lat = latencies[-1]

print(f"\n--- Results for PID {os.getpid()} ---")
print(f"p50 Wakeup Jitter : {p50:8.2f} µs")
print(f"p95 Wakeup Jitter : {p95:8.2f} µs")
print(f"p99 Wakeup Jitter : {p99:8.2f} µs")
print(f"Max Wakeup Jitter : {max_lat:8.2f} µs")
EOF

echo ""
echo "======================================================================"
echo " [Test 1/2] Baseline: Default Kernel Scheduler under CPU Saturation"
echo "======================================================================"
# Start synthetic telemetry emitter in background
python3 /tmp/telemetry_emitter.py $((DURATION * 200)) > /tmp/baseline_emitter.log 2>&1 &
EMITTER_PID=$!
sleep 0.5

# Generate heavy background CPU and I/O contention
echo "[*] Injecting background contention: $NUM_CPUS CPU stressors + 2 I/O stressors..."
stress-ng --cpu $NUM_CPUS --io 2 --timeout "${DURATION}s" --metrics-brief &> /tmp/stress_baseline.log

wait $EMITTER_PID
cat /tmp/baseline_emitter.log

echo ""
echo "======================================================================"
echo " [Test 2/2] scx_telemetry: Dual-DSQ Isolated Priority Scheduling"
echo "======================================================================"

# Start synthetic telemetry emitter
python3 /tmp/telemetry_emitter.py $((DURATION * 200)) > /tmp/scx_emitter.log 2>&1 &
SCX_EMITTER_PID=$!
sleep 0.5

# Start scx_telemetry with PID targeted for DSQ_TELEMETRY
echo "[*] Attaching scx_telemetry with PID $SCX_EMITTER_PID assigned to DSQ_TELEMETRY..."
"$ROOT_DIR/scx_telemetry" -p $SCX_EMITTER_PID -s 20 > /tmp/scx_telemetry.log 2>&1 &
SCHED_PID=$!
sleep 1

# Apply identical background contention
echo "[*] Injecting identical contention: $NUM_CPUS CPU stressors + 2 I/O stressors..."
stress-ng --cpu $NUM_CPUS --io 2 --timeout "${DURATION}s" --metrics-brief &> /tmp/stress_scx.log

wait $SCX_EMITTER_PID

# Stop scheduler gracefully
kill -INT $SCHED_PID 2>/dev/null || true
wait $SCHED_PID 2>/dev/null || true

cat /tmp/scx_emitter.log

echo ""
echo "======================================================================"
echo " Comparative Summary: Scheduling Jitter / Wakeup Latency"
echo "======================================================================"
echo -e "Metric\t\t\tDefault Scheduler\t\tscx_telemetry (Dual DSQ)"
echo "----------------------------------------------------------------------"
p50_base=$(grep "p50" /tmp/baseline_emitter.log | awk '{print $5, $6}')
p95_base=$(grep "p95" /tmp/baseline_emitter.log | awk '{print $5, $6}')
p99_base=$(grep "p99" /tmp/baseline_emitter.log | awk '{print $5, $6}')
max_base=$(grep "Max" /tmp/baseline_emitter.log | awk '{print $5, $6}')

p50_scx=$(grep "p50" /tmp/scx_emitter.log | awk '{print $5, $6}')
p95_scx=$(grep "p95" /tmp/scx_emitter.log | awk '{print $5, $6}')
p99_scx=$(grep "p99" /tmp/scx_emitter.log | awk '{print $5, $6}')
max_scx=$(grep "Max" /tmp/scx_emitter.log | awk '{print $5, $6}')

echo -e "p50 Latency Jitter\t$p50_base\t\t\t$p50_scx"
echo -e "p95 Latency Jitter\t$p95_base\t\t\t$p95_scx"
echo -e "p99 Latency Jitter\t$p99_base\t\t\t$p99_scx"
echo -e "Max Latency Jitter\t$max_base\t\t\t$max_scx"
echo "======================================================================"
echo "[+] Benchmark completed successfully."
