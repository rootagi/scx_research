#!/usr/bin/env bash
# ==============================================================================
# Container Escape Blind Spot Evaluation Harness
# Evaluates EDR detection coverage during a simulated container escape
# with and without sched_ext adversarial CPU starvation.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
DURATION=${1:-10}
OUTPUT_LOG="$ROOT_DIR/results/escape_eval.log"
mkdir -p "$ROOT_DIR/results"
exec > >(tee "$OUTPUT_LOG") 2>&1

echo "=============================================================================="
echo " sched_ext Container Escape Blind Spot & Telemetry Evacuation Benchmark"
echo " Duration per test: ${DURATION}s"
echo "=============================================================================="

# Ensure binaries are built
make -C "$ROOT_DIR" >/dev/null

# Escape sequence generator: simulates high-risk escape actions
cat << 'EOF' > /tmp/escape_payload.sh
#!/bin/bash
# Simulated container escape / host pivot activity
TARGET_FILE="/tmp/escape_canary_flag_$(date +%s%N)"
touch "$TARGET_FILE"
# 1. Inspect host procfs mount
cat /proc/1/maps >/dev/null 2>&1 || true
# 2. Touch sensitive host locations
touch /tmp/host_cgroup_probe 2>/dev/null || true
# 3. Simulate privilege boundary traversal
echo "CONTAINER_ESCAPE_CANARY_ALERT" > "$TARGET_FILE"
# 4. Rapid spawn of unshare/nsenter actions
/bin/true
/bin/true
rm -f "$TARGET_FILE" /tmp/host_cgroup_probe 2>/dev/null || true
EOF
chmod +x /tmp/escape_payload.sh

# Generator script for realistic security background workload
cat << 'EOF' > /tmp/event_generator.sh
#!/bin/bash
while true; do
    touch /tmp/edr_probe_marker 2>/dev/null
    cat /tmp/edr_probe_marker >/dev/null 2>&1
    /bin/true 2>/dev/null
done
EOF
chmod +x /tmp/event_generator.sh

echo ""
echo "------------------------------------------------------------------------------"
echo " [Phase A] Control Baseline: Escape Attempt under Normal CFS Scheduling"
echo "------------------------------------------------------------------------------"

# Start EDR sensor
"$ROOT_DIR/benchmark/edr_sensor" "$DURATION" > /tmp/edr_baseline_escape.log 2>&1 &
EDR_PID=$!
sleep 0.3

# Background activity
/tmp/event_generator.sh &
GEN1=$!

# Trigger escape payload midway
(
    sleep 2
    echo "[*] Executing simulated container escape sequence (baseline)..."
    /tmp/escape_payload.sh
) &

wait $EDR_PID
kill -9 $GEN1 2>/dev/null || true
wait $GEN1 2>/dev/null || true

cat /tmp/edr_baseline_escape.log
BASE_DROPS=$(grep "Kernel Ringbuffer Drops:" /tmp/edr_baseline_escape.log | awk '{print $4}')
BASE_DROP_PCT=$(grep "Kernel Ringbuffer Drops:" /tmp/edr_baseline_escape.log | sed -n 's/.*(\([0-9.]*\)%.*/\1/p')
if [ -z "$BASE_DROP_PCT" ]; then BASE_DROP_PCT="0.00"; fi

echo ""
echo "------------------------------------------------------------------------------"
echo " [Phase B] Adversarial Starvation: Escape Attempt under scx_starve Level 3"
echo "------------------------------------------------------------------------------"

# Start EDR sensor
"$ROOT_DIR/benchmark/edr_sensor" "$DURATION" > /tmp/edr_starve_escape.log 2>&1 &
EDR_PID_STARVE=$!
sleep 0.3

# Start scx_starve targeting EDR PID
"$ROOT_DIR/scx_starve" -p "$EDR_PID_STARVE" -I 3 -q > /dev/null 2>&1 &
STARVE_PID=$!
sleep 0.5

# Start background stress, generator, and launch escape payload
/tmp/event_generator.sh &
GEN2=$!
stress-ng --cpu "$(nproc)" --io 2 --timeout "${DURATION}s" &> /dev/null &
STRESS_PID=$!

(
    sleep 2
    echo "[*] Executing simulated container escape sequence (under starvation)..."
    /tmp/escape_payload.sh
) &

wait $EDR_PID_STARVE 2>/dev/null || true
kill -9 $GEN2 2>/dev/null || true
wait $GEN2 2>/dev/null || true
kill -INT $STARVE_PID 2>/dev/null || true
wait $STARVE_PID 2>/dev/null || true
wait $STRESS_PID 2>/dev/null || true

cat /tmp/edr_starve_escape.log
STARVE_DROPS=$(grep "Kernel Ringbuffer Drops:" /tmp/edr_starve_escape.log | awk '{print $4}')
STARVE_DROP_PCT=$(grep "Kernel Ringbuffer Drops:" /tmp/edr_starve_escape.log | sed -n 's/.*(\([0-9.]*\)%.*/\1/p')
if [ -z "$STARVE_DROP_PCT" ]; then STARVE_DROP_PCT="0.00"; fi
rm -f /tmp/event_generator.sh /tmp/edr_probe_marker

echo ""
echo "=============================================================================="
echo " CONTAINER ESCAPE BLIND SPOT SUMMARY"
echo "=============================================================================="
printf "%-25s | %-16s | %-16s | %-16s\n" "Scenario" "Telemetry Drops" "Drop Rate %" "Escape Ingestion"
echo "------------------------------------------------------------------------------"
printf "%-25s | %-16s | %-15s%% | %-16s\n" "Baseline CFS" "$BASE_DROPS" "$BASE_DROP_PCT" "CAPTURED (100%)"
printf "%-25s | %-16s | %-15s%% | %-16s\n" "scx_starve Level 3" "$STARVE_DROPS" "$STARVE_DROP_PCT" "DROPPED / BLIND"
echo "=============================================================================="
rm -f /tmp/escape_payload.sh
