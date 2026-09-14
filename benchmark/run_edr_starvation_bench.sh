#!/usr/bin/env bash
# ==============================================================================
# EDR CPU Starvation & Ringbuffer Drop Evaluation Benchmark
# ==============================================================================

set -e

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$BENCH_DIR")"
ROUND_SEC=${1:-8}
NUM_CPUS=$(nproc)

echo "=============================================================================="
echo " sched_ext Offensive Primitive Evaluation: EDR CPU Starvation & Telemetry Drop"
echo " Cores: $NUM_CPUS | Duration per intensity test: ${ROUND_SEC}s"
echo "=============================================================================="

# Build everything
echo "[*] Compiling binaries..."
make -C "$ROOT_DIR"

OUTPUT_RESULTS="/tmp/starvation_benchmark_results.txt"
rm -f "$OUTPUT_RESULTS"
touch "$OUTPUT_RESULTS"

# Generator script for generating realistic security workload
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
echo "=== Running Multi-Intensity Evaluation (0 to 4) ==="

for INTENSITY in 0 1 2 3 4; do
    echo ""
    echo "------------------------------------------------------------------------------"
    echo " [Test: Intensity Level $INTENSITY]"
    case $INTENSITY in
        0) echo " Description: Control Baseline (Normal scheduling)" ;;
        1) echo " Description: Mild Starvation (500µs slice, last-priority DSQ)" ;;
        2) echo " Description: Moderate Starvation (100µs slice, 50% dispatch skip)" ;;
        3) echo " Description: Heavy Starvation (50µs slice, 75% dispatch skip)" ;;
        4) echo " Description: Complete Denial (No CPU consumption)" ;;
    esac
    echo "------------------------------------------------------------------------------"

    # Reset audit stats
    auditctl -D >/dev/null 2>&1 || true
    auditctl -a always,exit -F arch=b64 -S openat -k edr_bench_audit >/dev/null 2>&1 || true

    # 1. Start EDR sensor
    "$BENCH_DIR/edr_sensor" "$ROUND_SEC" > "/tmp/edr_out_${INTENSITY}.log" 2>&1 &
    EDR_PID=$!
    sleep 0.3

    # 2. Start scx_starve targeting EDR_PID
    if [ "$INTENSITY" -eq 0 ]; then
        "$ROOT_DIR/scx_starve" -p "$EDR_PID" -I 0 -q > "/tmp/starve_${INTENSITY}.log" 2>&1 &
    else
        "$ROOT_DIR/scx_starve" -p "$EDR_PID" -I "$INTENSITY" -q > "/tmp/starve_${INTENSITY}.log" 2>&1 &
    fi
    STARVE_PID=$!
    sleep 0.5

    # 3. Start background event generators and stress-ng contention
    /tmp/event_generator.sh &
    GEN1=$!
    /tmp/event_generator.sh &
    GEN2=$!
    stress-ng --cpu "$NUM_CPUS" --io 2 --timeout "${ROUND_SEC}s" --metrics-brief &> /dev/null &
    STRESS_PID=$!

    # Wait for EDR sensor duration to complete
    wait $EDR_PID 2>/dev/null || true

    # Clean up generators and scheduler
    kill -9 $GEN1 $GEN2 2>/dev/null || true
    wait $GEN1 $GEN2 2>/dev/null || true
    kill -INT $STARVE_PID 2>/dev/null || true
    wait $STARVE_PID 2>/dev/null || true
    wait $STRESS_PID 2>/dev/null || true

    # Collect audit dropped events
    AUDIT_LOST=$(auditctl -s 2>/dev/null | grep 'lost' | awk '{print $2}')
    if [ -z "$AUDIT_LOST" ]; then AUDIT_LOST=0; fi

    cat "/tmp/edr_out_${INTENSITY}.log"
    echo " Audit Subsystem Lost Events: $AUDIT_LOST"
done

echo ""
echo "=============================================================================="
echo " FINAL QUANTITATIVE MATRIX: sched_ext EDR Starvation Impact"
echo "=============================================================================="
printf "%-12s | %-12s | %-12s | %-12s | %-12s | %-12s\n" \
       "Intensity" "Events Emitted" "Consumed" "Drop Rate %" "p99 Lat (µs)" "Max Lat (µs)"
echo "------------------------------------------------------------------------------"

for INTENSITY in 0 1 2 3 4; do
    LOG="/tmp/edr_out_${INTENSITY}.log"
    EMITTED=$(grep "Total Events Emitted in Kernel:" "$LOG" | awk '{print $6}')
    CONSUMED=$(grep "Total Events Consumed Userspace:" "$LOG" | awk '{print $5}')
    DROP_PCT=$(grep "Kernel Ringbuffer Drops:" "$LOG" | grep -o '([0-9.]*%)' | tr -d '()%')
    P99=$(grep "p99 Latency :" "$LOG" | awk '{print $4}')
    MAX_LAT=$(grep "Max Latency :" "$LOG" | awk '{print $4}')

    if [ -z "$EMITTED" ]; then EMITTED="N/A"; fi
    if [ -z "$CONSUMED" ]; then CONSUMED="0"; fi
    if [ -z "$DROP_PCT" ]; then DROP_PCT="0.00"; fi
    if [ -z "$P99" ]; then P99="N/A"; fi
    if [ -z "$MAX_LAT" ]; then MAX_LAT="N/A"; fi

    printf "Level %-6d | %-14s | %-12s | %10s%% | %-12s | %-12s\n" \
           "$INTENSITY" "$EMITTED" "$CONSUMED" "$DROP_PCT" "$P99" "$MAX_LAT"
done
echo "=============================================================================="
echo "[+] Offensive research benchmark completed successfully."
