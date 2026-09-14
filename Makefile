CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
CC ?= gcc
PYTHON ?= python3

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I./benchmark -I./defenses
CFLAGS := -Wall -O2 -I. -I./benchmark -I./defenses
LDFLAGS := -lbpf -lelf -lz -lpthread

.PHONY: all clean check-env eval eval-quick eval-full eval-covert eval-escape figures

all: scx_telemetry scx_starve \
     benchmark/edr_sensor benchmark/scx_forensic_delay benchmark/latency_probe.bpf.o \
     defenses/scx_monitor \
     experiments/covert_channel/scx_covert_tx experiments/covert_channel/scx_covert_rx

# ==== Preflight Environment Check ====
check-env:
	@bash benchmark/eval_env_check.sh

# ==== scx_telemetry (prioritization scheduler) ====
scx_telemetry.bpf.o: scx_telemetry.bpf.c scx_telemetry.h vmlinux.h
	@echo "===> [telemetry] Compiling BPF object"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

scx_telemetry.skel.h: scx_telemetry.bpf.o
	@echo "===> [telemetry] Generating skeleton"
	$(BPFTOOL) gen skeleton $< > $@

scx_telemetry: scx_telemetry.c scx_telemetry.skel.h scx_telemetry.h
	@echo "===> [telemetry] Compiling userspace binary"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# ==== scx_starve (adversarial starvation scheduler) ====
scx_starve.bpf.o: scx_starve.bpf.c scx_starve.h vmlinux.h
	@echo "===> [starve] Compiling BPF object"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

scx_starve.skel.h: scx_starve.bpf.o
	@echo "===> [starve] Generating skeleton"
	$(BPFTOOL) gen skeleton $< > $@

scx_starve: scx_starve.c scx_starve.skel.h scx_starve.h
	@echo "===> [starve] Compiling userspace binary"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# ==== EDR Sensor & Benchmark Probes ====
benchmark/edr_sensor.bpf.o: benchmark/edr_sensor.bpf.c benchmark/edr_sensor.h vmlinux.h
	@echo "===> [edr_sensor] Compiling BPF object"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

benchmark/edr_sensor.skel.h: benchmark/edr_sensor.bpf.o
	@echo "===> [edr_sensor] Generating skeleton"
	$(BPFTOOL) gen skeleton $< > $@

benchmark/edr_sensor: benchmark/edr_sensor.c benchmark/edr_sensor.skel.h benchmark/edr_sensor.h
	@echo "===> [edr_sensor] Compiling userspace binary"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# ==== Autonomous Forensic Tool Delay ====
benchmark/scx_forensic_delay.bpf.o: benchmark/scx_forensic_delay.bpf.c scx_starve.h vmlinux.h
	@echo "===> [forensic_delay] Compiling BPF object"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

benchmark/scx_forensic_delay.skel.h: benchmark/scx_forensic_delay.bpf.o
	@echo "===> [forensic_delay] Generating skeleton"
	$(BPFTOOL) gen skeleton $< > $@

benchmark/scx_forensic_delay: benchmark/scx_forensic_delay.c benchmark/scx_forensic_delay.skel.h scx_starve.h
	@echo "===> [forensic_delay] Compiling userspace binary"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

benchmark/latency_probe.bpf.o: benchmark/latency_probe.bpf.c vmlinux.h
	@echo "===> [bench] Compiling latency probe"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# ==== Defensive Engineering: BPF LSM & Monitor Daemon ====
defenses/scx_guard_lsm.bpf.o: defenses/scx_guard_lsm.bpf.c defenses/scx_guard_lsm.h vmlinux.h
	@echo "===> [lsm_guard] Compiling LSM BPF object"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

defenses/scx_guard_lsm.skel.h: defenses/scx_guard_lsm.bpf.o
	@echo "===> [lsm_guard] Generating skeleton"
	$(BPFTOOL) gen skeleton $< > $@

defenses/scx_monitor: defenses/scx_monitor.c defenses/scx_guard_lsm.skel.h defenses/scx_guard_lsm.h
	@echo "===> [monitor] Compiling userspace defensive monitor daemon"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# ==== Covert Timing Channel Tools ====
experiments/covert_channel/scx_covert_tx: experiments/covert_channel/scx_covert_tx.c
	@echo "===> [covert] Compiling transmitter"
	$(CC) $(CFLAGS) $< -o $@

experiments/covert_channel/scx_covert_rx: experiments/covert_channel/scx_covert_rx.c
	@echo "===> [covert] Compiling receiver"
	$(CC) $(CFLAGS) $< -o $@

vmlinux.h:
	@if [ ! -f vmlinux.h ]; then \
		echo "===> Generating vmlinux.h from BTF..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

# ==== Artifact Evaluation Targets ====
eval-quick: all
	@echo "===> Running Quick Statistical Evaluation (Smoke Test)..."
	$(PYTHON) benchmark/run_rigorous_eval.py --quick

eval-full: all
	@echo "===> Running Full 30-Trial Rigorous Statistical Benchmark (USENIX/CCS Artifact)..."
	$(PYTHON) benchmark/run_rigorous_eval.py --trials 30 --duration 8

eval-covert: all
	@echo "===> Running Covert Timing Channel Benchmark..."
	$(PYTHON) experiments/covert_channel/run_covert_bench.py

eval-escape: all
	@echo "===> Running Container Escape Blind Spot Benchmark..."
	bash experiments/container_escape_eval/run_escape_blindspot_bench.sh 8

figures:
	@echo "===> Generating Publication Vector Figures..."
	$(PYTHON) paper/figures/generate_figures.py

eval: check-env all eval-full eval-covert eval-escape figures
	@echo ""
	@echo "======================================================================"
	@echo " [✓] Artifact Evaluation Completed Successfully!"
	@echo " Output results:  results/benchmark_summary.md"
	@echo " Figures:         paper/figures/"
	@echo " LaTeX tables:    results/benchmark_table.tex"
	@echo "======================================================================"

clean:
	@echo "===> Cleaning all artifacts..."
	rm -f scx_telemetry.bpf.o scx_telemetry.skel.h scx_telemetry
	rm -f scx_starve.bpf.o scx_starve.skel.h scx_starve
	rm -f benchmark/edr_sensor.bpf.o benchmark/edr_sensor.skel.h benchmark/edr_sensor
	rm -f benchmark/scx_forensic_delay.bpf.o benchmark/scx_forensic_delay.skel.h benchmark/scx_forensic_delay
	rm -f benchmark/latency_probe.bpf.o
	rm -f defenses/scx_guard_lsm.bpf.o defenses/scx_guard_lsm.skel.h defenses/scx_monitor
	rm -f experiments/covert_channel/scx_covert_tx experiments/covert_channel/scx_covert_rx
	rm -rf results/ /tmp/edr_out_*.log /tmp/starve_*.log /tmp/escape_*.log
