#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "edr_sensor.h"
#include "edr_sensor.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

#define MAX_SAMPLES 100000
static double latencies_us[MAX_SAMPLES];
static int sample_count = 0;
static __u64 total_consumed = 0;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct edr_event *e = data;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    __u64 now_ns = (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;

    double lat_us = (double)(now_ns - e->ktime_ns) / 1000.0;
    if (lat_us < 0)
        lat_us = 0;

    if (sample_count < MAX_SAMPLES)
        latencies_us[sample_count++] = lat_us;

    total_consumed++;
    return 0;
}

static int compare_doubles(const void *a, const void *b)
{
    double arg1 = *(const double *)a;
    double arg2 = *(const double *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    struct edr_sensor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;
    int duration = (argc > 1) ? atoi(argv[1]) : 10;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[*] Starting EDR Sensor Daemon (PID: %d)...\n", getpid());

    skel = edr_sensor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open and load EDR sensor BPF object\n");
        return 1;
    }

    err = edr_sensor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach EDR sensor BPF tracepoints\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events_rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] Failed to create ring buffer reader\n");
        goto cleanup;
    }

    printf("[+] EDR Sensor active, consuming ringbuffer for %d seconds...\n", duration);
    struct timespec start_ts, cur_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    while (!exiting) {
        clock_gettime(CLOCK_MONOTONIC, &cur_ts);
        double elapsed = (double)(cur_ts.tv_sec - start_ts.tv_sec) +
                         (double)(cur_ts.tv_nsec - start_ts.tv_nsec) / 1e9;
        if (elapsed >= (double)duration)
            break;
        /* Poll with 10ms timeout */
        ring_buffer__poll(rb, 10);
    }

    /* Drain remaining */
    ring_buffer__consume(rb);

    /* Read kernel-side drop counters */
    __u32 key_total = 0, key_drop = 1;
    __u64 k_total = 0, k_drop = 0;
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters_map), &key_total, &k_total);
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters_map), &key_drop, &k_drop);

    printf("\n=======================================================\n");
    printf(" EDR Security Sensor Ingestion & Telemetry Summary\n");
    printf("=======================================================\n");
    printf(" Total Events Emitted in Kernel: %llu\n", (unsigned long long)k_total);
    printf(" Total Events Consumed Userspace: %llu\n", (unsigned long long)total_consumed);
    printf(" Kernel Ringbuffer Drops:        %llu", (unsigned long long)k_drop);
    if (k_total > 0) {
        double drop_pct = 100.0 * (double)k_drop / (double)k_total;
        printf(" (%.2f%% drop rate)\n", drop_pct);
    } else {
        printf("\n");
    }

    if (sample_count > 0) {
        qsort(latencies_us, sample_count, sizeof(double), compare_doubles);
        double p50 = latencies_us[(int)(sample_count * 0.50)];
        double p95 = latencies_us[(int)(sample_count * 0.95)];
        double p99 = latencies_us[(int)(sample_count * 0.99)];
        double max_lat = latencies_us[sample_count - 1];

        printf("-------------------------------------------------------\n");
        printf(" Telemetry Ingestion Latency (Kernel -> Userspace):\n");
        printf("   p50 Latency : %10.2f µs\n", p50);
        printf("   p95 Latency : %10.2f µs\n", p95);
        printf("   p99 Latency : %10.2f µs\n", p99);
        printf("   Max Latency : %10.2f µs\n", max_lat);
    }
    printf("=======================================================\n");

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (skel)
        edr_sensor_bpf__destroy(skel);
    return err ? 1 : 0;
}
