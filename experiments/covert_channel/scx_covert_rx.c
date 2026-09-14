#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sched.h>

static inline uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <num_bits_to_read> <slot_duration_ms> <start_time_ms> [cpu_core]\n", argv[0]);
        return 1;
    }

    int total_bits = atoi(argv[1]);
    uint64_t slot_ns = (uint64_t)atoi(argv[2]) * 1000000ULL;
    uint64_t start_time_ns = (uint64_t)strtoull(argv[3], NULL, 10) * 1000000ULL;
    int target_cpu = (argc > 4) ? atoi(argv[4]) : 0;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(target_cpu, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);

    char *received = malloc(total_bits + 1);
    if (!received) return 1;
    received[total_bits] = '\0';

    double *metric = malloc(total_bits * sizeof(double));

    /* Synchronize start with nanosecond precision */
    struct timespec start_req;
    start_req.tv_sec = (time_t)(start_time_ns / 1000000000ULL);
    start_req.tv_nsec = (long)(start_time_ns % 1000000000ULL);
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &start_req, NULL);

    for (int i = 0; i < total_bits; i++) {
        uint64_t slot_start_ns = start_time_ns + (i * slot_ns);
        uint64_t slot_end_ns = slot_start_ns + slot_ns;
        uint64_t sample_start_ns = slot_start_ns + (slot_ns * 10 / 100);
        uint64_t sample_end_ns = slot_start_ns + (slot_ns * 80 / 100);

        struct timespec s_req;
        s_req.tv_sec = (time_t)(sample_start_ns / 1000000000ULL);
        s_req.tv_nsec = (long)(sample_start_ns % 1000000000ULL);
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &s_req, NULL);

        volatile uint64_t ops = 0;
        while (get_time_ns() < sample_end_ns) {
            ops++;
        }
        metric[i] = (double)ops;

        struct timespec e_req;
        e_req.tv_sec = (time_t)(slot_end_ns / 1000000000ULL);
        e_req.tv_nsec = (long)(slot_end_ns % 1000000000ULL);
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &e_req, NULL);
    }

    /* Calibrate threshold using preamble: 10101011 (indices 0,2,4,6,7 are '1', indices 1,3,5 are '0') */
    double avg_1 = 0.0, avg_0 = 0.0;
    if (total_bits >= 8) {
        avg_1 = (metric[0] + metric[2] + metric[4] + metric[6] + metric[7]) / 5.0;
        avg_0 = (metric[1] + metric[3] + metric[5]) / 3.0;
    } else {
        avg_1 = metric[0];
        avg_0 = metric[1];
    }
    double threshold = (avg_1 + avg_0) / 2.0;

    for (int i = 0; i < total_bits; i++) {
        received[i] = (metric[i] < threshold) ? '1' : '0';
    }

    printf("Received Bitstream: %s\n", received);

    free(metric);
    free(received);
    return 0;
}
