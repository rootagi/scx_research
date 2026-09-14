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
        fprintf(stderr, "Usage: %s <bitstring> <slot_duration_ms> <start_time_ms> [cpu_core]\n", argv[0]);
        return 1;
    }

    const char *payload = argv[1];
    uint64_t slot_ns = (uint64_t)atoi(argv[2]) * 1000000ULL;
    uint64_t start_time_ns = (uint64_t)strtoull(argv[3], NULL, 10) * 1000000ULL;
    int target_cpu = (argc > 4) ? atoi(argv[4]) : 0;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(target_cpu, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);

    const char *sync_seq = "10101011";
    char full_stream[1024];
    snprintf(full_stream, sizeof(full_stream), "%s%s", sync_seq, payload);
    size_t total_bits = strlen(full_stream);

    /* Wait until synchronized start */
    struct timespec start_req;
    start_req.tv_sec = (time_t)(start_time_ns / 1000000000ULL);
    start_req.tv_nsec = (long)(start_time_ns % 1000000000ULL);
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &start_req, NULL);

    for (size_t i = 0; i < total_bits; i++) {
        char bit = full_stream[i];
        uint64_t slot_start_ns = start_time_ns + (i * slot_ns);
        uint64_t slot_end_ns = slot_start_ns + slot_ns;
        uint64_t spin_end_ns = slot_start_ns + (slot_ns * 85 / 100);

        if (bit == '1') {
            volatile uint64_t count = 0;
            while (get_time_ns() < spin_end_ns) {
                count++;
            }
            (void)count;
        }

        /* Sleep out remaining slot buffer to guarantee clean boundary */
        struct timespec e_req;
        e_req.tv_sec = (time_t)(slot_end_ns / 1000000000ULL);
        e_req.tv_nsec = (long)(slot_end_ns % 1000000000ULL);
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &e_req, NULL);
    }

    return 0;
}
