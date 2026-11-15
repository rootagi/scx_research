/*
 * High-precision monotonic C canary generator for EDR starvation benchmarking.
 * Generates periodic file-access canaries monitored by Falco and Tetragon,
 * logging ground-truth event timestamps and sequence numbers.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static inline uint64_t get_time_ns(clockid_t clk_id)
{
    struct timespec ts;
    clock_gettime(clk_id, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char *argv[])
{
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <duration_sec> <interval_ms> <gt_log_path> <prefix>\n", argv[0]);
        return 1;
    }

    int duration_sec = atoi(argv[1]);
    int interval_ms = atoi(argv[2]);
    const char *gt_log_path = argv[3];
    const char *prefix = argv[4];

    if (duration_sec <= 0 || interval_ms <= 0) {
        fprintf(stderr, "Invalid duration (%d) or interval (%d)\n", duration_sec, interval_ms);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    mkdir("/tmp/scx_canary", 0777);

    FILE *gt_fp = fopen(gt_log_path, "w");
    if (!gt_fp) {
        perror("fopen gt_log");
        return 1;
    }

    uint64_t interval_ns = (uint64_t)interval_ms * 1000000ULL;
    uint64_t start_mono = get_time_ns(CLOCK_MONOTONIC);
    uint64_t end_mono = start_mono + (uint64_t)duration_sec * 1000000000ULL;
    uint64_t next_mono = start_mono;

    uint64_t seq = 0;
    char filepath[512];

    while (!g_stop && get_time_ns(CLOCK_MONOTONIC) < end_mono) {
        snprintf(filepath, sizeof(filepath), "/tmp/scx_canary/%s_%lu.dat", prefix, (unsigned long)seq);

        uint64_t ts_real = get_time_ns(CLOCK_REALTIME);

        int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            const char msg[] = "CANARY_PAYLOAD\n";
            (void)write(fd, msg, sizeof(msg) - 1);
            close(fd);
        }

        fprintf(gt_fp, "%llu %lu %s\n", (unsigned long long)ts_real, (unsigned long)seq, filepath);
        fflush(gt_fp);

        seq++;

        next_mono += interval_ns;
        uint64_t now_mono = get_time_ns(CLOCK_MONOTONIC);
        if (next_mono > now_mono) {
            struct timespec req;
            uint64_t diff = next_mono - now_mono;
            req.tv_sec = diff / 1000000000ULL;
            req.tv_nsec = diff % 1000000000ULL;
            clock_nanosleep(CLOCK_MONOTONIC, 0, &req, NULL);
        } else {
            /* Behind schedule, catch up next target */
            next_mono = now_mono;
        }
    }

    fclose(gt_fp);
    return 0;
}
