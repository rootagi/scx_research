#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "scx_starve.h"
#include "scx_forensic_delay.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct scx_forensic_delay_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int err = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("===============================================================\n");
    printf(" [scx_forensic] Autonomous Forensic Throttling Scheduler\n");
    printf(" Automatically throttles: strace, gdb, perf, bpftool, ausearch\n");
    printf("===============================================================\n");

    skel = scx_forensic_delay_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to load scx_forensic_delay BPF\n");
        return 1;
    }

    link = bpf_map__attach_struct_ops(skel->maps.forensic_ops);
    if (!link) {
        fprintf(stderr, "[-] Failed to attach struct_ops\n");
        goto cleanup;
    }

    printf("[+] Autonomous forensic throttling active!\n");
    printf("[*] Try running: strace /bin/ls or perf stat ls\n");

    int stats_fd = bpf_map__fd(skel->maps.forensic_stats);
    while (!exiting) {
        sleep(1);
        __u32 k0 = 0, k1 = 1;
        __u64 normal_cnt = 0, forensic_cnt = 0;
        bpf_map_lookup_elem(stats_fd, &k0, &normal_cnt);
        bpf_map_lookup_elem(stats_fd, &k1, &forensic_cnt);
        printf("\r[*] Normal Enqueues: %llu | Forensic Tools Throttled: %llu",
               (unsigned long long)normal_cnt, (unsigned long long)forensic_cnt);
        fflush(stdout);
    }
    printf("\n");

cleanup:
    if (link) bpf_link__destroy(link);
    if (skel) scx_forensic_delay_bpf__destroy(skel);
    printf("[+] Cleanly reverted scheduler.\n");
    return err ? 1 : 0;
}
