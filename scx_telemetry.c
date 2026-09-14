#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "scx_telemetry.h"
#include "scx_telemetry.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0; /* Suppress verbose debug output by default */
    return vfprintf(stderr, format, args);
}

/* Helper to find PID by process name in /proc */
static int find_pids_by_name(const char *target_name, __u32 *pids, int max_pids)
{
    DIR *dir = opendir("/proc");
    if (!dir)
        return -1;

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL && count < max_pids) {
        if (!isdigit(entry->d_name[0]))
            continue;

        __u32 pid = (__u32)atoi(entry->d_name);
        char comm_path[256];
        snprintf(comm_path, sizeof(comm_path), "/proc/%u/comm", pid);

        FILE *f = fopen(comm_path, "r");
        if (!f)
            continue;

        char comm[TASK_COMM_LEN];
        if (fgets(comm, sizeof(comm), f)) {
            /* Strip newline */
            size_t len = strlen(comm);
            if (len > 0 && comm[len - 1] == '\n')
                comm[len - 1] = '\0';

            if (strcmp(comm, target_name) == 0) {
                pids[count++] = pid;
            }
        }
        fclose(f);
    }
    closedir(dir);
    return count;
}

/* Helper to get comm string for a given PID */
static void get_pid_comm(__u32 pid, char *comm, size_t max_len)
{
    char comm_path[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/%u/comm", pid);

    FILE *f = fopen(comm_path, "r");
    if (!f) {
        snprintf(comm, max_len, "unknown");
        return;
    }

    if (fgets(comm, max_len, f)) {
        size_t len = strlen(comm);
        if (len > 0 && comm[len - 1] == '\n')
            comm[len - 1] = '\0';
    } else {
        snprintf(comm, max_len, "unknown");
    }
    fclose(f);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("sched_ext Dual-DSQ Telemetry Prioritization Scheduler\n\n");
    printf("Options:\n");
    printf("  -p, --pid <PID>         Add specific PID to prioritized Telemetry DSQ\n");
    printf("  -n, --name <NAME>       Auto-discover and add process by name (e.g. auditd, falco)\n");
    printf("  -s, --slice <MS>        Custom time slice for telemetry tasks in ms (default: 20)\n");
    printf("  -i, --interval <SEC>    Dashboard refresh interval in seconds (default: 1)\n");
    printf("  -v, --verbose           Enable libbpf debug output\n");
    printf("  -h, --help              Show this help message\n\n");
}

int main(int argc, char **argv)
{
    struct scx_telemetry_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int err = 0;
    int opt;
    bool verbose = false;
    __u32 initial_pids[MAX_TARGET_PIDS];
    int num_initial_pids = 0;
    char target_proc_name[TASK_COMM_LEN] = {0};
    __u64 custom_slice_ms = 20;
    int refresh_interval = 1;

    static struct option long_options[] = {
        {"pid",      required_argument, 0, 'p'},
        {"name",     required_argument, 0, 'n'},
        {"slice",    required_argument, 0, 's'},
        {"interval", required_argument, 0, 'i'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:n:s:i:vh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'p':
            if (num_initial_pids < MAX_TARGET_PIDS) {
                initial_pids[num_initial_pids++] = (__u32)atoi(optarg);
            }
            break;
        case 'n':
            strncpy(target_proc_name, optarg, TASK_COMM_LEN - 1);
            break;
        case 's':
            custom_slice_ms = (__u64)strtoull(optarg, NULL, 10);
            break;
        case 'i':
            refresh_interval = atoi(optarg);
            if (refresh_interval < 1)
                refresh_interval = 1;
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 0;
        }
    }

    if (verbose)
        libbpf_set_print(libbpf_print_fn);

    /* Signal handlers for clean shutdown */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=========================================================\n");
    printf(" [scx_telemetry] Initializing sched_ext BPF Control Plane\n");
    printf("=========================================================\n");

    /* 1. Open and load BPF skeleton */
    skel = scx_telemetry_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open BPF skeleton: %s\n", strerror(errno));
        return 1;
    }

    err = scx_telemetry_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to load BPF object: %d (%s)\n", err, strerror(-err));
        fprintf(stderr, "    Ensure CONFIG_SCHED_CLASS_EXT=y is enabled and kernel supports struct_ops.\n");
        goto cleanup;
    }

    int target_pids_fd = bpf_map__fd(skel->maps.target_pids);
    int stats_fd = bpf_map__fd(skel->maps.stats_map);

    /* 2. Resolve process name if requested */
    if (target_proc_name[0] != '\0') {
        __u32 discovered_pids[64];
        int discovered_count = find_pids_by_name(target_proc_name, discovered_pids, 64);
        if (discovered_count > 0) {
            printf("[+] Auto-discovered %d instance(s) of '%s':\n", discovered_count, target_proc_name);
            for (int i = 0; i < discovered_count; i++) {
                printf("    -> PID %u\n", discovered_pids[i]);
                if (num_initial_pids < MAX_TARGET_PIDS)
                    initial_pids[num_initial_pids++] = discovered_pids[i];
            }
        } else {
            printf("[!] Warning: No running process matched '%s'. Will register if PID appears later.\n", target_proc_name);
        }
    }

    /* 3. Populate initial target PIDs into BPF map */
    __u64 custom_slice_ns = custom_slice_ms * 1000ULL * 1000ULL;
    for (int i = 0; i < num_initial_pids; i++) {
        struct task_config cfg = {
            .priority = 1,
            .custom_slice_ns = custom_slice_ns,
        };
        get_pid_comm(initial_pids[i], cfg.comm, sizeof(cfg.comm));

        err = bpf_map_update_elem(target_pids_fd, &initial_pids[i], &cfg, BPF_ANY);
        if (err) {
            fprintf(stderr, "[-] Failed to add PID %u to target map: %s\n", initial_pids[i], strerror(errno));
        } else {
            printf("[+] Target Configured: PID %u ('%s') -> DSQ_TELEMETRY (Slice: %llu ms)\n",
                   initial_pids[i], cfg.comm, (unsigned long long)custom_slice_ms);
        }
    }

    /* 4. Attach struct_ops to register scheduler */
    link = bpf_map__attach_struct_ops(skel->maps.telemetry_ops);
    if (!link) {
        fprintf(stderr, "[-] Failed to attach sched_ext struct_ops: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("[+] Scheduler 'scx_telemetry' registered successfully!\n");
    printf("[*] Priority Queue (DSQ %llu) active. Standard Queue (DSQ %llu) active.\n",
           DSQ_TELEMETRY, DSQ_NORMAL);
    printf("[*] Entering monitoring loop (Ctrl+C to safely detach)...\n\n");

    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0)
        num_cpus = get_nprocs_conf();

    struct sched_telemetry_stats *percpu_stats = calloc(num_cpus, sizeof(struct sched_telemetry_stats));
    if (!percpu_stats) {
        fprintf(stderr, "[-] Failed to allocate stats buffer\n");
        goto cleanup;
    }

    struct sched_telemetry_stats prev_total = {0};
    __u32 stats_key = 0;

    /* 5. Live Telemetry Dashboard Loop */
    while (!exiting) {
        sleep(refresh_interval);

        /* Periodically scan for new instances if target_proc_name is specified */
        if (target_proc_name[0] != '\0') {
            __u32 cur_pids[64];
            int cur_count = find_pids_by_name(target_proc_name, cur_pids, 64);
            for (int i = 0; i < cur_count; i++) {
                struct task_config cfg;
                if (bpf_map_lookup_elem(target_pids_fd, &cur_pids[i], &cfg) != 0) {
                    /* New PID discovered */
                    cfg.priority = 1;
                    cfg.custom_slice_ns = custom_slice_ns;
                    get_pid_comm(cur_pids[i], cfg.comm, sizeof(cfg.comm));
                    bpf_map_update_elem(target_pids_fd, &cur_pids[i], &cfg, BPF_ANY);
                    printf("\n[+] Dynamically attached new '%s' instance (PID: %u)\n", cfg.comm, cur_pids[i]);
                }
            }
        }

        /* Read per-CPU statistics */
        if (bpf_map_lookup_elem(stats_fd, &stats_key, percpu_stats) == 0) {
            struct sched_telemetry_stats cur_total = {0};
            for (int i = 0; i < num_cpus; i++) {
                cur_total.nr_enqueued_telemetry += percpu_stats[i].nr_enqueued_telemetry;
                cur_total.nr_enqueued_normal += percpu_stats[i].nr_enqueued_normal;
                cur_total.nr_consumed_telemetry += percpu_stats[i].nr_consumed_telemetry;
                cur_total.nr_consumed_normal += percpu_stats[i].nr_consumed_normal;
            }

            __u64 delta_enq_tele = cur_total.nr_enqueued_telemetry - prev_total.nr_enqueued_telemetry;
            __u64 delta_enq_norm = cur_total.nr_enqueued_normal - prev_total.nr_enqueued_normal;
            __u64 delta_con_tele = cur_total.nr_consumed_telemetry - prev_total.nr_consumed_telemetry;
            __u64 delta_con_norm = cur_total.nr_consumed_normal - prev_total.nr_consumed_normal;

            time_t now = time(NULL);
            struct tm *t = localtime(&now);

            printf("\033[H\033[J"); /* Clear screen */
            printf("========================================================================================\n");
            printf("  scx_telemetry Dashboard | %02d:%02d:%02d | Target Slices: Tele=%llums Norm=%llums\n",
                   t->tm_hour, t->tm_min, t->tm_sec,
                   (unsigned long long)custom_slice_ms, (unsigned long long)(SLICE_NORMAL_NS / 1000000));
            printf("========================================================================================\n");
            printf("%-18s | %-14s | %-14s | %-14s | %-14s\n", "Queue", "Enq Rate", "Cons Rate", "Total Enqueued", "Total Consumed");
            printf("----------------------------------------------------------------------------------------\n");
            printf("DSQ_TELEMETRY (Hi) | %10llu/s | %10llu/s | %14llu | %14llu\n",
                   (unsigned long long)(delta_enq_tele / refresh_interval),
                   (unsigned long long)(delta_con_tele / refresh_interval),
                   (unsigned long long)cur_total.nr_enqueued_telemetry,
                   (unsigned long long)cur_total.nr_consumed_telemetry);
            printf("DSQ_NORMAL    (Lo) | %10llu/s | %10llu/s | %14llu | %14llu\n",
                   (unsigned long long)(delta_enq_norm / refresh_interval),
                   (unsigned long long)(delta_con_norm / refresh_interval),
                   (unsigned long long)cur_total.nr_enqueued_normal,
                   (unsigned long long)cur_total.nr_consumed_normal);
            printf("========================================================================================\n");
            printf(" Active Monitored Priority PIDs:\n");

            /* Iterate and list currently registered priority PIDs */
            __u32 cur_key = 0, next_key = 0;
            int listed = 0;
            while (bpf_map_get_next_key(target_pids_fd, &cur_key, &next_key) == 0) {
                struct task_config cfg;
                if (bpf_map_lookup_elem(target_pids_fd, &next_key, &cfg) == 0 && cfg.priority > 0) {
                    printf("   [%d] PID: %-6u | Comm: %-16s | Slice: %llu ms\n",
                           ++listed, next_key, cfg.comm, (unsigned long long)(cfg.custom_slice_ns / 1000000ULL));
                }
                cur_key = next_key;
            }
            if (listed == 0)
                printf("   (No specific PIDs registered; all tasks routing through DSQ_NORMAL)\n");

            printf("========================================================================================\n");
            printf(" Press [Ctrl+C] to safely unregister scheduler and restore kernel CFS.\n");
            fflush(stdout);

            prev_total = cur_total;
        }
    }

    free(percpu_stats);

cleanup:
    printf("\n[*] Cleaning up and unregistering scx_telemetry...\n");
    if (link)
        bpf_link__destroy(link);
    if (skel)
        scx_telemetry_bpf__destroy(skel);

    printf("[+] Reverted to default Linux scheduler cleanly.\n");
    return err ? 1 : 0;
}
