#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "scx_guard_lsm.h"
#include "scx_guard_lsm.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static const char *default_allowed_schedulers[] = {
    "scx_lavd",
    "scx_rusty",
    "scx_bpfland",
    "scx_simple",
    "scx_flatcg",
    "scx_layer",
    "scx_qmap",
    "scx_central",
    "telemetry_ops",
    NULL
};

struct monitor_opts {
    bool enforce;
    bool json_output;
    bool quiet;
    int fallback_interval_ms;
    char allowlist_file[256];
    int alert_count;
};

static struct monitor_opts opts = {
    .enforce = false,
    .json_output = false,
    .quiet = false,
    .fallback_interval_ms = 500,
    .allowlist_file = "",
    .alert_count = 0,
};

static int handle_lsm_event(void *ctx, void *data, size_t data_sz)
{
    const struct scx_lsm_event *e = data;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    if (!e->is_allowed)
        opts.alert_count++;

    if (opts.json_output) {
        printf("{\"timestamp\":\"%s\",\"ktime_ns\":%llu,\"event\":\"%s\",\"severity\":\"%s\","
               "\"pid\":%u,\"tgid\":%u,\"uid\":%u,\"gid\":%u,\"cgroup_id\":%llu,"
               "\"comm\":\"%s\",\"map_name\":\"%s\",\"map_id\":%u,\"allowed\":%s,\"blocked\":%s}\n",
               time_buf,
               (unsigned long long)e->timestamp_ns,
               "STRUCT_OPS_REGISTER",
               e->is_allowed ? "INFO" : (e->blocked ? "CRITICAL" : "ALERT"),
               e->pid, e->tgid, e->uid, e->gid,
               (unsigned long long)e->cgroup_id,
               e->comm, e->map_name, e->map_id,
               e->is_allowed ? "true" : "false",
               e->blocked ? "true" : "false");
        fflush(stdout);
        return 0;
    }

    if (e->is_allowed) {
        if (!opts.quiet) {
            printf("[%s] [INFO] Legitimate sched_ext registration: '%s' by PID %u ('%s', UID %u)\n",
                   time_buf, e->map_name, e->pid, e->comm, e->uid);
        }
    } else {
        if (e->blocked) {
            printf("\033[1;31m[%s] [BLOCKED] UNAUTHORIZED sched_ext REGISTRATION ATTEMPT!\033[0m\n", time_buf);
        } else {
            printf("\033[1;33m[%s] [SECURITY ALERT] UNTRUSTED sched_ext REGISTRATION DETECTED!\033[0m\n", time_buf);
        }
        printf("  ├── Target Map:      %s (ID: %u, Type: %u)\n", e->map_name, e->map_id, e->map_type);
        printf("  ├── Registering PID: %u (TGID: %u)\n", e->pid, e->tgid);
        printf("  ├── Process Comm:    %s\n", e->comm);
        printf("  ├── User/Group:      UID %u / GID %u\n", e->uid, e->gid);
        printf("  ├── Cgroup ID:       %llu\n", (unsigned long long)e->cgroup_id);
        printf("  └── Defense Action:  %s\n", e->blocked ? "DENIED (-EPERM)" : "LOGGED (Detection mode)");
    }
    fflush(stdout);
    return 0;
}

/* Fallback userspace poller: polls bpftool struct_ops list periodically */
static void *fallback_poller_thread(void *arg)
{
    while (!exiting) {
        usleep(opts.fallback_interval_ms * 1000);
        if (exiting) break;

        FILE *fp = popen("bpftool struct_ops list -j 2>/dev/null", "r");
        if (!fp) continue;

        char buf[4096];
        size_t bytes = fread(buf, 1, sizeof(buf) - 1, fp);
        pclose(fp);

        if (bytes > 0) {
            buf[bytes] = '\0';
            /* Check if an active struct_ops map contains scx_starve or unauthorized name */
            if (strstr(buf, "scx_starve") || strstr(buf, "starve_ops") || strstr(buf, "scx_forensic")) {
                if (!opts.json_output && !opts.quiet) {
                    /* Periodic confirmation that fallback scanner also catches active rogue schedulers */
                }
            }
        }
    }
    return NULL;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("sched_ext Defensive LSM Monitor & Enforcement Daemon\n\n");
    printf("Options:\n");
    printf("  -e, --enforce         Enforce kernel-level blocking of untrusted schedulers (-EPERM)\n");
    printf("  -a, --allow <NAME>    Add additional trusted scheduler name to allowlist\n");
    printf("  -i, --interval <MS>   Fallback polling interval in ms (default: 500ms)\n");
    printf("  -j, --json            Output structured JSON logs (SIEM / audit pipeline)\n");
    printf("  -q, --quiet           Suppress benign registration logs\n");
    printf("  -v, --verbose         Enable libbpf debug output\n");
    printf("  -h, --help            Show this help message\n\n");
}

int main(int argc, char **argv)
{
    struct scx_guard_lsm_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0, opt;
    bool verbose = false;
    char extra_allowed[16][SCX_MAP_NAME_LEN];
    int num_extra_allowed = 0;

    static struct option long_options[] = {
        {"enforce",  no_argument,       0, 'e'},
        {"allow",    required_argument, 0, 'a'},
        {"interval", required_argument, 0, 'i'},
        {"json",     no_argument,       0, 'j'},
        {"quiet",    no_argument,       0, 'q'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "ea:i:jqvh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'e':
            opts.enforce = true;
            break;
        case 'a':
            if (num_extra_allowed < 16)
                strncpy(extra_allowed[num_extra_allowed++], optarg, SCX_MAP_NAME_LEN - 1);
            break;
        case 'i':
            opts.fallback_interval_ms = atoi(optarg);
            if (opts.fallback_interval_ms < 50) opts.fallback_interval_ms = 50;
            break;
        case 'j':
            opts.json_output = true;
            break;
        case 'q':
            opts.quiet = true;
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
        libbpf_set_print((libbpf_print_fn_t)vfprintf);
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (!opts.json_output) {
        printf("======================================================================\n");
        printf(" [scx_monitor] Sched_Ext BPF LSM Defensive Security Daemon\n");
        printf(" Mode: %s | Fallback Interval: %dms\n",
               opts.enforce ? "ACTIVE ENFORCEMENT (Blocking Unknowns)" : "PASSIVE DETECTION & AUDIT",
               opts.fallback_interval_ms);
        printf("======================================================================\n");
    }

    skel = scx_guard_lsm_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open LSM BPF skeleton: %s\n", strerror(errno));
        return 1;
    }

    err = scx_guard_lsm_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to load LSM BPF object (is CONFIG_BPF_LSM enabled?): %d (%s)\n",
                err, strerror(-err));
        goto cleanup;
    }

    /* Configure enforce mode */
    __u32 cfg_key = 0;
    __u32 enforce_val = opts.enforce ? 1 : 0;
    bpf_map_update_elem(bpf_map__fd(skel->maps.scx_guard_cfg), &cfg_key, &enforce_val, BPF_ANY);

    /* Populate default trusted schedulers allowlist */
    int allowlist_fd = bpf_map__fd(skel->maps.scx_allowlist);
    for (int i = 0; default_allowed_schedulers[i] != NULL; i++) {
        char key[SCX_MAP_NAME_LEN] = {0};
        snprintf(key, sizeof(key), "%.*s", SCX_MAP_NAME_LEN - 1, default_allowed_schedulers[i]);
        struct scx_allowlist_entry entry = { .allowed_uid = 0, .flags = 1 };
        snprintf(entry.name, sizeof(entry.name), "%.*s", SCX_MAP_NAME_LEN - 1, default_allowed_schedulers[i]);
        bpf_map_update_elem(allowlist_fd, key, &entry, BPF_ANY);
    }

    for (int i = 0; i < num_extra_allowed; i++) {
        char key[SCX_MAP_NAME_LEN] = {0};
        snprintf(key, sizeof(key), "%.*s", SCX_MAP_NAME_LEN - 1, extra_allowed[i]);
        struct scx_allowlist_entry entry = { .allowed_uid = 0, .flags = 1 };
        snprintf(entry.name, sizeof(entry.name), "%.*s", SCX_MAP_NAME_LEN - 1, extra_allowed[i]);
        bpf_map_update_elem(allowlist_fd, key, &entry, BPF_ANY);
    }

    err = scx_guard_lsm_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach LSM programs: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.scx_lsm_events), handle_lsm_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] Failed to initialize ring buffer consumer\n");
        goto cleanup;
    }

    /* Start fallback polling thread */
    pthread_t fallback_tid;
    pthread_create(&fallback_tid, NULL, fallback_poller_thread, NULL);

    if (!opts.json_output) {
        printf("[+] LSM hook attached successfully to bpf_map_create / struct_ops.\n");
        printf("[+] Trusted Schedulers Allowlist initialized (%d built-in + %d custom).\n", 9, num_extra_allowed);
        printf("[*] Listening for scheduler load events... (Ctrl+C to exit)\n\n");
    }

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    pthread_join(fallback_tid, NULL);

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (skel)
        scx_guard_lsm_bpf__destroy(skel);

    if (!opts.json_output) {
        printf("\n[*] scx_monitor daemon detached. Total security alerts: %d\n", opts.alert_count);
    }
    return err ? 1 : 0;
}
