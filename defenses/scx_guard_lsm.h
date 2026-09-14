#ifndef __SCX_GUARD_LSM_H
#define __SCX_GUARD_LSM_H

#if !defined(__bpf__) && !defined(__KERNEL__)
#include <linux/types.h>
#include <stdbool.h>
#endif

#define SCX_COMM_LEN 16
#define SCX_MAP_NAME_LEN 16
#define SCX_MAX_ALLOWLIST_ENTRIES 64

/* Event types emitted by the defense engine */
#define SCX_EVENT_MAP_CREATE        1
#define SCX_EVENT_MAP_UPDATE        2
#define SCX_EVENT_LINK_CREATE       3
#define SCX_EVENT_STRUCT_OPS_REG    4

/* Severity level */
#define SCX_SEV_INFO    0
#define SCX_SEV_WARN    1
#define SCX_SEV_ALERT   2
#define SCX_SEV_BLOCK   3

/*
 * Structure emitted to userspace ring buffer on sched_ext registration
 */
struct scx_lsm_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 severity;

    /* Caller credentials */
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;

    /* Task & Target metadata */
    char comm[SCX_COMM_LEN];
    char map_name[SCX_MAP_NAME_LEN];
    __u32 map_type;
    __u32 map_id;
    __u32 btf_vmlinux_value_type_id;

    /* Action taken */
    __u32 is_allowed;           /* 1 if found in allowlist, 0 if unauthorized */
    __u32 blocked;              /* 1 if blocked by LSM enforcement, 0 if passive */
};

/*
 * Allowlist entry structure for trusted schedulers
 */
struct scx_allowlist_entry {
    char name[SCX_MAP_NAME_LEN];
    __u32 allowed_uid;          /* 0 for root only, or specific UID */
    __u32 flags;
};

#endif /* __SCX_GUARD_LSM_H */
