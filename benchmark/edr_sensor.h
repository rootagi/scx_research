#ifndef __EDR_SENSOR_H
#define __EDR_SENSOR_H

#if !defined(__bpf__) && !defined(__KERNEL__)
#include <linux/types.h>
#include <stdint.h>
#endif

struct edr_event {
    __u64 ktime_ns;        /* Kernel timestamp at event generation */
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    char  comm[16];
    char  filename[64];
    __u32 event_type;      /* 1 = EXEC, 2 = OPEN_SENSITIVE, 3 = PTRACE */
};

#endif /* __EDR_SENSOR_H */
