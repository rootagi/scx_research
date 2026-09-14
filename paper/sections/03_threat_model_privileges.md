# Threat Model & Privilege Prerequisite Analysis

## 1. Prerequisite Capabilities for `sched_ext` Exploitation

Loading a custom BPF scheduler (`struct sched_ext_ops`) via `bpf(BPF_MAP_CREATE, ...)` and `bpf(BPF_LINK_CREATE, ...)` requires specific Linux capabilities:

1. **`CAP_BPF`**: Required to load BPF programs and create BPF maps.
2. **`CAP_PERFMON`**: Required for tracing and struct_ops programs that hook into core kernel subsystems.
3. **Root in Initial User Namespace (`init_user_ns`)**: In standard Linux distributions, `CAP_BPF` and `CAP_SYS_ADMIN` in unprivileged user namespaces (`user_namespaces(7)`) do *not* permit loading kernel-wide scheduler classes.

Reviewers legitimately ask: *“If the attacker already has `CAP_BPF` or root, aren't they already in complete control of the system?”*

This section formally addresses this question by examining:
- The distinction between **system control** and **stealthy telemetry suppression**.
- **Four realistic operational attack vectors** through which an adversary obtains `sched_ext` loading capabilities without full kernel memory corruption.

---

## 2. Why `sched_ext` Over Direct Kernel Tampering?

Traditional root-level attacks against EDRs (e.g., terminating the daemon, killing probes with `SIGKILL`, or patching syscall tables) produce high-visibility alerts:
- Terminating `/usr/bin/falco` or `osqueryd` triggers a service heartbeat failure alert in the SOC within seconds.
- Modifying `/dev/kmem` or kernel text triggers `Kernel Integrity Monitoring (KIM)` or hardware hypervisor alerts.
- BPF LSM / kprobe detaches generate explicit `bpf_prog_detach` audit events.

In contrast, **`sched_ext` exploitation uses an intended, fully upstreamed kernel feature**:
- The EDR process continues running; no signals (`SIGKILL`, `SIGSTOP`) are delivered.
- Heartbeats continue arriving at the SIEM (just delayed or sparse), preventing automated failover alerts.
- The kernel ring buffer silently drops security events in the kernel fast-path before userspace ever receives them.

---

## 3. Realistic Attacker Ingress Vectors

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ATTACKER INGRESS VECTORS                             │
└────┬─────────────────────────┬─────────────────────────┬────────────────┘
     │                         │                         │
     ▼                         ▼                         ▼
┌──────────────┐        ┌──────────────┐        ┌──────────────────┐
│  Vector 1:   │        │  Vector 2:   │        │    Vector 3:     │
│  Privileged  │        │  Capability  │        │   SUID / Helper  │
│  Container   │        │  Delegation  │        │     Exploit      │
│  (Docker/K8s)│        │ (systemd/BPF)│        │  (Local PrivEsc) │
└──────┬───────┘        └──────┬───────┘        └────────┬─────────┘
       │                       │                         │
       └───────────────────────┼─────────────────────────┘
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │   CAP_BPF + CAP_PERFMON Acquired     │
            │   in Host Initial Namespace          │
            └──────────────────┬───────────────────┘
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │   Load Adversarial 'scx_starve'      │
            │   -> EDR Blind Window Exploited      │
            └──────────────────────────────────────┘
```

### Vector 1: Privileged Containers & Node DaemonSets
In modern Kubernetes clusters, monitoring, networking (e.g., Cilium, Calico), and storage DaemonSets are routinely granted `privileged: true` or `CAP_SYS_ADMIN` + `CAP_BPF`. A compromise of a single containerized pod with these capabilities allows the adversary to interact with the host kernel's `bpf()` syscall directly, loading `scx_starve` to blind node-level host EDRs.

### Vector 2: Capability-Delegated Microservices
Modern infrastructure architectures split monolithic root into fine-grained capabilities. Daemons managing observability, eBPF telemetry, or network routing are assigned `ambient` capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`). Exploitation of a vulnerability (such as an RCE or memory corruption) in these unprivileged daemons immediately provides the adversary with the exact capabilities required for `sched_ext` manipulation without requiring traditional root escalation.

### Vector 3: Local Privilege Escalation (LPE) & SUID Exploits
In standard enterprise threat models, post-exploitation begins as an unprivileged user (`www-data` or employee workstation). Attackers chain unprivileged LPEs (e.g., dirty pipe, overlayfs vulnerabilities, misconfigured SUID binaries) to elevate to a privileged context. Once achieved, the attacker's immediate priority is evading detection by the resident EDR before launching payload stages (lateral movement, ransomware encryption, or exfiltration). `scx_starve` serves as the evasion mechanism that blinds the EDR while the main payload executes.

---

## 4. Summary

`sched_ext` adversarial scheduling is not an initial exploit vector; it is a **post-compromise evasion primitive** that transforms standard root/capability access into complete telemetry blindness without triggering EDR health alerts or kernel integrity tripwires.
