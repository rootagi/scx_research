#!/usr/bin/env bash
# ==============================================================================
# Sched_ext Evaluation Environment Preflight Check
# Verifies kernel version, CONFIG_SCHED_CLASS_EXT, BTF, toolchain & dependencies
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}        sched_ext Security Research: Artifact Preflight Check         ${NC}"
echo -e "${BLUE}======================================================================${NC}"

ERRORS=0
WARNINGS=0

# 1. Kernel Version Check
KVER=$(uname -r)
echo -n "[*] Checking Linux kernel version ($KVER)... "
K_MAJOR=$(echo "$KVER" | cut -d. -f1)
K_MINOR=$(echo "$KVER" | cut -d. -f2)

if [ "$K_MAJOR" -gt 6 ] || { [ "$K_MAJOR" -eq 6 ] && [ "$K_MINOR" -ge 12 ]; }; then
    echo -e "${GREEN}PASS (>= 6.12 sched_ext merge)${NC}"
else
    echo -e "${RED}FAIL: Kernel $KVER does not meet minimum >= 6.12 requirement${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 2. CONFIG_SCHED_CLASS_EXT Verification
echo -n "[*] Verifying CONFIG_SCHED_CLASS_EXT=y... "
HAS_SCHED_EXT=0

if [ -f /proc/config.gz ]; then
    if zcat /proc/config.gz | grep -q "CONFIG_SCHED_CLASS_EXT=y"; then
        HAS_SCHED_EXT=1
    fi
elif [ -f "/boot/config-$KVER" ]; then
    if grep -q "CONFIG_SCHED_CLASS_EXT=y" "/boot/config-$KVER"; then
        HAS_SCHED_EXT=1
    fi
elif [ -f "/lib/modules/$KVER/build/.config" ]; then
    if grep -q "CONFIG_SCHED_CLASS_EXT=y" "/lib/modules/$KVER/build/.config"; then
        HAS_SCHED_EXT=1
    fi
elif [ -d "/sys/kernel/debug/sched_ext" ] || [ -f "/sys/kernel/btf/vmlinux" ]; then
    # Test if struct sched_ext_ops exists in BTF
    if bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -q "struct sched_ext_ops"; then
        HAS_SCHED_EXT=1
    fi
fi

if [ "$HAS_SCHED_EXT" -eq 1 ]; then
    echo -e "${GREEN}PASS (CONFIG_SCHED_CLASS_EXT is enabled)${NC}"
else
    echo -e "${RED}FAIL: CONFIG_SCHED_CLASS_EXT is not active in this kernel build${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 2b. CONFIG_BPF_LSM Verification
echo -n "[*] Verifying CONFIG_BPF_LSM=y & active LSM... "
if grep -qw "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo -e "${GREEN}PASS (bpf LSM active in /sys/kernel/security/lsm)${NC}"
elif [ -f /proc/config.gz ] && zcat /proc/config.gz | grep -q "CONFIG_BPF_LSM=y"; then
    echo -e "${GREEN}PASS (CONFIG_BPF_LSM=y)${NC}"
else
    echo -e "${RED}FAIL: bpf LSM not active${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 3. Kernel BTF Support
echo -n "[*] Verifying Kernel BTF (/sys/kernel/btf/vmlinux)... "
if [ -f "/sys/kernel/btf/vmlinux" ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL: /sys/kernel/btf/vmlinux not found (CONFIG_DEBUG_INFO_BTF required)${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 4. Toolchain Dependencies
check_tool() {
    local cmd=$1
    local name=$2
    local required=$3
    echo -n "[*] Checking dependency: $name ($cmd)... "
    if command -v "$cmd" &>/dev/null; then
        echo -e "${GREEN}PASS ($(command -v "$cmd"))${NC}"
    else
        if [ "$required" -eq 1 ]; then
            echo -e "${RED}FAIL: $name is required but not installed${NC}"
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${YELLOW}WARN: $name optional tool missing${NC}"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
}

check_tool "clang" "Clang C/BPF Compiler" 1
check_tool "bpftool" "BPF Tooling" 1
check_tool "gcc" "GNU C Compiler" 1
check_tool "make" "GNU Make" 1
check_tool "stress-ng" "Stress-ng Workload Generator" 1
check_tool "auditctl" "Linux Audit Control" 1
check_tool "python3" "Python 3 Interpreter" 1
check_tool "rsync" "Rsync Utility" 0

# 5. Python Scientific Libraries
echo -n "[*] Checking Python scipy, numpy, matplotlib... "
if python3 -c "import scipy, numpy, matplotlib; print('ok')" &>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL: Python packages (scipy, numpy, matplotlib) missing${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 6. Capabilities & Root Privileges
echo -n "[*] Checking runtime permissions... "
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}PASS (running as root / CAP_SYS_ADMIN + CAP_BPF available)${NC}"
else
    echo -e "${YELLOW}WARN: Not root. BPF struct_ops registration requires root/CAP_BPF.${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo -e "${BLUE}======================================================================${NC}"
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}[+] Preflight checks PASSED with $WARNINGS warning(s). Ready for evaluation.${NC}"
    exit 0
else
    echo -e "${RED}[-] Preflight checks FAILED with $ERRORS error(s) and $WARNINGS warning(s).${NC}"
    exit 1
fi
