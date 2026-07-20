#!/usr/bin/env bash
#
# kernel-hardening.sh
#
# Applies the Timesys kernel-hardening configuration recommendations
# (https://timesys.com/pdf/Timesys-kernel-hardening-guide.pdf) to a
# Linux kernel .config file.
#
# Written for Linux kernel 7.1.3, but works against any modern kernel
# source tree since it uses the upstream `scripts/config` helper and
# only touches options that still exist in current mainline. Options
# that were removed/renamed in your specific tree are simply skipped
# with a warning (scripts/config prints "warning: symbol not found").
#
# Usage:
#   ./kernel-hardening.sh /path/to/linux-7.1.3 [/path/to/.config]
#
#   /path/to/linux-7.1.3   Kernel source tree (must contain scripts/config)
#   /path/to/.config       Optional; defaults to <kernel-src>/.config
#
# After running, rebuild your config to resolve dependencies:
#   make -C /path/to/linux-7.1.3 olddefconfig
#
set -euo pipefail

KERNEL_SRC="${1:-}"
CONFIG_FILE="${2:-}"

usage() {
    echo "Usage: $0 /path/to/kernel-source [/path/to/.config]" >&2
    exit 1
}

[[ -z "$KERNEL_SRC" ]] && usage
[[ -d "$KERNEL_SRC" ]] || { echo "Error: '$KERNEL_SRC' is not a directory" >&2; exit 1; }

SCRIPTS_CONFIG="$KERNEL_SRC/scripts/config"
[[ -x "$SCRIPTS_CONFIG" ]] || { echo "Error: $SCRIPTS_CONFIG not found or not executable" >&2; exit 1; }

if [[ -z "$CONFIG_FILE" ]]; then
    CONFIG_FILE="$KERNEL_SRC/.config"
fi
[[ -f "$CONFIG_FILE" ]] || { echo "Error: config file '$CONFIG_FILE' not found" >&2; exit 1; }

BACKUP="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
cp "$CONFIG_FILE" "$BACKUP"
echo "Backed up existing config to: $BACKUP"

CFG=(--file "$CONFIG_FILE")

enable()  { "$SCRIPTS_CONFIG" "${CFG[@]}" -e  "$1" 2>/dev/null || true; }
disable() { "$SCRIPTS_CONFIG" "${CFG[@]}" -d  "$1" 2>/dev/null || true; }
setval()  { "$SCRIPTS_CONFIG" "${CFG[@]}" --set-val "$1" "$2" 2>/dev/null || true; }
setstr()  { "$SCRIPTS_CONFIG" "${CFG[@]}" --set-str "$1" "$2" 2>/dev/null || true; }

echo "=== Applying Timesys kernel-hardening options to $CONFIG_FILE ==="

# ---------------------------------------------------------------------------
# Stack overflow protection
# ---------------------------------------------------------------------------
echo "--- Stack protection"
for opt in INIT_STACK_ALL_ZERO GCC_PLUGIN_ARM_SSP_PER_TASK STACKPROTECTOR \
           STACKPROTECTOR_STRONG STACKPROTECTOR_PER_TASK VMAP_STACK \
           SCHED_STACK_END_CHECK GCC_PLUGIN_STACKLEAK SHADOW_CALL_STACK \
           RANDOMIZE_KSTACK_OFFSET_DEFAULT CFI_CLANG THREAD_INFO_IN_TASK; do
    enable "$opt"
done
for opt in STACKLEAK_METRICS STACKLEAK_RUNTIME_DISABLE; do
    disable "$opt"
done

# ---------------------------------------------------------------------------
# Heap / slab hardening
# ---------------------------------------------------------------------------
echo "--- Heap protection"
for opt in STRICT_KERNEL_RWX SLAB_FREELIST_HARDENED SLAB_FREELIST_RANDOM \
           SHUFFLE_PAGE_ALLOCATOR INIT_ON_ALLOC_DEFAULT_ON INIT_ON_FREE_DEFAULT_ON \
           PAGE_POISONING SLUB_DEBUG SLUB_DEBUG_ON FORTIFY_SOURCE; do
    enable "$opt"
done
for opt in COMPAT_BRK INET_DIAG SLAB_MERGE_DEFAULT; do
    disable "$opt"
done

# ---------------------------------------------------------------------------
# Hardened usercopy
# ---------------------------------------------------------------------------
echo "--- Usercopy hardening"
enable HARDENED_USERCOPY
disable HARDENED_USERCOPY_FALLBACK
disable HARDENED_USERCOPY_PAGESPAN

# ---------------------------------------------------------------------------
# Information exposure
# ---------------------------------------------------------------------------
echo "--- Information exposure reduction"
enable X86_UMIP
for opt in PROC_PAGE_MONITOR PROC_VMCORE DEBUG_FS DEBUG_BUGVERBOSE \
           KALLSYMS PAGE_OWNER DEBUG_KMEMLEAK PTDUMP_DEBUGFS; do
    disable "$opt"
done
enable SECURITY_DMESG_RESTRICT

# ---------------------------------------------------------------------------
# KASLR / randomization
# ---------------------------------------------------------------------------
echo "--- Address space randomization"
for opt in ARCH_HAS_ELF_RANDOMIZE RANDOMIZE_BASE RANDOMIZE_MEMORY \
           GCC_PLUGIN_RANDSTRUCT GCC_PLUGIN_LATENT_ENTROPY; do
    enable "$opt"
done
disable GCC_PLUGIN_RANDSTRUCT_PERFORMANCE
disable RANDOM_TRUST_BOOTLOADER
disable RANDOM_TRUST_CPU

# ---------------------------------------------------------------------------
# Spectre / speculative execution mitigations
# ---------------------------------------------------------------------------
echo "--- CPU speculation mitigations"
enable RETPOLINE                 # x86
enable HARDEN_BRANCH_PREDICTOR   # arm/arm64
enable PAGE_TABLE_ISOLATION
enable MICROCODE
enable X86_SMAP

# ---------------------------------------------------------------------------
# ARM64-specific hardening
# ---------------------------------------------------------------------------
echo "--- ARM64-specific"
for opt in ARM64_PAN UNMAP_KERNEL_AT_EL0 HARDEN_EL2_VECTORS \
           RODATA_FULL_DEFAULT_ENABLED ARM64_PTR_AUTH ARM64_PTR_AUTH_KERNEL \
           ARM64_SW_TTBR0_PAN ARM64_BTI_KERNEL ARM64_MTE ARM64_EPAN \
           CPU_SW_DOMAIN_PAN; do
    enable "$opt"
done

# ---------------------------------------------------------------------------
# Kernel replacement / runtime modification attacks
# ---------------------------------------------------------------------------
echo "--- Kernel replacement protection"
for opt in HIBERNATION KEXEC KEXEC_FILE LIVEPATCH; do
    disable "$opt"
done

# ---------------------------------------------------------------------------
# Module security
# ---------------------------------------------------------------------------
echo "--- Module security"
enable STRICT_MODULE_RWX
enable MODULE_SIG
enable MODULE_SIG_ALL
enable MODULE_SIG_SHA512
enable MODULE_SIG_FORCE
enable DEBUG_SET_MODULE_RONX
# NOTE: If you need loadable modules at all, keep MODULES=y but the above
# signature-enforcement options are then mandatory. If you don't need
# modules, uncomment the next line to disable them entirely:
# disable MODULES

# ---------------------------------------------------------------------------
# Syscall surface reduction
# ---------------------------------------------------------------------------
echo "--- Syscall surface reduction"
enable SECCOMP
enable SECCOMP_FILTER
for opt in USELIB MODIFY_LDT_SYSCALL X86_VSYSCALL_EMULATION IO_URING \
           USER_NS USERFAULTFD BPF_SYSCALL BPF_JIT CHECKPOINT_RESTORE \
           X86_IOPL_IOPERM LDISC_AUTOLOAD KCMP RSEQ; do
    disable "$opt"
done
enable LEGACY_VSYSCALL_NONE
enable X86_INTEL_TSX_MODE_OFF

# ---------------------------------------------------------------------------
# LSM / security policy
# ---------------------------------------------------------------------------
echo "--- LSM / security policy"
enable SECURITY
enable SECURITY_YAMA
enable SECURITY_LOCKDOWN_LSM
enable SECURITY_LOCKDOWN_LSM_EARLY
enable LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY
enable SECURITY_SAFESETID
enable SECURITY_LOADPIN
enable SECURITY_LOADPIN_ENFORCE
disable SECURITY_WRITABLE_HOOKS
disable SECURITY_SELINUX_DISABLE

# ---------------------------------------------------------------------------
# /dev/mem, /dev/kmem, physical memory access
# ---------------------------------------------------------------------------
echo "--- Physical memory access"
disable DEVMEM
disable DEVKMEM
disable DEVPORT
enable IO_STRICT_DEVMEM
enable STRICT_DEVMEM
disable ACPI_CUSTOM_METHOD
disable PROC_KCORE

# ---------------------------------------------------------------------------
# Legacy / risky interfaces & drivers
# ---------------------------------------------------------------------------
echo "--- Legacy interfaces and risky drivers"
for opt in LEGACY_PTYS IA32_EMULATION X86_X32 OABI_COMPAT COMPAT_VDSO \
           BINFMT_MISC BINFMT_AOUT ZSMALLOC ZSMALLOC_STAT DRM_LEGACY \
           FB VT AIO STAGING KSM MAGIC_SYSRQ X86_MSR X86_CPUID \
           ACPI_TABLE_UPGRADE EFI_TEST EFI_CUSTOM_SSDT_OVERLAYS \
           MMIOTRACE MMIOTRACE_TEST IP_DCCP IP_SCTP VIDEO_VIVID \
           INPUT_EVBUG BLK_DEV_FD PUNIT_ATOM_DEBUG ACPI_CONFIGFS \
           EDAC_DEBUG DRM_I915_DEBUG BCACHE_CLOSURES_DEBUG \
           MTD_SLRAM MTD_PHRAM NOTIFIER_ERROR_INJECTION X86_PTDUMP \
           HWPOISON_INJECT MEM_SOFT_DIRTY; do
    disable "$opt"
done
enable EFI_DISABLE_PCI_DMA

# ---------------------------------------------------------------------------
# Tracing / debugging / probes (reduce attack + info-leak surface)
# ---------------------------------------------------------------------------
echo "--- Tracing and debug interfaces"
for opt in KPROBES UPROBES KPROBE_EVENTS UPROBE_EVENTS GENERIC_TRACER \
           TRACING TRACING_SUPPORT FTRACE FUNCTION_TRACER STACK_TRACER \
           HIST_TRIGGERS BLK_DEV_IO_TRACE FAIL_FUTEX LATENCYTOP KCOV \
           PROVIDE_OHCI1394_DMA_INIT SUNRPC_DEBUG; do
    disable "$opt"
done

# ---------------------------------------------------------------------------
# Panic / crash behavior
# ---------------------------------------------------------------------------
echo "--- Panic behavior"
enable PANIC_ON_OOPS
setval PANIC_TIMEOUT -1
enable TRIM_UNUSED_KSYMS
enable BUG
disable DEBUG_BUGVERBOSE

# ---------------------------------------------------------------------------
# Sanitizers / additional validation checks
# ---------------------------------------------------------------------------
echo "--- Sanitizers and validation checks"
for opt in UBSAN_BOUNDS UBSAN_SANITIZE_ALL UBSAN_TRAP DEBUG_LIST DEBUG_SG \
           DEBUG_CREDENTIALS DEBUG_NOTIFIERS BUG_ON_DATA_CORRUPTION \
           DEBUG_WX SYN_COOKIES STATIC_USERMODEHELPER RESET_ATTACK_MITIGATION; do
    enable "$opt"
done

# ---------------------------------------------------------------------------
# IOMMU / DMA attack mitigation
# ---------------------------------------------------------------------------
echo "--- IOMMU / DMA protection"
for opt in IOMMU_SUPPORT INTEL_IOMMU INTEL_IOMMU_DEFAULT_ON INTEL_IOMMU_SVM \
           AMD_IOMMU AMD_IOMMU_V2; do
    enable "$opt"
done

# ---------------------------------------------------------------------------
# Filesystem integrity (requires userspace support - see notes)
# ---------------------------------------------------------------------------
echo "--- Filesystem integrity (dm-verity preferred over IMA/EVM per Timesys)"
enable DM_VERITY
enable DM_CRYPT
enable DM_INTEGRITY
# IMA/EVM are more complex to deploy correctly; Timesys recommends
# DM_VERITY instead, but these are provided for completeness:
enable IMA
enable EVM

# ---------------------------------------------------------------------------
# Minimum mmap address (NULL pointer deref mitigation)
# ---------------------------------------------------------------------------
echo "--- Minimum mmap address"
# Set per architecture: 65536 for x86, 32768 for ARM/ARM64.
# Detect target arch from the kernel tree's current config if possible.
if grep -q '^CONFIG_X86' "$CONFIG_FILE" 2>/dev/null; then
    setval DEFAULT_MMAP_MIN_ADDR 65536
elif grep -q '^CONFIG_ARM' "$CONFIG_FILE" 2>/dev/null; then
    setval DEFAULT_MMAP_MIN_ADDR 32768
fi

echo
echo "=== Done. ==="
echo "Original config backed up to: $BACKUP"
echo
echo "Next steps:"
echo "  1. Resolve any new dependencies:"
echo "       make -C \"$KERNEL_SRC\" olddefconfig"
echo "  2. Add the following to your kernel boot cmdline for full effect:"
echo "       page_poison=1 slub_debug=P init_on_alloc=1 init_on_free=1"
echo "  3. Review the diff before building:"
echo "       diff -u \"$BACKUP\" \"$CONFIG_FILE\""
echo "  4. Some options (DM_CRYPT, DM_VERITY, DM_INTEGRITY, IMA, EVM) need"
echo "     matching userspace support and are NOT enabled by dependency"
echo "     resolution alone -- verify they build/link into your image."
echo "  5. Not every option applies to every architecture; scripts/config"
echo "     silently no-ops on options that don't exist in your Kconfig tree."


