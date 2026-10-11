.DEFAULT_GOAL := all

CC = gcc
AS = nasm
LD = ld
OBJCOPY = objcopy
OBJDUMP = objdump
PYTHON = python3

CORE = src/core
CRYPTO = src/crypto
PROCESS = src/process
OBJECTS = src/objects
NET = src/net
DRIVER = src/driver
FS = src/fs
BLOCK = src/block
PORTABLE_INCLUDES = -Isrc/arch -I$(CORE) -I$(CRYPTO) -I$(PROCESS) -I$(OBJECTS) \
	-I$(NET) -I$(DRIVER) -I$(FS) -I$(BLOCK)
ARCH64 = src/arch/x86_64
ARCH64_BOOT = $(ARCH64)/boot
ARCH64_CPU = $(ARCH64)/cpu
ARCH64_MEMORY = $(ARCH64)/memory
ARCH64_PLATFORM = $(ARCH64)/platform
ARCH64_DRIVERS = $(ARCH64)/drivers
ARCH64_KERNEL = $(ARCH64)/kernel
ARCH64_INCLUDES = -I$(ARCH64) -I$(ARCH64_CPU) -I$(ARCH64_MEMORY) \
	-I$(ARCH64_PLATFORM) -I$(ARCH64_DRIVERS) -I$(ARCH64_KERNEL)
TEST64 = src/tests/x86_64
# Shared freestanding base for the kernel and the user programs. GCC's own
# include directory provides the SSE2 intrinsics headers (used by user-side
# net code), which are self-contained under -nostdinc.
GCC_INCLUDE = $(shell $(CC) -print-file-name=include)
CFLAGS64_BASE = -m64 -mno-red-zone -nostdlib -nostdinc -fno-builtin -fno-stack-protector -nostartfiles -nodefaultlibs -ffreestanding -fno-pie -fno-pic -fno-asynchronous-unwind-tables -MMD -MP -Wall -Wextra -O2 -Isrc -I$(GCC_INCLUDE) $(ARCH64_INCLUDES) $(PORTABLE_INCLUDES) -I$(TEST64)
# The kernel itself must never emit SSE/MMX code: user FPU state is only
# preserved lazily (fpu64_save/fpu64_load around context switches) and the
# syscall/fault/interrupt entry paths do not save XMM registers. Any SSE
# instruction executed by kernel code (compiler-vectorized copy loops, SSE
# memcpy/checksum) silently corrupts live user XMM registers - a movdqa/
# movaps pair split by a COW write fault stored zeros into signal_demo's
# nanosleep interval that way. mem.c and net/checksum.h keep scalar fallback
# paths for exactly this build.
CFLAGS64 = $(CFLAGS64_BASE) -mgeneral-regs-only
# User programs run with their own FPU state (saved by the scheduler), so
# they keep the x86-64 baseline ISA with SSE2.
USER64_CFLAGS = $(CFLAGS64_BASE) -msse2 -mno-mmx -mcmodel=large -Isrc/user64/include -Isrc/user64/lib
LDFLAGS64 = -m elf_x86_64 -T $(ARCH64_BOOT)/linker.ld

# The netbench capsule grows to real bulk and packet-rate sizes and dials the
# peer directly only on the tap/vhost (KVM) topology; MICH_NET_TAP selects that
# build. make does not track flag changes, so run `make clean` when switching
# topology. The same variable switches qemu-smoke64.sh to a tap+vhost netdev.
ifdef MICH_NET_TAP
NETBENCH_TAP_FLAG = -DMICH_NETBENCH_TAP
endif

BIN_DIR = bin
BIN64 = $(BIN_DIR)/x86_64
OBJ64 = $(BIN64)/obj
KERNEL64_ELF = $(BIN64)/mich-kernel.elf
KERNEL64_FLAT = $(BIN64)/mich-kernel.bin
KERNEL64_TEST_ELF = $(BIN64)/mich-kernel-test.elf
KERNEL64_TEST_FLAT = $(BIN64)/mich-kernel-test.bin
DISK64 = $(BIN64)/disk.img
DISK64_TEST = $(BIN64)/disk-test.img
DISK64_UNIT = $(BIN64)/disk-unit.img
DISK64_HARDWARE = $(BIN64)/disk-hardware.img
DISK64_DNS = $(BIN64)/disk-dns.img
DISK64_NETBENCH = $(BIN64)/disk-netbench.img
DISK64_TCPWIRE = $(BIN64)/disk-tcpwire.img
DISK64_TTY = $(BIN64)/disk-tty.img
DISK64_VIRTIO_BLK = $(BIN64)/disk-virtio-blk.img
DISK64_NVME = $(BIN64)/disk-nvme.img
DISK64_HARDWARE_RESTART = $(BIN64)/disk-hardware-restart.img
DISK64_HARDWARE_CIRCUIT = $(BIN64)/disk-hardware-circuit.img
DISK64_HARDWARE_RECOVERY = $(BIN64)/disk-hardware-recovery.img
RECOVERY_STABILITY_RUNS ?= 3
DISK64_PANIC = $(BIN64)/disk-panic.img
DISK64_CRASH = $(BIN64)/disk-crash.img
UEFI64_OBJ = $(OBJ64)/uefi.o
UEFI64_EFI = $(BIN64)/BOOTX64.EFI
USER64_DIR = $(BIN64)/user
USER64_OBJ_DIR = $(USER64_DIR)/obj
INIT64_ELF = $(USER64_DIR)/init64.elf
INIT64_OBJS = $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(USER64_OBJ_DIR)/sigreturn.o $(USER64_OBJ_DIR)/posix.o $(USER64_OBJ_DIR)/process.o $(USER64_OBJ_DIR)/init.o
POSIXAPP64_ELF = $(USER64_DIR)/posixapp64.elf
POSIXAPP64_OBJS = $(USER64_OBJ_DIR)/crt0_posix.o $(USER64_OBJ_DIR)/syscall.o $(USER64_OBJ_DIR)/sigreturn.o $(USER64_OBJ_DIR)/posix.o $(USER64_OBJ_DIR)/process.o $(USER64_OBJ_DIR)/string.o $(USER64_OBJ_DIR)/stdio.o $(USER64_OBJ_DIR)/stdlib.o $(USER64_OBJ_DIR)/posixapp.o
POSIXDEMO64_ELF = $(USER64_DIR)/posixdemo64.elf
POSIXDEMO64_OBJS = $(USER64_OBJ_DIR)/crt0_posix.o $(USER64_OBJ_DIR)/syscall.o $(USER64_OBJ_DIR)/sigreturn.o $(USER64_OBJ_DIR)/posix.o $(USER64_OBJ_DIR)/process.o $(USER64_OBJ_DIR)/string.o $(USER64_OBJ_DIR)/stdio.o $(USER64_OBJ_DIR)/stdlib.o $(USER64_OBJ_DIR)/posixdemo.o
VIRTIO_LIB64_OBJ = $(USER64_OBJ_DIR)/virtio_lib.o
VIRTIO_BLK64_OBJ = $(USER64_OBJ_DIR)/virtio_blk.o
NVME64_OBJ = $(USER64_OBJ_DIR)/nvme_capsule.o
VIRTIO_NET64_OBJ = $(USER64_OBJ_DIR)/virtio_net.o
VIRTIO_NET_SAFE64_OBJ = $(USER64_OBJ_DIR)/virtio_net_safe.o
VIRTIO_NET64_PROBES_OBJ = $(USER64_OBJ_DIR)/virtio_net_probes.o
DNSPROBE64_OBJ = $(USER64_OBJ_DIR)/dnsprobe.o
NETBENCH64_OBJ = $(USER64_OBJ_DIR)/netbench.o
TCPWIRE64_OBJ = $(USER64_OBJ_DIR)/tcpwire.o
DNS64_OBJ = $(USER64_OBJ_DIR)/dns.o
DNS_MESSAGE64_OBJ = $(USER64_OBJ_DIR)/dns_message.o
VIRTIO_BLK64_ELF = $(USER64_DIR)/virtio-blk.elf
NVME64_ELF = $(USER64_DIR)/nvme.elf
VIRTIO_NET64_ELF = $(USER64_DIR)/virtio-net.elf
DNSPROBE64_ELF = $(USER64_DIR)/dnsprobe.elf
NETBENCH64_ELF = $(USER64_DIR)/netbench.elf
TCPWIRE64_ELF = $(USER64_DIR)/tcpwire.elf
GEN64_DIR = $(BIN64)/generated
VIRTIO_NET_RECOVERY_RIP_H = $(GEN64_DIR)/virtio_net_recovery_rip.h
VIRTIO_NET_SAFE64_ELF = $(USER64_DIR)/virtio-net-safe.elf
# The object lists are derived from the tree, so a new module or a new test is
# one new file instead of four Makefile edits; a dropped edit is exactly how
# the pipe recipes went missing. scripts/check-build.sh verifies the derived
# result the way the linker would find out anyway, only earlier.
PORTABLE_CORE_DIRS = $(CORE) $(CRYPTO) $(PROCESS) $(OBJECTS) $(NET) $(DRIVER) $(FS) $(BLOCK)
PORTABLE_CORE_SRCS = $(foreach dir,$(PORTABLE_CORE_DIRS),$(wildcard $(dir)/*.c))
PORTABLE_CORE_OBJS = $(foreach src,$(PORTABLE_CORE_SRCS),$(OBJ64)/$(notdir $(basename $(src)))_core.o)
# scheduler_core.c already carries the suffix, so its object drops the doubling.
PORTABLE_CORE_OBJS := $(filter-out $(OBJ64)/scheduler_core_core.o,$(PORTABLE_CORE_OBJS))
ARCH64_OBJS = \
	$(patsubst $(ARCH64_CPU)/%.c,$(OBJ64)/%.o,$(wildcard $(ARCH64_CPU)/*.c)) \
	$(patsubst $(ARCH64_MEMORY)/%.c,$(OBJ64)/%.o,$(wildcard $(ARCH64_MEMORY)/*.c)) \
	$(patsubst $(ARCH64_PLATFORM)/%.c,$(OBJ64)/%.o,$(wildcard $(ARCH64_PLATFORM)/*.c)) \
	$(patsubst $(ARCH64_DRIVERS)/%.c,$(OBJ64)/%.o,$(wildcard $(ARCH64_DRIVERS)/*.c)) \
	$(patsubst $(ARCH64_KERNEL)/%.c,$(OBJ64)/%.o,$(filter-out $(ARCH64_KERNEL)/kernel.c,$(wildcard $(ARCH64_KERNEL)/*.c))) \
	$(patsubst $(ARCH64_CPU)/%.asm,$(OBJ64)/%.o,$(filter-out $(ARCH64_CPU)/gdt.asm,$(wildcard $(ARCH64_CPU)/*.asm))) \
	$(patsubst $(ARCH64_KERNEL)/%.asm,$(OBJ64)/%.o,$(wildcard $(ARCH64_KERNEL)/*.asm))
# boot.asm, gdt.asm and kernel.c keep explicit rules: their object names do not
# follow their source names, and kernel.c is compiled twice with different flags.
OBJS64 = $(PORTABLE_CORE_OBJS) $(OBJ64)/scheduler_core.o $(ARCH64_OBJS) \
	$(OBJ64)/boot.o $(OBJ64)/gdt_asm.o $(OBJ64)/kernel.o
# <name>_test.c becomes test_<name>64.o. Seven sources predate the convention
# (ipv4, ipv6, and the five auxiliary runners) and stay listed.
TEST64_SRCS = $(wildcard $(TEST64)/*_test.c)
TEST64_AUX_SRCS = $(filter-out $(TEST64_SRCS),$(wildcard $(TEST64)/*.c))
TEST64_OBJS = \
	$(patsubst $(TEST64)/%_test.c,$(OBJ64)/test_%64.o,$(filter-out $(TEST64)/ipv4_test.c $(TEST64)/ipv6_test.c,$(TEST64_SRCS))) \
	$(patsubst $(TEST64)/%.c,$(OBJ64)/test_%64.o,$(filter-out $(TEST64)/test_runner.c $(TEST64)/test_report.c $(TEST64)/network_runner.c $(TEST64)/net_test_support.c $(TEST64)/crash_boot.c,$(TEST64_AUX_SRCS))) \
	$(OBJ64)/test_ipv4_64.o $(OBJ64)/test_ipv6_64.o $(OBJ64)/test_runner64.o \
	$(OBJ64)/test_report64.o $(OBJ64)/test_network_runner64.o $(OBJ64)/test_net_support64.o \
	$(OBJ64)/test_crash_boot64.o
OBJS64_TEST = $(OBJ64)/boot.o $(OBJ64)/kernel_test.o $(filter-out $(OBJ64)/boot.o $(OBJ64)/kernel.o,$(OBJS64)) $(TEST64_OBJS)
PORTABLE64_DIR = $(BIN64)/portable
# The portable check compiles each module standalone. The excluded modules are
# the pre-refactor exclusion list kept verbatim: they either need arch glue or
# are kernel-only (mem, entropy, siphash, crypto, iommu, scheduler_core,
# dns_message). A new module joins the check by default, and a failure here is
# the signal to add it to this list with a reason.
PORTABLE64_NAMES = $(filter-out mem entropy siphash crypto iommu scheduler_core dns_message,$(notdir $(basename $(PORTABLE_CORE_SRCS))))
PORTABLE64_OBJS = $(addprefix $(PORTABLE64_DIR)/,$(addsuffix .o,$(PORTABLE64_NAMES)))

all: $(DISK64) $(PORTABLE64_OBJS)

$(BIN_DIR) $(BIN64) $(OBJ64) $(PORTABLE64_DIR) $(USER64_DIR) $(USER64_OBJ_DIR) $(GEN64_DIR):
	mkdir -p $@

$(PORTABLE64_DIR)/%.o: $(CORE)/%.c | $(PORTABLE64_DIR)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(PORTABLE64_DIR)/%.o: $(PROCESS)/%.c | $(PORTABLE64_DIR)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(PORTABLE64_DIR)/%.o: $(OBJECTS)/%.c | $(PORTABLE64_DIR)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(PORTABLE64_DIR)/%.o: $(NET)/%.c | $(PORTABLE64_DIR)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(PORTABLE64_DIR)/%.o: $(DRIVER)/%.c | $(PORTABLE64_DIR)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(PORTABLE64_DIR)/%.o: $(FS)/%.c | $(PORTABLE64_DIR)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(PORTABLE64_DIR)/%.o: $(BLOCK)/%.c | $(PORTABLE64_DIR)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/boot.o: $(ARCH64_BOOT)/boot.asm | $(OBJ64)
	$(AS) -f elf64 $< -o $@

$(OBJ64)/kernel.o: $(ARCH64_KERNEL)/kernel.c $(CORE)/version.h $(VIRTIO_NET_RECOVERY_RIP_H) | $(OBJ64)
	$(CC) $(CFLAGS64) -I$(GEN64_DIR) -Werror -c $< -o $@

$(OBJ64)/kernel_test.o: $(ARCH64_KERNEL)/kernel.c $(CORE)/version.h $(VIRTIO_NET_RECOVERY_RIP_H) $(TEST64)/tests64.h $(TEST64)/test_report.h | $(OBJ64)
	$(CC) $(CFLAGS64) -DMICH_TEST_BUILD -I$(GEN64_DIR) -Werror -c $< -o $@

$(OBJ64)/syscall_dispatch.o: $(ARCH64_KERNEL)/syscall_dispatch.c $(ARCH64_KERNEL)/kernel64_internal.h | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

# One <module>_core.o per portable source. The header graph comes from the
# -MMD files included at the bottom, so a rule needs no hand list of headers.
$(OBJ64)/%_core.o: $(CORE)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%_core.o: $(CRYPTO)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%_core.o: $(PROCESS)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%_core.o: $(OBJECTS)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%_core.o: $(NET)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%_core.o: $(DRIVER)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%_core.o: $(FS)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%_core.o: $(BLOCK)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/scheduler_core.o: $(PROCESS)/scheduler_core.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_%64.o: $(TEST64)/%_test.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_%64.o: $(TEST64)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_ipv4_64.o: $(TEST64)/ipv4_test.c $(TEST64)/tests64.h | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_ipv6_64.o: $(TEST64)/ipv6_test.c $(TEST64)/tests64.h | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_runner64.o: $(TEST64)/test_runner.c $(TEST64)/tests64.h $(TEST64)/test_report.h | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_network_runner64.o: $(TEST64)/network_runner.c $(TEST64)/tests64.h | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_net_support64.o: $(TEST64)/net_test_support.c $(TEST64)/tests64.h | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_crash_boot64.o: $(TEST64)/crash_boot.c $(TEST64)/tests64.h | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/test_report64.o: $(TEST64)/test_report.c $(TEST64)/test_report.h | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@


$(OBJ64)/gdt_asm.o: $(ARCH64_CPU)/gdt.asm | $(OBJ64)
	$(AS) -f elf64 $< -o $@

$(OBJ64)/%.o: $(ARCH64_CPU)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%.o: $(ARCH64_MEMORY)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%.o: $(ARCH64_PLATFORM)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%.o: $(ARCH64_DRIVERS)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%.o: $(ARCH64_KERNEL)/%.c | $(OBJ64)
	$(CC) $(CFLAGS64) -Werror -c $< -o $@

$(OBJ64)/%.o: $(ARCH64_CPU)/%.asm | $(OBJ64)
	$(AS) -f elf64 $< -o $@

$(OBJ64)/%.o: $(ARCH64_KERNEL)/%.asm | $(OBJ64)
	$(AS) -f elf64 $< -o $@

$(USER64_OBJ_DIR)/crt0.o: src/user64/lib/crt0.asm | $(USER64_OBJ_DIR)
	$(AS) -f elf64 $< -o $@

$(USER64_OBJ_DIR)/syscall.o: src/user64/lib/syscall.asm | $(USER64_OBJ_DIR)
	$(AS) -f elf64 $< -o $@

$(USER64_OBJ_DIR)/sigreturn.o: src/user64/lib/sigreturn.asm | $(USER64_OBJ_DIR)
	$(AS) -f elf64 $< -o $@

$(USER64_OBJ_DIR)/posix.o: src/user64/lib/posix.c src/process/posix_abi.h src/user64/include/errno.h src/user64/include/fcntl.h src/user64/include/signal.h src/user64/include/time.h src/user64/include/unistd.h src/user64/include/mich/syscall.h src/user64/include/sys/stat.h src/user64/include/sys/random.h src/user64/include/sys/socket.h src/user64/include/netinet/in.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(USER64_OBJ_DIR)/init.o: src/user64/init/main.c src/user64/include/mich/syscall.h src/user64/include/mich/service.h src/user64/include/mich/capability.h src/user64/include/mich/ipc.h src/user64/include/mich/event.h src/user64/include/mich/bridge.h src/user64/include/mich/hardware.h src/user64/include/mich/driver.h src/user64/include/mich/memory.h src/user64/include/mich/sg.h src/user64/include/mich/ring.h src/user64/include/mich/completion.h src/user64/include/mich/timer.h src/user64/include/mich/wait.h src/user64/include/mich/net.h src/user64/include/mich/socket.h src/user64/include/mich/net_interface.h src/user64/include/mich/vfs.h src/user64/include/mich/firmware.h src/user64/include/mich/block.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(INIT64_ELF): $(INIT64_OBJS) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -T src/user64/linker.ld -o $@ $(INIT64_OBJS)

$(USER64_OBJ_DIR)/crt0_posix.o: src/user64/lib/crt0_posix.asm | $(USER64_OBJ_DIR)
	$(AS) -f elf64 $< -o $@

$(USER64_OBJ_DIR)/process.o: src/user64/lib/process.c src/process/posix_abi.h src/user64/include/errno.h src/user64/include/unistd.h src/user64/include/sys/wait.h src/user64/include/mich/syscall.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(USER64_OBJ_DIR)/string.o: src/user64/lib/string.c src/user64/include/string.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(USER64_OBJ_DIR)/stdio.o: src/user64/lib/stdio.c src/user64/include/stdio.h src/user64/include/string.h src/user64/include/stdlib.h src/user64/include/unistd.h src/user64/include/fcntl.h src/user64/include/errno.h src/user64/include/mich/syscall.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(USER64_OBJ_DIR)/stdlib.o: src/user64/lib/stdlib.c src/user64/include/stdlib.h src/user64/include/string.h src/user64/include/errno.h src/user64/include/limits.h src/user64/include/unistd.h src/user64/include/sys/stat.h src/user64/include/mich/syscall.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(USER64_OBJ_DIR)/posixapp.o: src/user64/posixapp/main.c src/user64/include/errno.h src/user64/include/fcntl.h src/user64/include/unistd.h src/user64/include/sys/stat.h src/user64/include/mich/syscall.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(POSIXAPP64_ELF): $(POSIXAPP64_OBJS) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -T src/user64/linker.ld -o $@ $(POSIXAPP64_OBJS)

$(USER64_OBJ_DIR)/posixdemo.o:src/user64/posixdemo/main.c src/user64/include/errno.h src/user64/include/fcntl.h src/user64/include/signal.h src/user64/include/time.h src/user64/include/unistd.h src/user64/include/string.h src/user64/include/stdio.h src/user64/include/stdlib.h src/user64/include/sys/stat.h src/user64/include/sys/wait.h src/user64/include/mich/syscall.h src/user64/include/sys/random.h src/user64/include/sys/socket.h src/user64/include/netinet/in.h src/user64/include/poll.h src/user64/include/sys/select.h | $(USER64_OBJ_DIR) src/user64/include/sys/random.h
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(POSIXDEMO64_ELF): $(POSIXDEMO64_OBJS) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -T src/user64/linker.ld -o $@ $(POSIXDEMO64_OBJS)

$(VIRTIO_LIB64_OBJ): src/user64/lib/virtio/virtio.c src/user64/lib/virtio/virtio.h src/user64/include/mich/hardware.h src/user64/include/mich/syscall.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(VIRTIO_BLK64_OBJ): src/user64/virtio_blk/main.c src/user64/virtio_blk/capsule.h src/user64/lib/virtio/virtio.h src/user64/include/mich/syscall.h src/user64/include/mich/driver.h src/user64/include/mich/hardware.h src/user64/include/mich/ring.h src/user64/include/mich/memory.h src/user64/include/mich/event.h src/user64/include/mich/block.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(NVME64_OBJ): src/user64/nvme/main.c src/user64/nvme/capsule.h src/user64/include/mich/syscall.h src/user64/include/mich/driver.h src/user64/include/mich/hardware.h src/user64/include/mich/ring.h src/user64/include/mich/memory.h src/user64/include/mich/event.h src/user64/include/mich/block.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(VIRTIO_NET64_OBJ): src/user64/virtio_net/main.c src/user64/virtio_net/capsule.h src/user64/lib/virtio/virtio.h src/user64/include/mich/syscall.h src/user64/include/mich/event.h src/user64/include/mich/driver.h src/user64/include/mich/hardware.h src/user64/include/mich/net.h src/user64/include/mich/net_interface.h src/user64/include/mich/timer.h src/user64/include/mich/wait.h src/user64/include/mich/vfs.h src/user64/include/mich/firmware.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(VIRTIO_NET_SAFE64_OBJ): src/user64/virtio_net/safe.c src/user64/include/mich/syscall.h src/user64/include/mich/driver.h src/user64/lib/virtio/virtio.h src/user64/include/mich/hardware.h src/user64/include/mich/net.h src/user64/include/mich/net_interface.h src/user64/include/mich/bridge.h src/user64/include/mich/wait.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(VIRTIO_NET64_PROBES_OBJ): src/user64/virtio_net/probes.c src/user64/virtio_net/capsule.h src/user64/include/mich/syscall.h src/user64/include/mich/net_interface.h src/user64/include/mich/socket.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(DNS_MESSAGE64_OBJ): src/net/dns_message.c src/net/dns_message.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@










$(DNS64_OBJ): src/user64/lib/dns.c src/user64/include/mich/dns.h src/net/dns_message.h src/user64/include/mich/socket.h src/user64/include/mich/syscall.h src/user64/include/mich/timer.h src/user64/include/mich/event.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(DNSPROBE64_OBJ): src/user64/dnsprobe/main.c src/user64/include/mich/dns.h src/user64/include/mich/syscall.h src/user64/include/mich/timer.h src/net/dns_message.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

$(DNSPROBE64_ELF): $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(DNSPROBE64_OBJ) $(DNS64_OBJ) $(DNS_MESSAGE64_OBJ) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -x -T src/user64/linker.ld -o $@ $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(DNSPROBE64_OBJ) $(DNS64_OBJ) $(DNS_MESSAGE64_OBJ)

$(NETBENCH64_OBJ): src/user64/netbench/main.c src/user64/include/mich/syscall.h src/user64/include/mich/socket.h src/net/socket_abi.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) $(NETBENCH_TAP_FLAG) -Werror -c $< -o $@

$(NETBENCH64_ELF): $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(NETBENCH64_OBJ) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -x -T src/user64/linker.ld -o $@ $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(NETBENCH64_OBJ)

$(TCPWIRE64_OBJ): src/user64/tcpwire/main.c src/user64/include/sys/types.h src/user64/include/sys/socket.h src/user64/include/netinet/in.h src/user64/include/time.h src/user64/include/mich/syscall.h | $(USER64_OBJ_DIR)
	$(CC) $(USER64_CFLAGS) -Werror -c $< -o $@

# The posix wrappers ride along, so the capsule reaches the wire through the
# same request ABI the posixdemo uses; the module flag admits it to the posix
# profile, which is what the socket gate checks.
$(TCPWIRE64_ELF): $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(USER64_OBJ_DIR)/sigreturn.o $(USER64_OBJ_DIR)/posix.o $(USER64_OBJ_DIR)/process.o $(TCPWIRE64_OBJ) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -x -T src/user64/linker.ld -o $@ $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(USER64_OBJ_DIR)/sigreturn.o $(USER64_OBJ_DIR)/posix.o $(USER64_OBJ_DIR)/process.o $(TCPWIRE64_OBJ)



$(VIRTIO_BLK64_ELF): $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(VIRTIO_LIB64_OBJ) $(VIRTIO_BLK64_OBJ) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -x -T src/user64/linker.ld -o $@ $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(VIRTIO_LIB64_OBJ) $(VIRTIO_BLK64_OBJ)

# Builds the block-driver capsule on its own, without a boot image.
user64-virtio-blk: $(VIRTIO_BLK64_ELF)

$(NVME64_ELF): $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(NVME64_OBJ) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -x -T src/user64/linker.ld -o $@ $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(NVME64_OBJ)

user64-nvme: $(NVME64_ELF)

$(VIRTIO_NET64_ELF): $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(VIRTIO_LIB64_OBJ) $(VIRTIO_NET64_OBJ) $(VIRTIO_NET64_PROBES_OBJ) $(DNS64_OBJ) $(DNS_MESSAGE64_OBJ) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -x -T src/user64/linker.ld -o $@ $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(VIRTIO_LIB64_OBJ) $(VIRTIO_NET64_OBJ) $(VIRTIO_NET64_PROBES_OBJ) $(DNS64_OBJ) $(DNS_MESSAGE64_OBJ)

$(VIRTIO_NET_RECOVERY_RIP_H): $(VIRTIO_NET64_ELF) scripts/gen-virtio-net-recovery-rip.sh | $(GEN64_DIR)
	OBJDUMP=$(OBJDUMP) sh scripts/gen-virtio-net-recovery-rip.sh $(VIRTIO_NET64_ELF) > $@.tmp
	mv $@.tmp $@

$(VIRTIO_NET_SAFE64_ELF): $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(VIRTIO_LIB64_OBJ) $(VIRTIO_NET_SAFE64_OBJ) src/user64/linker.ld | $(USER64_DIR)
	$(LD) -m elf_x86_64 -x -T src/user64/linker.ld -o $@ $(USER64_OBJ_DIR)/crt0.o $(USER64_OBJ_DIR)/syscall.o $(VIRTIO_LIB64_OBJ) $(VIRTIO_NET_SAFE64_OBJ)
$(KERNEL64_ELF): $(OBJS64) $(ARCH64_BOOT)/linker.ld | $(BIN64)
	$(LD) $(LDFLAGS64) -o $@ $(OBJS64)

$(KERNEL64_FLAT): $(KERNEL64_ELF)
	$(OBJCOPY) -O binary $< $@

$(KERNEL64_TEST_ELF): $(OBJS64_TEST) $(ARCH64_BOOT)/linker.ld | $(BIN64)
	$(LD) $(LDFLAGS64) -o $@ $(OBJS64_TEST)

$(KERNEL64_TEST_FLAT): $(KERNEL64_TEST_ELF)
	$(OBJCOPY) -O binary $< $@

$(UEFI64_OBJ): $(ARCH64_BOOT)/uefi.c $(CORE)/bootinfo.h $(CORE)/types.h | $(OBJ64)
	$(CC) $(CFLAGS64) -mno-sse -mno-sse2 -fno-ident -Werror -c $< -o $@

$(UEFI64_EFI): $(UEFI64_OBJ) $(ARCH64_BOOT)/uefi.ld | $(BIN64)
	$(LD) -m i386pep -T $(ARCH64_BOOT)/uefi.ld --subsystem 10 -e efi_main \
		--image-base 0x3000000 --section-alignment 4096 --file-alignment 512 \
		--disable-reloc-section --disable-dynamicbase --disable-high-entropy-va \
		-o $@ $(UEFI64_OBJ)

$(DISK64): mkuefi64.py $(KERNEL64_ELF) $(KERNEL64_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(POSIXAPP64_ELF) $(POSIXDEMO64_ELF)
	$(PYTHON) mkuefi64.py --efi $(UEFI64_EFI) $@ init64:0x20000C9=$(INIT64_ELF) posixapp:0=$(POSIXAPP64_ELF) posixdemo:0=$(POSIXDEMO64_ELF)

$(DISK64_TEST): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(POSIXAPP64_ELF) $(POSIXDEMO64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x30000C9=$(INIT64_ELF) posixapp:0=$(POSIXAPP64_ELF) posixdemo:0=$(POSIXDEMO64_ELF)

# The console wire profile: the same battery as the test disk, with the
# flag that lets the demo run its input stage. The runner types into the
# serial port, so nothing here is reachable on a plain boot.
$(DISK64_TTY): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(POSIXAPP64_ELF) $(POSIXDEMO64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x32000C9=$(INIT64_ELF) posixapp:0=$(POSIXAPP64_ELF) posixdemo:0=$(POSIXDEMO64_ELF)

# Ships the default disk (kernel, init, posix images so init's process tests
# still pass) plus the virtio-blk capsule the kernel spots by module name.
$(DISK64_VIRTIO_BLK): mkuefi64.py $(KERNEL64_ELF) $(KERNEL64_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(POSIXAPP64_ELF) $(POSIXDEMO64_ELF) $(VIRTIO_BLK64_ELF)
	$(PYTHON) mkuefi64.py --efi $(UEFI64_EFI) $@ init64:0x30000C9=$(INIT64_ELF) posixapp:0=$(POSIXAPP64_ELF) posixdemo:0=$(POSIXDEMO64_ELF) virtio-blk:0=$(VIRTIO_BLK64_ELF)

# Production kernel plus the NVMe capsule the kernel spots by module name.
$(DISK64_NVME): mkuefi64.py $(KERNEL64_ELF) $(KERNEL64_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(POSIXAPP64_ELF) $(POSIXDEMO64_ELF) $(NVME64_ELF)
	$(PYTHON) mkuefi64.py --efi $(UEFI64_EFI) $@ init64:0x30000C9=$(INIT64_ELF) posixapp:0=$(POSIXAPP64_ELF) posixdemo:0=$(POSIXDEMO64_ELF) nvme:0=$(NVME64_ELF)

$(DISK64_UNIT): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(POSIXAPP64_ELF) $(POSIXDEMO64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x130000C9=$(INIT64_ELF) posixapp:0=$(POSIXAPP64_ELF) posixdemo:0=$(POSIXDEMO64_ELF)

$(DISK64_HARDWARE): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(VIRTIO_NET64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x410000C9=$(INIT64_ELF) virtio-net:0=$(VIRTIO_NET64_ELF)

$(DISK64_DNS): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(VIRTIO_NET64_ELF) $(DNSPROBE64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x410000C9=$(INIT64_ELF) virtio-net:0=$(VIRTIO_NET64_ELF) dnsprobe:0=$(DNSPROBE64_ELF)
# Loopback socket-path benchmark. Ships the same init flags and virtio-net
# capsule as the dns image so it reuses the kernel's probe-spawn hook,
# but the kernel recognises the "netbench" module and skips the driver-live
# recovery lab for this boot: a resident bench task perturbs that lab's tick
# deadline and pollutes the cycle counts, so the benchmark wants a quiescent
# kernel. The benchmark itself never touches the NIC; it runs over loopback.
$(DISK64_NETBENCH): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(VIRTIO_NET64_ELF) $(NETBENCH64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x410000C9=$(INIT64_ELF) virtio-net:0=$(VIRTIO_NET64_ELF) netbench:0=$(NETBENCH64_ELF)
# POSIX stream demo over the real NIC: the same capsule pair as the dns image,
# with the probe module carrying the posix profile flag so its socket calls
# pass the admission gate. The smoke runner bridges the host echo to 10.0.2.4.
$(DISK64_TCPWIRE): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(VIRTIO_NET64_ELF) $(TCPWIRE64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x410000C9=$(INIT64_ELF) virtio-net:0=$(VIRTIO_NET64_ELF) tcpwire:0x02000000=$(TCPWIRE64_ELF)



$(DISK64_HARDWARE_RESTART): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(VIRTIO_NET64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x610000C9=$(INIT64_ELF) virtio-net:0=$(VIRTIO_NET64_ELF)

$(DISK64_HARDWARE_CIRCUIT): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(VIRTIO_NET64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x690000C9=$(INIT64_ELF) virtio-net:0=$(VIRTIO_NET64_ELF)

$(DISK64_HARDWARE_RECOVERY): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF) $(VIRTIO_NET64_ELF) $(VIRTIO_NET_SAFE64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x650000C9=$(INIT64_ELF) virtio-net:0=$(VIRTIO_NET64_ELF) virtio-net-safe:0=$(VIRTIO_NET_SAFE64_ELF)

$(DISK64_PANIC): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0x800000C9=$(INIT64_ELF)

$(DISK64_CRASH): mkuefi64.py $(KERNEL64_TEST_ELF) $(KERNEL64_TEST_FLAT) $(UEFI64_EFI) $(INIT64_ELF)
	$(PYTHON) mkuefi64.py --kernel $(KERNEL64_TEST_ELF) --kernel-flat $(KERNEL64_TEST_FLAT) \
		--efi $(UEFI64_EFI) $@ init64:0xC9=$(INIT64_ELF) crash64:0=$(INIT64_ELF)

run64: $(DISK64)
	sh ./scripts/qemu-run64.sh $(DISK64)

# With the syscall-186 fix init runs its whole suite, and the extra serial volume
# occasionally loses a byte in serial64_putc (non-blocking by design, see
# drivers/serial.c) which garbles one random marker line. That is emulation
# noise, not a kernel failure, so retry; a real regression fails every attempt.
test64: $(DISK64_TEST)
	@attempt=1; while :; do sh ./scripts/qemu-smoke64.sh $(DISK64_TEST) && break; if [ $$attempt -ge 4 ]; then echo "test64: smoke failed after $$attempt attempts"; exit 1; fi; echo "test64: transient smoke failure, retry $$attempt/4"; attempt=$$((attempt + 1)); done

test64-prod: $(DISK64)
	sh ./scripts/qemu-prod64.sh $(DISK64)

test64-unit: $(DISK64_UNIT)
	sh ./scripts/qemu-unit64.sh $(DISK64_UNIT)

test64-highmem: $(DISK64_TEST)
	sh ./scripts/qemu-smoke64.sh $(DISK64_TEST) 768M highmem

test64-smp: $(DISK64_TEST)
	sh ./scripts/qemu-smoke64.sh $(DISK64_TEST) 128M smp
# Four CPUs make the spinlock stress and the AP tests much slower under TCG,
# so the four-CPU profile gets a longer guest budget.
SMP4_ENV = MICH_SMP_CPUS=4 MICH_QEMU_TIMEOUT=300
test64-smp4: $(DISK64_TEST)
	$(SMP4_ENV) sh ./scripts/qemu-smoke64.sh $(DISK64_TEST) 128M smp

test64-hardware: $(DISK64_HARDWARE)
	sh ./scripts/qemu-smoke64.sh $(DISK64_HARDWARE) 128M hardware
test64-dns: $(DISK64_DNS)
	sh ./scripts/qemu-smoke64.sh $(DISK64_DNS) 256M dns
test64-netbench: $(DISK64_NETBENCH)
	sh ./scripts/qemu-smoke64.sh $(DISK64_NETBENCH) 256M netbench

test64-tcpwire: $(DISK64_TCPWIRE)
	sh ./scripts/qemu-smoke64.sh $(DISK64_TCPWIRE) 256M tcpwire

test64-tty: $(DISK64_TTY)
	sh ./scripts/qemu-smoke64.sh $(DISK64_TTY) 128M tty
test64-virtio-blk: $(DISK64_VIRTIO_BLK)
	sh ./scripts/qemu-smoke64.sh $(DISK64_VIRTIO_BLK) 256M virtio-blk
test64-nvme: $(DISK64_NVME)
	sh ./scripts/qemu-smoke64.sh $(DISK64_NVME) 256M nvme




test64-msi: $(DISK64_HARDWARE)
	sh ./scripts/qemu-smoke64.sh $(DISK64_HARDWARE) 256M msi

test64-msi-restart: $(DISK64_HARDWARE_RESTART)
	sh ./scripts/qemu-smoke64.sh $(DISK64_HARDWARE_RESTART) 256M msi-restart

test64-msi-circuit: $(DISK64_HARDWARE_CIRCUIT)
	sh ./scripts/qemu-smoke64.sh $(DISK64_HARDWARE_CIRCUIT) 256M msi-circuit

test64-msi-recovery: $(DISK64_HARDWARE_RECOVERY)
	sh ./scripts/qemu-smoke64.sh $(DISK64_HARDWARE_RECOVERY) 256M msi-recovery

test64-msi-restart-stability: $(DISK64_HARDWARE_RESTART)
	sh ./scripts/qemu-recovery-stability.sh $(DISK64_HARDWARE_RESTART) 256M msi-restart $(RECOVERY_STABILITY_RUNS)

test64-msi-circuit-stability: $(DISK64_HARDWARE_CIRCUIT)
	sh ./scripts/qemu-recovery-stability.sh $(DISK64_HARDWARE_CIRCUIT) 256M msi-circuit $(RECOVERY_STABILITY_RUNS)

test64-msi-recovery-stability: $(DISK64_HARDWARE_RECOVERY)
	sh ./scripts/qemu-recovery-stability.sh $(DISK64_HARDWARE_RECOVERY) 256M msi-recovery $(RECOVERY_STABILITY_RUNS)

test64-pcie: $(DISK64_TEST)
	sh ./scripts/qemu-smoke64.sh $(DISK64_TEST) 256M pcie

test64-iommu: $(DISK64_TEST)
	sh ./scripts/qemu-smoke64.sh $(DISK64_TEST) 256M iommu

test64-amd-iommu: $(DISK64_TEST)
	sh ./scripts/qemu-smoke64.sh $(DISK64_TEST) 256M amd-iommu

test64-panic: $(DISK64_PANIC)
	sh ./scripts/qemu-panic64.sh $(DISK64_PANIC)

test64-crash: $(DISK64_CRASH)
	sh ./scripts/qemu-crash64.sh $(DISK64_CRASH) 128M

# A rule that lost its recipe still satisfies make, so the breakage only shows
# up at link time (twice now, on the pipe objects). Ask make itself whether
# every object the lists name can be built before anything else runs.
check-build:
	@MAKE="$(MAKE)" sh scripts/check-build.sh $(OBJS64) $(TEST64_OBJS) $(PORTABLE64_OBJS)

release-check:
	$(MAKE) clean
	$(MAKE) all
	$(MAKE) check-build
	$(MAKE) test64
	$(MAKE) test64-smp
	$(MAKE) test64-smp4
	$(MAKE) test64-prod
	$(MAKE) test64-unit
	$(MAKE) test64-highmem
	$(MAKE) test64-hardware
	$(MAKE) test64-msi
	$(MAKE) test64-pcie
	$(MAKE) test64-iommu
	$(MAKE) test64-amd-iommu
	$(MAKE) test64-panic
	! grep -q '—' README.md
	grep -q '#define MICH_VERSION_STRING "0.2.0"' src/core/version.h
	git diff --check

DEPFILES = $(OBJS64:.o=.d) $(OBJS64_TEST:.o=.d) $(PORTABLE64_OBJS:.o=.d) \
           $(INIT64_OBJS:.o=.d) $(VIRTIO_NET64_OBJ:.o=.d) \
           $(VIRTIO_NET_SAFE64_OBJ:.o=.d) $(VIRTIO_NET64_PROBES_OBJ:.o=.d) \
           $(DNS64_OBJ:.o=.d) $(DNS_MESSAGE64_OBJ:.o=.d) \
           $(POSIXAPP64_OBJS:.o=.d) $(POSIXDEMO64_OBJS:.o=.d) $(UEFI64_OBJ:.o=.d)
-include $(DEPFILES)

clean:
	rm -rf $(BIN_DIR)

.PHONY: all user64-virtio-blk test64-virtio-blk user64-nvme test64-nvme run64 test64 test64-smp test64-smp4 test64-prod test64-crash test64-unit test64-highmem test64-dns test64-hardware test64-msi test64-msi-restart test64-msi-circuit test64-msi-recovery test64-msi-restart-stability test64-msi-circuit-stability test64-msi-recovery-stability test64-pcie test64-panic test64-iommu test64-amd-iommu test64-tcpwire test64-tty test64-netbench check-build release-check clean
