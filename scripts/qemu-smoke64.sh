#!/bin/sh
set -eu
image="${1:-bin/x86_64/disk.img}"
memory="${2:-128M}"
profile="${3:-default}"
qemu_timeout=45
# The crypto known-answer tests run before the profile-specific ones, and the
# RSA modular exponentiations are the slowest thing in the boot under TCG.
if [ "$profile" = "smp" ] || [ "$profile" = "iommu" ]; then qemu_timeout=130; fi
if [ "$profile" = "msi" ]; then qemu_timeout=300; fi
if [ "$profile" = "dns" ]; then qemu_timeout=150; fi
if [ "$profile" = "netbench" ]; then qemu_timeout=300; fi
if [ "$profile" = "tcpwire" ]; then qemu_timeout=300; fi
if [ "$profile" = "virtio-blk" ]; then qemu_timeout=120; fi
# The tty profile's passing run lands close to the old 60 second budget, which
# truncated good runs on slower hosts mid-log rather than failing them.
if [ "$profile" = "tty" ]; then qemu_timeout=120; fi
if [ "$profile" = "nvme" ]; then qemu_timeout=300; fi
if [ "$profile" = "msi-restart" ] || [ "$profile" = "msi-circuit" ] ||
   [ "$profile" = "msi-recovery" ]; then
    qemu_timeout=360
fi
# OVMF spends a few seconds enumerating devices and probing the boot order
# before it hands over, which the old BIOS path did not.
qemu_timeout=$((qemu_timeout + 25))
# KVM is opt-in via MICH_KVM: CI runs TCG, but a developer on a KVM box exports
# MICH_KVM=1 to get real host cycles out of the rdtsc benchmark instead of the
# emulator's. -cpu host is required so the guest reads the real TSC and sees the
# AES-NI the crypto boot tests use. MICH_QEMU_TIMEOUT overrides the per-profile
# budget, since a KVM run finishes in seconds where TCG needs minutes.
accel_cpu="-cpu qemu64,+aes,+pclmulqdq,+ssse3"
if [ -n "${MICH_KVM:-}" ]; then accel_cpu="-enable-kvm -cpu host"; fi
if [ -n "${MICH_QEMU_TIMEOUT:-}" ]; then qemu_timeout="$MICH_QEMU_TIMEOUT"; fi
# The smp profile defaults to two CPUs; the local stress runs ask for more
# with MICH_SMP_CPUS. Sixteen is the ceiling the xAPIC destination byte and
# the per-CPU tables allow, so a larger request is refused up front.
if [ -n "${MICH_SMP_CPUS:-}" ]; then
    case "$MICH_SMP_CPUS" in
        *[!0-9]*|'') echo "MICH_SMP_CPUS must be a number" >&2; exit 1 ;;
    esac
    if [ "$MICH_SMP_CPUS" -lt 2 ] || [ "$MICH_SMP_CPUS" -gt 16 ]; then
        echo "MICH_SMP_CPUS must be between 2 and 16" >&2
        exit 1
    fi
fi
# The serial log is a temp that the exit trap deletes, so a clean run drops the
# guest report (throughput lines, wire-tx offsets) it never printed. Set
# MICH_KEEP_LOG to a path to keep a copy for inspection on both pass and fail.
keep_log="${MICH_KEEP_LOG:-}"
passive_result=""
passive_pid=""
passive_expected=0
tty_socket=""
tty_result=""
tty_peer_pid=""
active_result=""
recovery_guestfwd=""
dns_guestfwd=""
netbench_peer_pid=""
netbench_peer_bin=""
netbench_peer_log=""
# The firmware needs a machine with a working pflash pair, so every profile
# runs on q35 now. Profiles that used to ask for it no longer add their own
# -machine.
want_nic_none=1
case "$profile" in
    msi|msi-restart|msi-circuit)
        want_nic_none=0
        set -- -netdev user,id=michnet,guestfwd=tcp:10.0.2.4:8080-cmd:/bin/cat,hostfwd=tcp:127.0.0.1:10080-10.0.2.15:8082 -device virtio-net-pci,netdev=michnet
        ;;
    dns)
        want_nic_none=0
        dns_guestfwd="$(mktemp)"
        set -- -netdev user,id=michnet,guestfwd=tcp:10.0.2.4:53-cmd:$dns_guestfwd -device virtio-net-pci,netdev=michnet
        ;;
    tcpwire)
        want_nic_none=0
        # The host side of the demo is plain cat, so the guest exchange is a
        # byte-exact echo; no helper script or host socket is involved.
        set -- -netdev user,id=michnet,guestfwd=tcp:10.0.2.4:8080-cmd:/bin/cat -device virtio-net-pci,netdev=michnet
        ;;
    netbench)
        want_nic_none=0
        # The benchmark runs its loopback pass first, then dials the host peer
        # over virtio-net for the wire pass. The peer is the same C program the
        # host-side self-test uses; slirp bridges the guest's fixed 10.0.2.4:4500
        # target to it, the way the dns profile bridges its resolver.
        netbench_peer_bin="$(mktemp)"
        netbench_peer_log="$(mktemp)"
        cc -O2 -o "$netbench_peer_bin" scripts/net-bench/peer.c
        "$netbench_peer_bin" --port 4500 >"$netbench_peer_log" 2>&1 &
        netbench_peer_pid=$!
        # Give it a moment to bind before QEMU tries to reach it.
        sleep 1
        if [ -n "${MICH_NET_TAP:-}" ]; then
            # tap+vhost topology: vhost moves the virtio datapath into the host
            # kernel and tap replaces slirp's userspace TCP, so the wire numbers
            # reflect the guest stack, not the emulator. The tap device, its host
            # address, and the guest's DHCP lease are set up by the caller
            # (scripts/net-bench/kvm-tap-bench.sh); the peer binds INADDR_ANY, so
            # it answers on the tap host address the guest dials.
            tap_if="${MICH_TAP_IF:-tap0}"
            set -- -netdev "tap,id=michnet,ifname=$tap_if,script=no,downscript=no,vhost=on" -device virtio-net-pci,netdev=michnet
        else
            set -- -netdev user,id=michnet,guestfwd=tcp:10.0.2.4:4500-tcp:127.0.0.1:4500 -device virtio-net-pci,netdev=michnet
        fi
        ;;
    msi-recovery)
        want_nic_none=0
        active_result="$(mktemp)"
        recovery_guestfwd="$(mktemp)"
        set -- -netdev user,id=michnet,guestfwd=tcp:10.0.2.4:8080-cmd:$recovery_guestfwd,hostfwd=tcp:127.0.0.1:10080-10.0.2.15:8082 -device virtio-net-pci,netdev=michnet
        ;;
    pcie)
        set --
        ;;
    tty)
        # The console wire profile: the guest's second serial port is a
        # socket the host peer owns, which is where the typed line enters
        # the machine. The console itself keeps the file log every profile
        # uses, because a QEMU socket chardev drops guest output when its
        # buffer fills and a log with holes cannot gate a run.
        tty_socket="$(mktemp -u /tmp/mich-tty-XXXXXX.sock)"
        tty_result="$(mktemp)"
        set -- -chardev socket,id=michwire,path="$tty_socket",server=on,wait=on \
            -serial chardev:michwire
        ;;
    iommu)
        set -- -device intel-iommu,intremap=off -device edu
        ;;
    amd-iommu)
        set -- -device amd-iommu,intremap=off
        ;;
    smp)
        set -- -smp "${MICH_SMP_CPUS:-2}"
        ;;
    *)
        set --
        ;;
esac
log="$(mktemp)"
# Fail loudly naming the exact marker that was missing. The old inline check
# dumped the whole serial log with no hint which expectation broke, so a missing
# line meant reading hundreds of lines to guess what the gate wanted.
require_marker() {
    if ! grep -Fq "$1" "$log"; then
        echo "SMOKE FAIL: expected marker not found in serial log:" >&2
        echo "  $1" >&2
        echo "--- full serial log follows ---" >&2
        cat "$log" >&2
        exit 1
    fi
}
# QEMU 11.x full-buffers a stdio serial that is redirected to a file and drops
# the buffer when timeout(1) delivers SIGTERM, so a fast KVM guest that finishes
# early and idles to the deadline leaves an empty log. -serial file: writes the
# guest console unbuffered, and qemu's own diagnostics get their own sink so the
# two writers never clobber the same fd.
qemu_diag="$(mktemp)"
if [ "$profile" = "msi" ] || [ "$profile" = "msi-restart" ] ||
   [ "$profile" = "msi-circuit" ] || [ "$profile" = "msi-recovery" ]; then
    passive_result="$(mktemp)"
    if [ "$profile" = "msi-restart" ]; then passive_expected=2; else passive_expected=1; fi
    python3 - "$passive_result" "$qemu_timeout" "$log" "$passive_expected" <<'PY' &
import os
import socket
import sys
import time

result, timeout, log, expected = sys.argv[1:]
deadline = time.monotonic() + int(timeout)
ready_marker = "Mich virtio-net: passive listener ready"
trace_path = os.environ.get("MICH_QEMU_PASSIVE_TRACE")
trace_start = time.monotonic()

def trace(event):
    if not trace_path:
        return
    try:
        with open(trace_path, "a", encoding="ascii") as output:
            elapsed = time.monotonic() - trace_start
            output.write(f"{elapsed:.3f}s {event}\n")
    except OSError:
        pass

expected = int(expected)
completed = 0
observed_ready = 0
trace("passive peer started")
while time.monotonic() < deadline:
    try:
        with open(log, "r", encoding="ascii", errors="replace") as input:
            ready = input.read().count(ready_marker)
    except OSError:
        ready = 0
    if ready > observed_ready:
        observed_ready = ready
        trace(f"serial passive listener count={ready}")
    if ready <= completed:
        time.sleep(0.1)
        continue
    connection = None
    try:
        trace(f"passive session {completed + 1} connect")
        connection = socket.create_connection(("127.0.0.1", 10080), 0.2)
        connection.settimeout(0.2)
        connection.sendall(b"PASSIVE")
        trace(f"passive session {completed + 1} sent")
        data = b""
        while len(data) < 7 and time.monotonic() < deadline:
            try:
                chunk = connection.recv(7 - len(data))
            except socket.timeout:
                continue
            if not chunk:
                break
            data += chunk
        trace(f"passive session {completed + 1} received={data!r}")
        if data == b"PASSIVE":
            completed += 1
            if completed == expected:
                with open(result, "w", encoding="ascii") as output:
                    output.write("PASS")
                trace("passive peer pass")
                break
    except OSError as error:
        trace(f"passive session {completed + 1} error={error.__class__.__name__}")
    finally:
        if connection is not None:
            connection.close()
    time.sleep(0.1)
trace(f"passive peer deadline completed={completed}")
PY
    passive_pid=$!
fi
if [ "$profile" = "tty" ]; then
    # The peer is the keyboard: it watches the log for the guest's ready
    # marker and types the line the parked read waits for.
    python3 ./scripts/tty-wire-peer.py "$tty_socket" "$log" "$tty_result" &
    tty_peer_pid=$!
fi
if [ "$profile" = "msi-recovery" ]; then
    cat >"$recovery_guestfwd" <<'PYHELPER'
#!/usr/bin/env python3
import os

result = os.environ.get("MICH_RECOVERY_ACTIVE_RESULT")
log = os.environ.get("MICH_RECOVERY_LOG")
seen = False
while True:
    data = os.read(0, 4096)
    if not data:
        break
    if not seen:
        seen = True
        if result and log:
            try:
                selected = "Mich virtio-net: recovery artifact selected" in \
                    open(log, "r", encoding="ascii", errors="replace").read()
            except OSError:
                selected = False
            if selected:
                with open(result, "w", encoding="ascii") as output:
                    output.write("PASS")
    view = memoryview(data)
    while view:
        written = os.write(1, view)
        view = view[written:]
PYHELPER
    chmod 700 "$recovery_guestfwd"
    export MICH_RECOVERY_ACTIVE_RESULT="$active_result"
    export MICH_RECOVERY_LOG="$log"
fi
if [ "$profile" = "dns" ]; then
    cat >"$dns_guestfwd" <<'PYHELPER'
#!/usr/bin/env python3
# One DNS exchange over the QEMU guest forward. QEMU runs this per accepted
# connection with the socket on stdin/stdout, so it answers once and exits.
# Only TCP reaches here: guestfwd has no UDP form, which is exactly what makes
# the guest burn its UDP retries before falling back.
import os
import sys

ANSWERS = {b"probe.mich": bytes((192, 0, 2, 77))}


def read_exactly(count):
    data = b""
    while len(data) < count:
        chunk = os.read(0, count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def parse_question(message):
    if len(message) < 12:
        return None, None
    offset = 12
    labels = []
    while offset < len(message):
        length = message[offset]
        offset += 1
        if not length:
            break
        if length > 63 or offset + length > len(message):
            return None, None
        labels.append(message[offset:offset + length])
        offset += length
    if offset + 4 > len(message):
        return None, None
    return b".".join(labels), offset + 4


prefix = read_exactly(2)
if not prefix:
    sys.exit(0)
query = read_exactly((prefix[0] << 8) | prefix[1])
if not query:
    sys.exit(0)
name, question_end = parse_question(query)
if name is None:
    sys.exit(0)

header = query[:2]
address = ANSWERS.get(name.lower())
if address is None:
    # NXDOMAIN: the guest has to treat this as a failure, not as an answer.
    reply = header + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    reply += query[12:question_end]
else:
    reply = header + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    reply += query[12:question_end]
    # Name compression pointer back to the question, then A/IN, TTL 60.
    reply += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + address

framed = bytes(((len(reply) >> 8) & 0xFF, len(reply) & 0xFF)) + reply
view = memoryview(framed)
while view:
    written = os.write(1, view)
    view = view[written:]
# Exiting here would tear the forward down before the guest has drained the
# reply, so hold the connection until the guest closes its side.
while os.read(0, 4096):
    pass
PYHELPER
    chmod 700 "$dns_guestfwd"
fi
blk_img="$(mktemp)"
dd if=/dev/zero of="$blk_img" bs=512 count=256 2>/dev/null
nvme_img="$(mktemp)"
dd if=/dev/zero of="$nvme_img" bs=1M count=16 2>/dev/null
. "$(dirname "$0")/uefi-firmware.sh"
mich_uefi_firmware
if [ "$want_nic_none" -eq 1 ]; then
    set -- "$@" -nic none
fi
trap 'if [ -n "$keep_log" ] && [ -f "$log" ]; then cp "$log" "$keep_log" 2>/dev/null || true; fi; if [ -n "$passive_pid" ]; then kill "$passive_pid" 2>/dev/null || true; fi; if [ -n "$netbench_peer_pid" ]; then kill "$netbench_peer_pid" 2>/dev/null || true; fi; if [ -n "$tty_peer_pid" ]; then kill "$tty_peer_pid" 2>/dev/null || true; fi; rm -f "$netbench_peer_bin" "$netbench_peer_log" "$log" "$qemu_diag" "$passive_result" "$active_result" "$recovery_guestfwd" "$dns_guestfwd" "$blk_img" "$tty_socket" "$tty_result" "$nvme_img" "$uefi_vars"' EXIT
set +e
timeout "${qemu_timeout}s" qemu-system-x86_64 \
    -machine q35 \
    $accel_cpu \
    -drive if=pflash,format=raw,readonly=on,file="$uefi_code" \
    -drive if=pflash,format=raw,file="$uefi_vars" \
    -drive file="$image",format=raw,if=none,id=esdisk \
    -device ide-hd,drive=esdisk,bootindex=1 \
    -drive file="$blk_img",format=raw,if=none,id=michblk \
    -device virtio-blk-pci,drive=michblk,disable-legacy=on \
    -drive file="$nvme_img",format=raw,if=none,id=michnvme \
    -device nvme,drive=michnvme,serial=michx0 \
    -m "$memory" \
    -serial file:"$log" \
    -vga std \
    -display none \
    -no-reboot \
    -no-shutdown \
    "$@" >"$qemu_diag" 2>&1
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
    cat "$qemu_diag"
    cat "$log"
    exit 1
fi
# The netbench profile boots a deliberately quiescent kernel: it skips the
# driver-live-recovery lab so that lab cannot perturb the loopback timing or
# pollute the cycle counts. That same lab is what the init role-1/2 CI battery
# is wired to run behind, so it does not execute here either. This profile is
# therefore gated on boot-essential plus net plus netbench markers only; the
# full init battery stays covered by the disk-test and dns profiles.
if [ "$profile" = "netbench" ]; then
    for marker in \
        "Mich Core 0.2.0 x86_64: long mode alive" \
        "Mich x86_64: GDT and TSS alive" \
        "Mich x86_64: IDT alive" \
        "Mich x86_64: panic subsystem ready" \
        "Mich x86_64: E820 PMM alive" \
        "Mich x86_64: ACPI tables pass" \
        "Mich x86_64: PCI enumeration pass" \
        "Mich x86_64: LAPIC controller pass" \
        "Mich x86_64: IOAPIC routing pass" \
        "Mich x86_64: APIC timer pass" \
        "Mich x86_64: preemptive scheduler pass" \
        "Mich virtio-net: bootstrap pass" \
        "Mich virtio-net: DRIVER_OK pass" \
        "Mich virtio-net: userspace capsule running" \
        "Mich test64: netbench baseline report pass"
    do
        require_marker "$marker"
    done
elif [ "$profile" = "virtio-blk" ]; then
    # This boots the production kernel, which carries no in-kernel virtio-blk
    # driver and no test64 battery; the capsule is the driver. The full init
    # battery assumes it is the only userspace task, so a resident capsule makes
    # its later stages nondeterministic; that battery is covered by the disk-test
    # profile. Here we gate on boot-essential markers plus the capsule bringing
    # the real device up and reaching its serve state.
    for marker in \
        "Mich Core 0.2.0 x86_64: long mode alive" \
        "Mich x86_64: GDT and TSS alive" \
        "Mich x86_64: IDT alive" \
        "Mich x86_64: panic subsystem ready" \
        "Mich x86_64: E820 PMM alive" \
        "Mich x86_64: ACPI tables pass" \
        "Mich x86_64: PCI enumeration pass" \
        "Mich x86_64: LAPIC controller pass" \
        "Mich x86_64: IOAPIC routing pass" \
        "Mich x86_64: APIC timer pass" \
        "Mich x86_64: preemptive scheduler pass" \
        "Mich virtio-blk: bootstrap pass" \
        "Mich virtio-blk: serve pass"
    do
        require_marker "$marker"
    done
elif [ "$profile" = "nvme" ]; then
    # Same reduced gate as virtio-blk: the production kernel carries no in-kernel
    # NVMe driver and no test64 battery, so the capsule is the driver. Gate on
    # boot-essential markers plus the capsule bringing the real controller up and
    # reaching its serve state.
    for marker in \
        "Mich Core 0.2.0 x86_64: long mode alive" \
        "Mich x86_64: GDT and TSS alive" \
        "Mich x86_64: IDT alive" \
        "Mich x86_64: panic subsystem ready" \
        "Mich x86_64: E820 PMM alive" \
        "Mich x86_64: ACPI tables pass" \
        "Mich x86_64: PCI enumeration pass" \
        "Mich x86_64: LAPIC controller pass" \
        "Mich x86_64: IOAPIC routing pass" \
        "Mich x86_64: APIC timer pass" \
        "Mich x86_64: preemptive scheduler pass" \
        "Mich nvme: bootstrap pass" \
        "Mich nvme: serve pass"
    do
        require_marker "$marker"
    done
elif [ "$profile" = "dns" ]; then
    # Same network composition as tcpwire with the resolver capsule instead,
    # so the same reasoning applies: no init userspace battery to ask for
    # (disk-test covers it), and the gate names the wire path plus the
    # resolver behaviour the profile exists to prove.
    for marker in \
        "Mich Core 0.2.0 x86_64: long mode alive" \
        "Mich x86_64: GDT and TSS alive" \
        "Mich x86_64: IDT alive" \
        "Mich x86_64: panic subsystem ready" \
        "Mich x86_64: E820 PMM alive" \
        "Mich x86_64: ACPI tables pass" \
        "Mich x86_64: PCI enumeration pass" \
        "Mich x86_64: LAPIC controller pass" \
        "Mich x86_64: IOAPIC routing pass" \
        "Mich x86_64: APIC timer pass" \
        "Mich x86_64: preemptive scheduler pass" \
        "Mich virtio-net: bootstrap pass" \
        "Mich virtio-net: feature negotiation pass" \
        "Mich virtio-net: stable device config pass" \
        "Mich virtio-net: RX and TX queue setup pass" \
        "Mich virtio-net: MSI-X queue vectors pass" \
        "Mich virtio-net: RX buffers published" \
        "Mich virtio-net: DRIVER_OK pass" \
        "Mich virtio-net: network interface registered" \
        "Mich virtio-net: userspace capsule running" \
        "Mich virtio-net: real RX completion pass" \
        "Mich virtio-net: real TX completion pass" \
        "Mich virtio-net: batched RX/TX datapath pass" \
        "Mich virtio-net: adaptive interrupt moderation pass" \
        "Mich virtio-net: interrupt-driven RX/TX pass" \
        "Mich virtio-net: DHCP Offer receive pass" \
        "Mich virtio-net: DHCP Request transmit pass" \
        "Mich virtio-net: DHCP ACK receive pass" \
        "Mich virtio-net: DHCP IPv4 lease applied" \
        "Mich virtio-net: external ping reply pass" \
        "Mich virtio-net: external UDP reply pass" \
        "Mich virtio-net: external IPv6 DAD pass" \
        "Mich virtio-net: external IPv6 RA and SLAAC pass" \
        "Mich virtio-net: external IPv6 ping reply pass" \
        "Mich virtio-net: external UDPv6 ICMP error pass" \
        "Mich dnsprobe: resolver ready" \
        "Mich dnsprobe: transport pass" \
        "Mich dnsprobe: TCP fallback and framing pass" \
        "Mich dnsprobe: cached answer pass" \
        "Mich dnsprobe: refused name rejected pass"
    do
        require_marker "$marker"
    done
elif [ "$profile" = "tcpwire" ]; then
    # This image boots the network composition (init plus the virtio-net and
    # tcpwire capsules), so it runs the in-kernel net battery and the external
    # lab but never the init userspace battery that the disk-test profile
    # covers. Asking for those markers here failed on a line the image was
    # never built to print, so this gate is boot-essential plus the wire path
    # the profile exists to prove.
    for marker in \
        "Mich Core 0.2.0 x86_64: long mode alive" \
        "Mich x86_64: GDT and TSS alive" \
        "Mich x86_64: IDT alive" \
        "Mich x86_64: panic subsystem ready" \
        "Mich x86_64: E820 PMM alive" \
        "Mich x86_64: ACPI tables pass" \
        "Mich x86_64: PCI enumeration pass" \
        "Mich x86_64: LAPIC controller pass" \
        "Mich x86_64: IOAPIC routing pass" \
        "Mich x86_64: APIC timer pass" \
        "Mich x86_64: preemptive scheduler pass" \
        "Mich virtio-net: bootstrap pass" \
        "Mich virtio-net: feature negotiation pass" \
        "Mich virtio-net: stable device config pass" \
        "Mich virtio-net: RX and TX queue setup pass" \
        "Mich virtio-net: MSI-X queue vectors pass" \
        "Mich virtio-net: RX buffers published" \
        "Mich virtio-net: DRIVER_OK pass" \
        "Mich virtio-net: network interface registered" \
        "Mich virtio-net: userspace capsule running" \
        "Mich virtio-net: real RX completion pass" \
        "Mich virtio-net: real TX completion pass" \
        "Mich virtio-net: batched RX/TX datapath pass" \
        "Mich virtio-net: adaptive interrupt moderation pass" \
        "Mich virtio-net: interrupt-driven RX/TX pass" \
        "Mich virtio-net: DHCP Offer receive pass" \
        "Mich virtio-net: DHCP Request transmit pass" \
        "Mich virtio-net: DHCP ACK receive pass" \
        "Mich virtio-net: DHCP IPv4 lease applied" \
        "Mich virtio-net: stream socket connect queued" \
        "Mich virtio-net: stream socket send pass" \
        "Mich virtio-net: stream socket receive pass" \
        "Mich virtio-net: stream socket shutdown pass" \
        "Mich virtio-net: TCP stream soak pass" \
        "Mich virtio-net: external ping reply pass" \
        "Mich virtio-net: external UDP reply pass" \
        "Mich virtio-net: external socket UDP reply pass" \
        "Mich virtio-net: external TCP handshake and echo pass" \
        "Mich virtio-net: external TCP FIN lifecycle pass" \
        "Mich virtio-net: external IPv6 DAD pass" \
        "Mich virtio-net: external IPv6 RA and SLAAC pass" \
        "Mich virtio-net: IPv6 lifecycle timer pass" \
        "Mich virtio-net: external IPv6 ping reply pass" \
        "Mich virtio-net: external UDPv6 ICMP error pass"
    do
        require_marker "$marker"
    done
else
for marker in \
    "Mich Core 0.2.0 x86_64: long mode alive" \
    "Mich x86_64: GDT and TSS alive" \
    "Mich x86_64: IDT alive" \
    "Mich x86_64: panic subsystem ready" \
    "Mich x86_64: E820 PMM alive" \
    "Mich x86_64: ACPI tables pass" \
    "Mich x86_64: platform MMIO objects pass" \
    "Mich x86_64: PCI enumeration pass" \
    "Mich test64: driver module core pass" \
    "Mich test64: driver manifest pass" \
    "Mich test64: driver dependency order pass" \
    "Mich test64: driver restart policy pass" \
    "Mich test64: device removal pass" \
    "Mich test64: driver supervisor pass" \
    "Mich test64: driver crash teardown pass" \
    "Mich test64: driver crash passport pass" \
    "Mich test64: driver crash circuit breaker pass" \
    "Mich test64: driver crash policy pass" \
    "Mich test64: driver recovery decision matrix pass" \
    "Mich test64: trigger policy pass" \
    "Mich test64: driver recovery fallback pass" \
    "Mich test64: driver recovery selector pass" \
    "Mich test64: driver IOMMU crash quarantine pass" \
    "Mich test64: atomic driver bundle pass" \
    "Mich test64: userspace driver manifest pass" \
    "Mich test64: firmware manifest allowlist pass" \
    "Mich test64: driver bootstrap ABI pass" \
    "Mich test64: IRQ bootstrap source pass" \
    "Mich x86_64: driver bootstrap access pass" \
    "Mich x86_64: firmware domain isolation pass" \
    "Mich test64: userspace driver manager pass" \
    "Mich test64: driver scheduler weight pass" \
    "Mich test64: driver manifest priority pass" \
    "Mich test64: driver manifest fallback pass" \
    "Mich test64: driver dependency graph pass" \
    "Mich test64: automatic PCI driver binding pass" \
    "Mich test64: PCI FLR abstraction pass" \
    "Mich test64: driver reset policy pass" \
    "Mich test64: driver crash stress pass" \
    "Mich test64: graceful driver stop pass" \
    "Mich test64: driver stop timeout fallback pass" \
    "Mich test64: firmware crash handle revoke pass" \
    "Mich test64: IRQ teardown race pass" \
    "Mich test64: driver resource accounting pass" \
    "Mich x86_64: LAPIC controller pass" \
    "Mich x86_64: IOAPIC routing pass" \
    "Mich x86_64: legacy PIC disabled" \
    "Mich x86_64: APIC timer pass" \
    "Mich test64: MSI vector allocator pass" \
    "Mich test64: MSI programming API pass" \
    "Mich test64: MSI-X table object pass" \
    "Mich test64: MSI-X programming API pass" \
    "Mich test64: multi-vector IRQ groups pass" \
    "Mich test64: atomic vector rollback pass" \
    "Mich test64: IRQ event binding pass" \
    "Mich test64: safe IRQ unmask pass" \
    "Mich test64: IRQ endpoint binding pass" \
    "Mich test64: Driver Bridge endpoint pass" \
    "Mich x86_64: PML4 address space alive" \
    "Mich test64: kernel object layer pass" \
    "Mich test64: 24-bit handle generation stress pass" \
    "Mich test64: VFS vnode and mount objects pass" \
    "Mich test64: VFS ramfs backend pass" \
    "Mich test64: VFS immutable bootfs pass" \
    "Mich test64: VFS mount traversal pass" \
    "Mich test64: firmware lookup service pass" \
    "Mich test64: VFS file lifetime pass" \
    "Mich test64: VFS unlink-open semantics pass" \
    "Mich test64: VFS append transaction pass" \
    "Mich test64: VFS absolute and relative paths pass" \
    "Mich test64: VFS root escape protection pass" \
    "Mich test64: VFS path component bounds pass" \
    "Mich test64: VFS path mutation stress pass" \
    "Mich test64: VFS page-backed files pass" \
    "Mich test64: POSIX FD/OFD substrate pass" \
    "Mich test64: POSIX FD lifecycle cleanup pass" \
    "Mich test64: POSIX VFS authority and mode pass" \
    "Mich test64: POSIX process stack layout pass" \
    "Mich test64: POSIX clocks and sleep pass" \
    "Mich test64: POSIX poll readiness pass" \
    "Mich test64: block device objects pass" \
    "Mich test64: ramdisk read and write pass" \
    "Mich test64: block request generation pass" \
    "Mich test64: block bounds and revoke pass" \
    "Mich test64: ChaCha20 DRBG pass" \
    "Mich test64: RTC civil date conversion pass" \
    "Mich x86_64: wall clock anchored" \
    "Mich test64: crc32c and little-endian helpers pass" \
    "Mich test64: BLAKE2b pass" \
    "Mich test64: adytumfs superblock pass" \
    "Mich test64: adytumfs format pass" \
    "Mich test64: adytumfs block allocator pass" \
    "Mich test64: adytumfs inode table pass" \
    "Mich test64: adytumfs extents pass" \
    "Mich test64: adytumfs directories pass" \
    "Mich test64: adytumfs directory iteration pass" \
    "Mich test64: adytumfs file read write pass" \
    "Mich test64: adytumfs path operations pass" \
    "Mich test64: adytumfs format and mount pass" \
    "Mich test64: adytumfs file io pass" \
    "Mich x86_64: fsbench bytes=" \
    "Mich test64: calibrated time base pass" \
    "Mich test64: task runtime accounting pass" \
    "Mich test64: eevdf policy pass" \
    "Mich test64: adytumfs busy unmount lifetime pass" \
    "Mich test64: adytumfs stale vnode generation pass" \
    "Mich test64: resource object layer pass" \
    "Mich test64: page and shared memory objects pass" \
    "Mich test64: page grow and trim pass" \
    "Mich test64: scatter-gather objects pass" \
    "Mich test64: scatter-gather rollback pass" \
    "Mich test64: shared zero-copy rings pass" \
    "Mich test64: ring index validation pass" \
    "Mich test64: ring generation revoke pass" \
    "Mich test64: completion objects pass" \
    "Mich test64: completion cancel and timeout pass" \
    "Mich test64: timer objects pass" \
    "Mich test64: wait-many pass" \
    "Mich test64: packet page pools pass" \
    "Mich test64: virtual benchmark NIC pass" \
    "Mich test64: malformed packet descriptor rejected" \
    "Mich test64: packet hot path allocation-free pass" \
    "Mich test64: cycles-per-packet harness pass" \
    "Mich test64: netbench baseline report pass" \
    "Mich test64: Ethernet parser pass" \
    "Mich test64: Ethernet MAC filter pass" \
    "Mich test64: Ethernet VLAN detection pass" \
    "Mich test64: EtherType dispatch pass" \
    "Mich test64: malformed Ethernet frames rejected" \
    "Mich test64: Ethernet batch path pass" \
    "Mich test64: ARP request and reply pass" \
    "Mich test64: ARP neighbor cache pass" \
    "Mich test64: ARP expiration pass" \
    "Mich test64: ARP rate limit pass" \
    "Mich test64: ARP reply flood bound pass" \
    "Mich test64: ARP conflict detection pass" \
    "Mich test64: malformed ARP packets rejected" \
    "Mich test64: IPv4 header validation pass" \
    "Mich test64: IPv4 checksum pass" \
    "Mich test64: IPv4 local filtering pass" \
    "Mich test64: IPv4 land attack rejected" \
    "Mich test64: IPv4 spoofed source rejected" \
    "Mich test64: IPv4 protocol dispatch pass" \
    "Mich test64: IPv4 options bounds pass" \
    "Mich test64: IPv4 fragments rejected" \
    "Mich test64: malformed IPv4 packets rejected" \
    "Mich test64: IPv4 transmit path pass" \
    "Mich test64: IPv6 fixed header validation pass" \
    "Mich test64: IPv6 extension header bounds pass" \
    "Mich test64: IPv6 multicast filtering pass" \
    "Mich test64: IPv6 land attack rejected" \
    "Mich test64: IPv6 spoofed source rejected" \
    "Mich test64: IPv6 fragments rejected" \
    "Mich test64: malformed IPv6 packets rejected" \
    "Mich test64: IPv6 link-local address pass" \
    "Mich test64: IPv6 solicited-node multicast pass" \
    "Mich test64: ICMPv6 checksum pass" \
    "Mich test64: ICMPv6 echo pass" \
    "Mich test64: ICMPv6 Packet Too Big pass" \
    "Mich test64: IPv6 Path MTU cache pass" \
    "Mich test64: NDP neighbor discovery pass" \
    "Mich test64: IPv6 duplicate address detection pass" \
    "Mich test64: IPv6 router advertisement pass" \
    "Mich test64: UDPv6 checksum pass" \
    "Mich test64: UDPv6 binding and delivery pass" \
    "Mich test64: UDPv6 ephemeral ports pass" \
    "Mich test64: TCP header and option validation pass" \
    "Mich test64: TCP checksum pass" \
    "Mich test64: TCPv6 checksum and builder pass" \
    "Mich test64: TCPv6 active handshake pass" \
    "Mich test64: TCPv6 passive accept pass" \
    "Mich test64: TCPv6 stream receive pass" \
    "Mich test64: TCP three-way handshake pass" \
    "Mich test64: TCP sequence validation pass" \
    "Mich test64: TCP invalid-sequence RST challenge pass" \
    "Mich test64: TCP retransmission timer pass" \
    "Mich test64: TCP send and receive buffers pass" \
    "Mich test64: TCP out-of-order merge pass" \
    "Mich test64: TCP congestion window foundation pass" \
    "Mich test64: TCP passive accept queue pass" \
    "Mich test64: TCP FIN and TIME-WAIT foundation pass" \
    "Mich test64: TCP connection churn stress pass" \
    "Mich test64: TCP retry exhaustion pass" \
    "Mich test64: TCP persist timer pass" \
    "Mich test64: TCP RTT estimator foundation pass" \
    "Mich test64: TCP EOF and readiness foundation pass" \
    "Mich test64: TCP SO_ERROR pass" \
    "Mich test64: TCP SYN flood bound pass" \
    "Mich test64: TCP mutation stress pass" \
    "Mich test64: TCP path MTU clamp pass" \
    "Mich test64: TCP PMTU blackhole pass" \
    "Mich test64: TCP page send pass" \
    "Mich test64: socket send file pass" \
    "Mich test64: socket receive file pass" \
    "Mich test64: socket send adytumfs file pass" \
    "Mich test64: adytumfs page-backed write-back pass" \
    "Mich test64: adytumfs mount policies pass" \
    "Mich test64: adytumfs slot reuse pass" \
    "Mich test64: adytumfs mount integrity pass" \
    "Mich test64: adytumfs data checksum pass" \
    "Mich test64: adytumfs copy-on-write pass" \
    "Mich test64: adytumfs crash windows pass" \
    "Mich test64: nvme controller and prp io pass" \
    "Mich test64: nvme scatter-gather io pass" \
    "Mich test64: nvme msi-x completion wake pass" \
    "Mich test64: nvme adytumfs mount pass" \
    "Mich test64: ICMP checksum pass" \
    "Mich test64: ICMP echo request and reply pass" \
    "Mich test64: ICMP rate limit pass" \
    "Mich test64: ICMP Path MTU Discovery pass" \
    "Mich test64: ICMP broadcast suppression pass" \
    "Mich test64: virtual ping pass" \
    "Mich test64: malformed ICMP packets rejected" \
    "Mich test64: IPv4 loopback interface pass" \
    "Mich test64: loopback bypasses Ethernet and ARP" \
    "Mich test64: loopback virtual ping pass" \
    "Mich test64: loopback packet pool accounting pass" \
    "Mich test64: UDP checksum pass" \
    "Mich test64: UDP port binding pass" \
    "Mich test64: UDP bounded receive queue pass" \
    "Mich test64: UDP loopback delivery pass" \
    "Mich test64: UDP queue overflow pass" \
    "Mich test64: zero-copy UDP receive queue pass" \
    "Mich test64: queued UDP close reclaim pass" \
    "Mich test64: full-MTU UDP pass" \
    "Mich test64: ephemeral UDP ports pass" \
    "Mich test64: ICMP Port Unreachable pass" \
    "Mich test64: malformed UDP datagrams rejected" \
    "Mich test64: routing longest-prefix match pass" \
    "Mich test64: connected and default routes pass" \
    "Mich test64: UDP socket objects pass" \
    "Mich test64: UDP socket wait pass" \
    "Mich test64: UDP socket close cleanup pass" \
    "Mich test64: routed stream connect pass" \
    "Mich test64: socket close wakes waiters pass" \
    "Mich test64: network integration stress pass" \
    "Mich test64: VNIC queued revoke stress pass" \
    "Mich test64: packet pool exhaustion pass" \
    "Mich test64: stale packet IDs rejected" \
    "Mich test64: network revoke accounting pass" \
    "Mich test64: network interface registry pass" \
    "Mich test64: network interface ownership pass" \
    "Mich test64: network interface link state pass" \
    "Mich test64: network interface generation revoke pass" \
    "Mich test64: interface route deactivation pass" \
    "Mich test64: network parser mutation stress pass" \
    "Mich x86_64: network runtime ready" \
    "Mich test64: ioremap pass" \
    "Mich x86_64: syscall MSRs alive" \
    "Mich x86_64: external ELF64 init loaded" \
    "Mich x86_64: driver image registry pass" \
    "Mich x86_64: idle task alive" \
    "Mich x86_64: external init64 task one" \
    "Mich x86_64: external init64 task two" \
    "Mich x86_64: task pool pass" \
    "Mich x86_64: userspace runtime pass" \
    "Mich x86_64: ELF64 load pass" \
    "Mich x86_64: address spaces pass" \
    "Mich x86_64: FPU context pass" \
    "Mich x86_64: context switch pass" \
    "Mich x86_64: syscall/sysret pass" \
    "Mich x86_64: user exception contained" \
    "Mich x86_64: process lifecycle pass" \
    "Mich x86_64: E820 PMM pass" \
    "Mich x86_64: wait any pass" \
    "Mich x86_64: blocking wait pass" \
    "Mich x86_64: VM reclaim pass" \
    "Mich x86_64: fork child alive" \
    "Mich x86_64: fork pass" \
    "Mich x86_64: copy-on-write address isolation pass" \
    "Mich x86_64: exec pass" \
    "Mich x86_64: fresh FPU state pass" \
    "Mich x86_64: dynamic spawn pass" \
    "Mich x86_64: PID generation pass" \
    "Mich x86_64: resource reuse pass" \
    "Mich x86_64: capability grant pass" \
    "Mich x86_64: service cleanup pass" \
    "Mich x86_64: reparenting pass" \
    "Mich x86_64: orphan cleanup pass" \
    "Mich x86_64: kill permission pass" \
    "Mich x86_64: invalid syscall return contained" \
    "Mich x86_64: syscall return containment pass" \
    "Mich x86_64: killed child wait wake pass" \
    "Mich x86_64: blocking IPC pass" \
    "Mich x86_64: nonblocking IPC pass" \
    "Mich x86_64: IPC sender queue pass" \
    "Mich x86_64: IPC stale PID pass" \
    "Mich x86_64: IPC deadlock pass" \
    "Mich x86_64: IPC timeout pass" \
    "Mich x86_64: IPC death notification pass" \
    "Mich x86_64: IPC uaccess pass" \
    "Mich x86_64: lifecycle stress pass" \
    "Mich x86_64: event objects pass" \
    "Mich x86_64: event timeout pass" \
    "Mich x86_64: cross-process handle pass" \
    "Mich x86_64: atomic handle batch pass" \
    "Mich x86_64: Driver Bridge userspace pass" \
    "Mich x86_64: userspace IRQ handles pass" \
    "Mich x86_64: userspace VFS objects pass" \
    "Mich x86_64: userspace VFS read and write pass" \
    "Mich x86_64: userspace VFS unlink-open pass" \
    "Mich x86_64: userspace VFS path resolution pass" \
    "Mich x86_64: userspace VFS root clamp pass" \
    "Mich x86_64: userspace immutable bootfs pass" \
    "Mich x86_64: userspace block device pass" \
    "Mich x86_64: userspace deferred block io pass" \
    "Mich x86_64: userspace PCI handles pass" \
    "Mich x86_64: userspace BAR mapping pass" \
    "Mich x86_64: read-only resource mapping pass" \
    "Mich x86_64: userspace DMA mapping pass" \
    "Mich x86_64: userspace page objects pass" \
    "Mich x86_64: shared memory revoke pass" \
    "Mich x86_64: userspace scatter-gather pass" \
    "Mich x86_64: userspace shared ring pass" \
    "Mich x86_64: userspace ring corruption rejected" \
    "Mich x86_64: userspace completion objects pass" \
    "Mich x86_64: userspace timer objects pass" \
    "Mich x86_64: userspace wait-many pass" \
    "Mich x86_64: userspace packet pool pass" \
    "Mich x86_64: userspace virtual NIC pass" \
    "Mich x86_64: userspace packet benchmark pass" \
    "Mich x86_64: userspace UDP sockets pass" \
    "Mich x86_64: userspace full-MTU UDP pass" \
    "Mich x86_64: userspace ephemeral port pass" \
    "Mich x86_64: userspace socket wait timeout pass" \
    "Mich x86_64: userspace socket cleanup stress pass" \
    "Mich x86_64: service registry pass" \
    "Mich x86_64: capability state pass" \
    "Mich x86_64: preemptive scheduler pass"
do
    require_marker "$marker"
done
fi
# The hardware and msi profiles spawn init without the POSIX modules, so these
# markers can never appear there. Asking for them made those profiles fail on
# something the image was never built to do.
case "$profile" in
    hardware|msi|msi-restart|msi-circuit|msi-recovery|dns|netbench|tcpwire|virtio-blk|nvme)
        ;;
    *)
        for marker in \
            "Mich test64: POSIX profile cwd and authority pass" \
            "Mich x86_64: POSIX userspace facade pass" \
            "Mich x86_64: POSIX userspace process pass" \
            "Mich x86_64: POSIX application alive" \
            "Mich x86_64: POSIX application IO pass" \
            "Mich x86_64: POSIX application cwd pass" \
            "Mich x86_64: POSIX application errno pass" \
            "Mich x86_64: POSIX libc string pass" \
            "Mich x86_64: POSIX libc stdio pass" \
            "Mich x86_64: POSIX libc heap pass" \
            "Mich x86_64: POSIX libc file pass" \
            "Mich x86_64: POSIX entropy pass" \
            "Mich x86_64: POSIX application link pass" \
            "Mich x86_64: POSIX application rename pass" \
            "Mich x86_64: POSIX application symlink pass" \
            "Mich x86_64: POSIX application times pass" \
            "Mich x86_64: POSIX libc realpath pass" \
            "Mich x86_64: POSIX clocks pass" \
            "Mich x86_64: POSIX signals pass" \
            "Mich x86_64: POSIX sockets pass" \
            "Mich x86_64: POSIX poll pass" \
            "Mich x86_64: POSIX tty console pass" \
            "Mich x86_64: POSIX application process pass" \
            "Mich x86_64: POSIX pledge and unveil pass" \
            "Mich x86_64: POSIX pipes pass" \
            "Mich x86_64: POSIX static application pass"
        do
            require_marker "$marker"
        done
        ;;
esac
# The netbench and tcpwire profiles skip the driver-live-recovery lab, so none
# of its bootstrap markers exist there; every other profile runs the lab and
# must show the full crash-restart-fallback sequence in order. The virtio-blk
# profile boots the production kernel, which has no recovery lab, so it is
# excluded too.
if [ "$profile" != "netbench" ] && [ "$profile" != "virtio-blk" ] &&
   [ "$profile" != "nvme" ] && [ "$profile" != "tcpwire" ]; then
live_primary="Mich test64: driver live primary bootstrap pass"
    live_fallback="Mich test64: driver live fallback bootstrap pass"
    live_isolation="Mich test64: driver live recovery isolation pass"
    [ "$(grep -Fc "$live_primary" "$log")" -eq 2 ] &&
    [ "$(grep -Fc "$live_fallback" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "$live_isolation" "$log")" -eq 1 ] || {
        cat "$log"
        exit 1
    }
    primary_first="$(grep -Fn "$live_primary" "$log" | sed -n '1s/:.*//p')"
    primary_second="$(grep -Fn "$live_primary" "$log" | sed -n '2s/:.*//p')"
    fallback_line="$(grep -Fn "$live_fallback" "$log" | sed -n '1s/:.*//p')"
    isolation_line="$(grep -Fn "$live_isolation" "$log" | sed -n '1s/:.*//p')"
[ "$primary_first" -lt "$primary_second" ] &&
[ "$primary_second" -lt "$fallback_line" ] &&
[ "$fallback_line" -lt "$isolation_line" ] || {
    cat "$log"
    exit 1
}
fi
if [ "$profile" = "uefi" ]; then
    grep -Fq "BigDevBoot UEFI 0.2.0 by ukdaemonz" "$log" || {
        cat "$log"
        exit 1
    }
fi
if [ "$profile" = "highmem" ]; then
    grep -Fq "Mich x86_64: high memory identity pass" "$log" || {
        cat "$log"
        exit 1
    }
fi
if [ "$profile" = "smp" ]; then
    # The bring-up marker spells the CPU count it brought up, so the check
    # cannot pass on a log from a different -smp.
    expected_cpus=$(printf '%016X' "${MICH_SMP_CPUS:-2}")
    bench_cpus_1=$(printf '%016X' 1)
    bench_cpus_2=$(printf '%016X' 2)
    bench_cpus_4=$(printf '%016X' 4)
    for marker in \
        "Mich x86_64: SMP MADT enumeration pass" \
        "Mich x86_64: SMP per-CPU storage pass" \
        "Mich x86_64: SMP AP bring-up pass ($expected_cpus cpus online)" \
        "Mich x86_64: SMP IPI round-trip pass" \
        "Mich x86_64: SMP spinlock stress pass" \
        "Mich x86_64: SMP AP timer pass" \
        "Mich x86_64: SMP per-CPU TSS pass" \
        "Mich x86_64: SMP per-CPU current pass" \
        "Mich x86_64: SMP per-CPU syscall pass" \
        "Mich x86_64: SMP AP userspace pass" \
        "Mich x86_64: SMP AP user IRQ pass" \
        "Mich x86_64: SMP AP preempt pass" \
        "Mich x86_64: SMP AP live syscall pass" \
        "Mich x86_64: SMP AP scheduler pass" \
        "Mich x86_64: SMP AP pinned task pass" \
        "Mich x86_64: SMP AP syscall containment pass" \
        "Mich x86_64: SMP allocator concurrency pass" \
        "Mich x86_64: SMP refcount concurrency pass" \
        "Mich x86_64: SMP spawn storm pass" \
        "Mich x86_64: SMP net receive storm pass" \
        "Mich x86_64: SMP receive mailbox pass" \
        "Mich x86_64: SMP resource storm pass" \
        "Mich x86_64: SMP driver domain storm pass" \
        "Mich x86_64: SMP driver module storm pass" \
        "Mich x86_64: SMP vector storm pass" \
        "Mich x86_64: SMP copy-on-write storm pass" \
        "Mich x86_64: netbench-smp drivers=$bench_cpus_1" \
        "Mich x86_64: netbench-smp drivers=$bench_cpus_2" \
        "Mich x86_64: SMP lock order pass" \
        "Mich x86_64: SMP lock contention report" \
        "Mich x86_64: SMP dual-core userspace pass"
    do
        require_marker "$marker"
    done
    require_marker "Mich x86_64: SMP speedup two-tasks one-cpu"
    # Two concurrent tasks need two APs, so these markers only exist when the
    # run was given three CPUs or more.
    if [ "${MICH_SMP_CPUS:-2}" -ge 3 ]; then
        require_marker "Mich x86_64: SMP two-task parallel pass"
        require_marker "Mich x86_64: SMP speedup two-tasks two-cpu"
    fi
    if [ "${MICH_SMP_CPUS:-2}" -ge 4 ]; then
        require_marker "Mich x86_64: netbench-smp drivers=$bench_cpus_4"
    fi
fi
if [ "$profile" = "dns" ]; then
    for marker in \
        "Mich dnsprobe: resolver ready" \
        "Mich dnsprobe: TCP fallback and framing pass" \
        "Mich dnsprobe: cached answer pass" \
        "Mich dnsprobe: refused name rejected pass" \
        "Mich dnsprobe: transport pass" \
        "Mich virtio-net: probe sockets released pass"
    do
        require_marker "$marker"
    done
fi
if [ "$profile" = "tcpwire" ]; then
    for marker in \
        "Mich tcpwire: stream connected" \
        "Mich tcpwire: echo round trip pass" \
        "Mich tcpwire: peer name pass" \
        "Mich tcpwire: POSIX TCP wire pass" \
        "Mich virtio-net: probe sockets released pass"
    do
        require_marker "$marker"
    done
fi
if [ "$profile" = "netbench" ]; then
    for marker in \
        "Mich netbench: loopback report pass" \
        "Mich netbench: wire report pass"
    do
        grep -Fq "$marker" "$log" || { echo "SMOKE FAIL: expected marker not found: $marker" >&2; cat "$log"; cat "$netbench_peer_log"; exit 1; }
    done
    # Surface the measured numbers the guest printed for both passes.
    grep -F "Mich netbench: loopback-udp" "$log" || true
    grep -F "Mich netbench: wire-rr" "$log" || true
    grep -F "Mich netbench: wire-tx" "$log" || true
fi
if [ "$profile" = "hardware" ] || [ "$profile" = "msi" ] ||
   [ "$profile" = "msi-restart" ] || [ "$profile" = "msi-circuit" ] ||
   [ "$profile" = "msi-recovery" ]; then
    grep -Fq "Mich x86_64: hardware destructive test profile" "$log" || {
        cat "$log"
        exit 1
    }
fi
if [ "$profile" = "msi" ] || [ "$profile" = "msi-restart" ] ||
   [ "$profile" = "msi-circuit" ] || [ "$profile" = "msi-recovery" ]; then
    if [ -n "$passive_pid" ]; then wait "$passive_pid" || true; fi
    grep -Fq "PASS" "$passive_result" || { cat "$log"; exit 1; }
    if [ "$profile" = "msi-recovery" ]; then
        grep -Fq "PASS" "$active_result" || { cat "$log"; exit 1; }
    fi
    for marker in \
        "Mich test64: MSI-X hardware programming pass" \
        "Mich virtio-net: bootstrap pass" \
        "Mich virtio-net: firmware allowlist pass" \
        "Mich virtio-net: bounded firmware read pass" \
        "Mich virtio-net: feature negotiation pass" \
        "Mich virtio-net: stable device config pass" \
        "Mich virtio-net: RX and TX queue setup pass" \
        "Mich virtio-net: MSI-X queue vectors pass" \
        "Mich virtio-net: network interface registered" \
        "Mich virtio-net: RX buffers published" \
        "Mich virtio-net: DRIVER_OK pass" \
        "Mich virtio-net: DHCP retry timer armed" \
        "Mich virtio-net: IPv6 DAD started" \
        "Mich virtio-net: real TX completion pass" \
        "Mich virtio-net: real RX completion pass" \
        "Mich virtio-net: DHCP Offer receive pass" \
        "Mich virtio-net: DHCP Request transmit pass" \
        "Mich virtio-net: DHCP ACK receive pass" \
        "Mich virtio-net: DHCP lease timers pass" \
        "Mich virtio-net: DHCP IPv4 lease applied" \
        "Mich virtio-net: external ping queued" \
        "Mich virtio-net: external ping reply pass" \
        "Mich virtio-net: external UDP queued" \
        "Mich virtio-net: external UDP reply pass" \
        "Mich virtio-net: external socket UDP queued" \
        "Mich virtio-net: external socket UDP reply pass" \
        "Mich virtio-net: external TCP SYN queued" \
        "Mich virtio-net: external TCP handshake and echo pass" \
        "Mich virtio-net: passive listener ready" \
        "Mich virtio-net: external passive accept pass" \
        "Mich virtio-net: external passive echo pass" \
        "Mich virtio-net: external passive close pass" \
        "Mich virtio-net: stream socket connect queued" \
        "Mich virtio-net: stream readiness connected pass" \
        "Mich virtio-net: stream socket send pass" \
        "Mich virtio-net: stream readiness readable pass" \
        "Mich virtio-net: stream socket receive pass" \
        "Mich virtio-net: TCP stream soak pass" \
        "Mich virtio-net: stream socket shutdown pass" \
        "Mich virtio-net: external TCP FIN lifecycle pass" \
        "Mich virtio-net: external IPv6 DAD pass" \
        "Mich virtio-net: IPv6 lifecycle timer pass" \
        "Mich virtio-net: external IPv6 RA and SLAAC pass" \
        "Mich virtio-net: external IPv6 ping queued" \
        "Mich virtio-net: external IPv6 ping reply pass" \
        "Mich virtio-net: external UDPv6 queued" \
        "Mich virtio-net: external IPv6 socket queued" \
        "Mich virtio-net: external UDPv6 ICMP error pass" \
        "Mich virtio-net: interrupt-driven RX/TX pass" \
        "Mich virtio-net: batched RX/TX datapath pass" \
        "Mich virtio-net: adaptive interrupt moderation pass" \
        "Mich virtio-net: adaptive ITR budget rx=0x" \
        "Mich virtio-net: packet cycle counters active" \
        "Mich virtio-net: userspace capsule running"
    do
        require_marker "$marker"
    done
fi
if [ "$profile" = "msi-restart" ]; then
    for marker in \
        "Mich virtio-net: pre-restart network baseline pass" \
        "Mich virtio-net: restart fault injected" \
        "Mich virtio-net: supervisor restart pass" \
        "Mich virtio-net: fresh eth0 re-registration pass" \
        "Mich virtio-net: post-restart network baseline pass"
    do
        [ "$(grep -Fc "$marker" "$log")" -eq 1 ] || {
            cat "$log"
            exit 1
        }
    done
    for marker in \
        "Mich virtio-net: bootstrap pass" \
        "Mich virtio-net: network interface registered" \
        "Mich virtio-net: DHCP ACK receive pass" \
        "Mich virtio-net: DHCP IPv4 lease applied" \
        "Mich virtio-net: external ping reply pass" \
        "Mich virtio-net: external UDP reply pass" \
        "Mich virtio-net: external socket UDP reply pass" \
        "Mich virtio-net: external TCP handshake and echo pass" \
        "Mich virtio-net: external passive accept pass" \
        "Mich virtio-net: external passive echo pass" \
        "Mich virtio-net: external passive close pass" \
        "Mich virtio-net: TCP stream soak pass" \
        "Mich virtio-net: external TCP FIN lifecycle pass" \
        "Mich virtio-net: external IPv6 DAD pass" \
        "Mich virtio-net: external IPv6 RA and SLAAC pass" \
        "Mich virtio-net: external IPv6 ping reply pass" \
        "Mich virtio-net: external UDPv6 ICMP error pass" \
        "Mich virtio-net: userspace capsule running"
    do
        [ "$(grep -Fc "$marker" "$log")" -eq 2 ] || {
            cat "$log"
            exit 1
        }
    done
    baseline_line="$(grep -Fn "Mich virtio-net: pre-restart network baseline pass" "$log" | sed -n '1s/:.*//p')"
    fault_line="$(grep -Fn "Mich virtio-net: restart fault injected" "$log" | sed -n '1s/:.*//p')"
    exception_line="$(grep -Fn "Mich x86_64: user fault vec=0000000000000006" "$log" | awk -F: -v line="$fault_line" '$1 > line { print $1; exit }')"
    contained_line="$(grep -Fn "Mich x86_64: user exception contained" "$log" | awk -F: -v line="$fault_line" '$1 > line { print $1; exit }')"
    restart_line="$(grep -Fn "Mich virtio-net: supervisor restart pass" "$log" | sed -n '1s/:.*//p')"
    eth0_line="$(grep -Fn "Mich virtio-net: fresh eth0 re-registration pass" "$log" | sed -n '1s/:.*//p')"
    post_line="$(grep -Fn "Mich virtio-net: post-restart network baseline pass" "$log" | sed -n '1s/:.*//p')"
    [ -n "$baseline_line" ] && [ -n "$fault_line" ] &&
    [ -n "$exception_line" ] && [ -n "$contained_line" ] &&
    [ -n "$restart_line" ] && [ -n "$eth0_line" ] &&
    [ -n "$post_line" ] && [ "$baseline_line" -lt "$fault_line" ] &&
    [ "$fault_line" -lt "$exception_line" ] &&
    [ "$exception_line" -lt "$contained_line" ] &&
    [ "$contained_line" -lt "$restart_line" ] &&
    [ "$restart_line" -lt "$eth0_line" ] &&
    [ "$eth0_line" -lt "$post_line" ] || {
        cat "$log"
        exit 1
    }
fi
if [ "$profile" = "msi-circuit" ]; then
    for marker in \
        "Mich virtio-net: pre-restart network baseline pass" \
        "Mich virtio-net: supervisor restart pass" \
        "Mich virtio-net: fresh eth0 re-registration pass"
    do
        [ "$(grep -Fc "$marker" "$log")" -eq 1 ] || {
            cat "$log"
            exit 1
        }
    done
    restart_fault="Mich virtio-net: restart fault injected"
    [ "$(grep -Fc "$restart_fault" "$log")" -eq 2 ] &&
    [ "$(grep -Fc "Mich virtio-net: bootstrap pass" "$log")" -eq 2 ] &&
    [ "$(grep -Fc "Mich virtio-net: network interface registered" "$log")" -eq 2 ] &&
    [ "$(grep -Fc "Mich virtio-net: DRIVER_OK pass" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "Mich virtio-net: userspace capsule running" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "Mich virtio-net: post-restart network baseline pass" "$log")" -eq 0 ] || {
        cat "$log"
        exit 1
    }
    baseline_line="$(grep -Fn "Mich virtio-net: pre-restart network baseline pass" "$log" | sed -n '1s/:.*//p')"
    first_fault_line="$(grep -Fn "$restart_fault" "$log" | sed -n '1s/:.*//p')"
    second_fault_line="$(grep -Fn "$restart_fault" "$log" | sed -n '2s/:.*//p')"
    first_exception_line="$(grep -Fn "Mich x86_64: user fault vec=0000000000000006 rip=" "$log" | awk -F: -v line="$first_fault_line" '$1 > line { print $1; exit }')"
    first_contained_line="$(grep -Fn "Mich x86_64: user exception contained" "$log" | awk -F: -v line="$first_fault_line" '$1 > line { print $1; exit }')"
    restart_line="$(grep -Fn "Mich virtio-net: supervisor restart pass" "$log" | sed -n '1s/:.*//p')"
    eth0_line="$(grep -Fn "Mich virtio-net: fresh eth0 re-registration pass" "$log" | sed -n '1s/:.*//p')"
    second_exception_line="$(grep -Fn "Mich x86_64: user fault vec=0000000000000006 rip=" "$log" | awk -F: -v line="$second_fault_line" '$1 > line { print $1; exit }')"
    second_contained_line="$(grep -Fn "Mich x86_64: user exception contained" "$log" | awk -F: -v line="$second_fault_line" '$1 > line { print $1; exit }')"
    first_rip="$(sed -n "${first_exception_line}p" "$log" | sed -n 's/.* rip=\([^[:space:]]*\).*/\1/p')"
    second_rip="$(sed -n "${second_exception_line}p" "$log" | sed -n 's/.* rip=\([^[:space:]]*\).*/\1/p')"
    [ -n "$baseline_line" ] && [ -n "$first_fault_line" ] &&
    [ -n "$second_fault_line" ] && [ -n "$first_exception_line" ] &&
    [ -n "$first_contained_line" ] && [ -n "$restart_line" ] &&
    [ -n "$eth0_line" ] && [ -n "$second_exception_line" ] &&
    [ -n "$second_contained_line" ] && [ -n "$first_rip" ] &&
    [ "$first_rip" = "$second_rip" ] &&
    [ "$baseline_line" -lt "$first_fault_line" ] &&
    [ "$first_fault_line" -lt "$first_exception_line" ] &&
    [ "$first_exception_line" -lt "$first_contained_line" ] &&
    [ "$first_contained_line" -lt "$restart_line" ] &&
    [ "$restart_line" -lt "$eth0_line" ] &&
    [ "$eth0_line" -lt "$second_fault_line" ] &&
    [ "$second_fault_line" -lt "$second_exception_line" ] &&
    [ "$second_exception_line" -lt "$second_contained_line" ] || {
        cat "$log"
        exit 1
    }
    for marker in \
        "Mich virtio-net: DHCP ACK receive pass" \
        "Mich virtio-net: DHCP IPv4 lease applied" \
        "Mich virtio-net: external ping reply pass" \
        "Mich virtio-net: external UDP reply pass" \
        "Mich virtio-net: external socket UDP reply pass" \
        "Mich virtio-net: external TCP handshake and echo pass" \
        "Mich virtio-net: external passive accept pass" \
        "Mich virtio-net: external passive echo pass" \
        "Mich virtio-net: external passive close pass" \
        "Mich virtio-net: TCP stream soak pass" \
        "Mich virtio-net: external TCP FIN lifecycle pass" \
        "Mich virtio-net: external IPv6 DAD pass" \
        "Mich virtio-net: external IPv6 RA and SLAAC pass" \
        "Mich virtio-net: external IPv6 ping reply pass" \
        "Mich virtio-net: external UDPv6 ICMP error pass" \
        "Mich virtio-net: userspace capsule running"
    do
        [ "$(grep -Fc "$marker" "$log")" -eq 1 ] || {
            cat "$log"
            exit 1
        }
        marker_line="$(grep -Fn "$marker" "$log" | sed -n '1s/:.*//p')"
        [ "$marker_line" -lt "$baseline_line" ] || {
            cat "$log"
            exit 1
        }
    done
fi

if [ "$profile" = "msi-recovery" ]; then
    restart_fault="Mich virtio-net: restart fault injected"
    audit="Mich test64: driver recovery audit pass"
    selected="Mich virtio-net: recovery artifact selected"
    safe_bootstrap="Mich virtio-net safe: bootstrap pass"
    safe_device="Mich virtio-net safe: device ready pass"
    safe_interface="Mich virtio-net safe: eth0 registered pass"
    safe_virtio="Mich virtio-net safe: virtio ready pass"
    safe_ipv4="Mich virtio-net safe: static IPv4 configured pass"
    safe_queued="Mich virtio-net safe: external TCP queued"
    safe_echo="Mich virtio-net safe: external TCP echo pass"
    [ "$(grep -Fc "$restart_fault" "$log")" -eq 2 ] &&
    [ "$(grep -Fc "$audit" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "Mich virtio-net: bootstrap pass" "$log")" -eq 2 ] &&
    [ "$(grep -Fc "Mich virtio-net: network interface registered" "$log")" -eq 2 ] &&
    [ "$(grep -Fc "Mich virtio-net: supervisor restart pass" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "Mich virtio-net: fresh eth0 re-registration pass" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "$selected" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "Mich virtio-net: pre-restart network baseline pass" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "Mich virtio-net: post-restart network baseline pass" "$log")" -eq 0 ] &&
    [ "$(grep -Fc "Mich virtio-net: external passive accept pass" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "Mich virtio-net: external passive echo pass" "$log")" -eq 1 ] &&
    [ "$(grep -Fc "Mich virtio-net: external passive close pass" "$log")" -eq 1 ] || {
        cat "$log"
        exit 1
    }
    for marker in \
        "$safe_bootstrap" \
        "$safe_device" \
        "$safe_interface" \
        "$safe_virtio" \
        "$safe_ipv4" \
        "$safe_queued" \
        "$safe_echo"
    do
        [ "$(grep -Fc "$marker" "$log")" -eq 1 ] || {
            cat "$log"
            exit 1
        }
    done
    baseline_line="$(grep -Fn "Mich virtio-net: pre-restart network baseline pass" "$log" | sed -n '1s/:.*//p')"
    audit_line="$(grep -Fn "$audit" "$log" | sed -n '1s/:.*//p')"
    first_fault_line="$(grep -Fn "$restart_fault" "$log" | sed -n '1s/:.*//p')"
    second_fault_line="$(grep -Fn "$restart_fault" "$log" | sed -n '2s/:.*//p')"
    first_exception_line="$(grep -Fn "Mich x86_64: user fault vec=0000000000000006 rip=" "$log" | awk -F: -v line="$first_fault_line" '$1 > line { print $1; exit }')"
    first_contained_line="$(grep -Fn "Mich x86_64: user exception contained" "$log" | awk -F: -v line="$first_fault_line" '$1 > line { print $1; exit }')"
    restart_line="$(grep -Fn "Mich virtio-net: supervisor restart pass" "$log" | sed -n '1s/:.*//p')"
    eth0_line="$(grep -Fn "Mich virtio-net: fresh eth0 re-registration pass" "$log" | sed -n '1s/:.*//p')"
    second_exception_line="$(grep -Fn "Mich x86_64: user fault vec=0000000000000006 rip=" "$log" | awk -F: -v line="$second_fault_line" '$1 > line { print $1; exit }')"
    second_contained_line="$(grep -Fn "Mich x86_64: user exception contained" "$log" | awk -F: -v line="$second_fault_line" '$1 > line { print $1; exit }')"
    selected_line="$(grep -Fn "$selected" "$log" | sed -n '1s/:.*//p')"
    safe_bootstrap_line="$(grep -Fn "$safe_bootstrap" "$log" | sed -n '1s/:.*//p')"
    safe_device_line="$(grep -Fn "$safe_device" "$log" | sed -n '1s/:.*//p')"
    safe_interface_line="$(grep -Fn "$safe_interface" "$log" | sed -n '1s/:.*//p')"
    safe_virtio_line="$(grep -Fn "$safe_virtio" "$log" | sed -n '1s/:.*//p')"
    safe_ipv4_line="$(grep -Fn "$safe_ipv4" "$log" | sed -n '1s/:.*//p')"
    safe_queued_line="$(grep -Fn "$safe_queued" "$log" | sed -n '1s/:.*//p')"
    safe_echo_line="$(grep -Fn "$safe_echo" "$log" | sed -n '1s/:.*//p')"
    first_rip="$(sed -n "${first_exception_line}p" "$log" | sed -n 's/.* rip=\([^[:space:]]*\).*/\1/p')"
    second_rip="$(sed -n "${second_exception_line}p" "$log" | sed -n 's/.* rip=\([^[:space:]]*\).*/\1/p')"
    [ -n "$audit_line" ] && [ -n "$baseline_line" ] &&
    [ -n "$first_fault_line" ] &&
    [ -n "$second_fault_line" ] && [ -n "$first_exception_line" ] &&
    [ -n "$first_contained_line" ] && [ -n "$restart_line" ] &&
    [ -n "$eth0_line" ] && [ -n "$second_exception_line" ] &&
    [ -n "$second_contained_line" ] && [ -n "$selected_line" ] &&
    [ -n "$safe_bootstrap_line" ] && [ -n "$safe_device_line" ] &&
    [ -n "$safe_interface_line" ] && [ -n "$safe_virtio_line" ] &&
    [ -n "$safe_ipv4_line" ] && [ -n "$safe_queued_line" ] &&
    [ -n "$safe_echo_line" ] && [ -n "$first_rip" ] &&
    [ "$first_rip" = "$second_rip" ] &&
    [ "$audit_line" -lt "$baseline_line" ] &&
    [ "$baseline_line" -lt "$first_fault_line" ] &&
    [ "$first_fault_line" -lt "$first_exception_line" ] &&
    [ "$first_exception_line" -lt "$first_contained_line" ] &&
    [ "$first_contained_line" -lt "$restart_line" ] &&
    [ "$restart_line" -lt "$eth0_line" ] &&
    [ "$eth0_line" -lt "$second_fault_line" ] &&
    [ "$second_fault_line" -lt "$second_exception_line" ] &&
    [ "$second_exception_line" -lt "$second_contained_line" ] &&
    [ "$second_contained_line" -lt "$selected_line" ] &&
    [ "$selected_line" -lt "$safe_bootstrap_line" ] &&
    [ "$safe_bootstrap_line" -lt "$safe_device_line" ] &&
    [ "$safe_device_line" -lt "$safe_interface_line" ] &&
    [ "$safe_interface_line" -lt "$safe_virtio_line" ] &&
    [ "$safe_virtio_line" -lt "$safe_ipv4_line" ] &&
    [ "$safe_ipv4_line" -lt "$safe_queued_line" ] &&
    [ "$safe_queued_line" -lt "$safe_echo_line" ] || {
        cat "$log"
        exit 1
    }
fi
if [ "$profile" = "tty" ]; then
    # The peer leaves right after typing, so wait for it to put its result
    # file on disk before the check reads it.
    wait_rounds=0
    while kill -0 "$tty_peer_pid" 2>/dev/null && [ "$wait_rounds" -lt 30 ]; do
        sleep 0.1
        wait_rounds=$((wait_rounds + 1))
    done
    wire_ready="Mich x86_64: POSIX tty wire ready"
    wire_pass="Mich x86_64: POSIX tty wire pass"
    require_marker "$wire_ready"
    require_marker "$wire_pass"
    # The order is the proof: the host typed after the ready marker and its
    # echo came back before the guest could print its pass marker.
    ready_line=$(grep -Fn "$wire_ready" "$log" | head -1 | cut -d: -f1)
    echo_line=$(grep -Fn "wire1" "$log" | head -1 | cut -d: -f1)
    pass_line=$(grep -Fn "$wire_pass" "$log" | head -1 | cut -d: -f1)
    if [ -z "$ready_line" ] || [ -z "$echo_line" ] || [ -z "$pass_line" ] ||
        [ "$ready_line" -ge "$echo_line" ] || [ "$echo_line" -ge "$pass_line" ]
    then
        echo "SMOKE FAIL: the typed line was not echoed between the markers:" >&2
        echo "  ready=$ready_line echo=$echo_line pass=$pass_line" >&2
        cat "$log" >&2
        exit 1
    fi
    if [ ! -f "$tty_result" ] || [ "$(cat "$tty_result")" != "TYPED" ]; then
        echo "SMOKE FAIL: the console peer never typed into the port" >&2
        echo "  after the ready marker, so the guest's read was completed" >&2
        echo "  by something else" >&2
        cat "$log" >&2
        exit 1
    fi
fi
if [ "$profile" = "pcie" ] || [ "$profile" = "iommu" ] ||
   [ "$profile" = "amd-iommu" ]; then
    grep -Fq "Mich x86_64: PCIe ECAM pass" "$log" || {
        cat "$log"
        exit 1
    }
fi
if [ "$profile" = "iommu" ]; then
    for marker in \
        "Mich x86_64: Intel VT-d discovery pass" \
        "Mich x86_64: IOMMU backend registration pass" \
        "Mich test64: Intel VT-d translation tables pass" \
        "Mich test64: Intel VT-d command engine pass" \
        "Mich test64: Intel VT-d revoke and resume pass" \
        "Mich test64: Intel VT-d fault decode pass" \
        "Mich test64: Intel VT-d forbidden DMA blocked"
    do
        require_marker "$marker"
    done
fi
if [ "$profile" = "amd-iommu" ]; then
    for marker in \
        "Mich x86_64: AMD-Vi discovery pass" \
        "Mich x86_64: AMD-Vi device table pass" \
        "Mich x86_64: AMD-Vi command and event buffers pass" \
        "Mich x86_64: AMD-Vi completion command pass" \
        "Mich test64: AMD-Vi DTE and domain pass" \
        "Mich test64: AMD-Vi page invalidation pass"
    do
        require_marker "$marker"
    done
fi
if [ "$profile" = "virtio-blk" ]; then
    for marker in \
        "Mich virtio-blk: bootstrap pass" \
        "Mich virtio-blk: serve pass"
    do
        require_marker "$marker"
    done
fi
if [ "$profile" = "nvme" ]; then
    for marker in \
        "Mich nvme: bootstrap pass" \
        "Mich nvme: serve pass"
    do
        require_marker "$marker"
    done
fi
# A tripped battery guard prints its line before it parks, so a boot that
# trips one is a failed boot even when every marker happens to be present.
# Refusing the log here keeps a stall from ever being reported as a missing
# marker with no clue which check died.
for guard in "battery guard at line" "battery check at line"; do
    if grep -Fq "$guard" "$log"; then
        echo "SMOKE FAIL: the battery tripped a guard:" >&2
        grep -F "$guard" "$log" >&2
        exit 1
    fi
done
bad="$(grep -Ei "FAIL|failure|bad boot protocol|exception vector" "$log" || true)"
if [ "$profile" = "iommu" ]; then
    # The forbidden-DMA test must produce this QEMU translation failure.
    bad="$(printf '%s\n' "$bad" | grep -Fiv \
        "vtd_iommu_translate: detected translation failure" || true)"
fi
if [ -n "$bad" ]; then
    cat "$log"
    exit 1
fi
cat "$log"
echo "qemu-smoke64: PASS ($memory)"
