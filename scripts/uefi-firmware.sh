# Locate OVMF and stage a writable copy of its variable store. Sourced by the
# QEMU runners; sets uefi_code and uefi_vars. The caller owns uefi_vars and is
# responsible for removing it.
#
# Distributions disagree on both the path and the split-vs-combined layout, so
# probe the known ones. MICH_OVMF_CODE and MICH_OVMF_VARS override the search
# for anything unusual.

mich_uefi_firmware() {
    uefi_code="${MICH_OVMF_CODE:-}"
    ovmf_vars_template="${MICH_OVMF_VARS:-}"
    if [ -z "$uefi_code" ] || [ -z "$ovmf_vars_template" ]; then
        for candidate in \
            "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
            "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
            "/usr/share/OVMF/x64/OVMF_CODE.4m.fd:/usr/share/OVMF/x64/OVMF_VARS.4m.fd" \
            "/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd:/usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd" \
            "/usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd" \
            "/usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd" \
            "/usr/share/qemu/edk2-x86_64-code.fd:/usr/share/qemu/edk2-i386-vars.fd"
        do
            code="${candidate%%:*}"
            vars="${candidate##*:}"
            if [ -r "$code" ] && [ -r "$vars" ]; then
                uefi_code="$code"
                ovmf_vars_template="$vars"
                break
            fi
        done
    fi
    if [ -z "$uefi_code" ] || [ ! -r "$uefi_code" ] ||
       [ -z "$ovmf_vars_template" ] || [ ! -r "$ovmf_vars_template" ]; then
        echo "OVMF firmware not found. Mich boots via UEFI only." >&2
        echo "Install it (Debian/Ubuntu: apt-get install ovmf, Fedora: dnf install edk2-ovmf)" >&2
        echo "or point MICH_OVMF_CODE and MICH_OVMF_VARS at the firmware files." >&2
        exit 1
    fi
    uefi_vars="$(mktemp)"
    cp "$ovmf_vars_template" "$uefi_vars"
}
