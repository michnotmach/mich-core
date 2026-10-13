#!/usr/bin/env python3
import struct
import sys
import zlib

BLOCK = 512
BLOB_MAGIC = 0x424F4C42
BASE = 0x100000
# The loader lays the kernel and then the modules into low RAM; the ceiling
# below is the loader's own (MODULE_LIMIT in src/arch/x86_64/boot/uefi.c).
MODULE_LIMIT = 0x5800000
MAX_MODULES = 8

ESP_TYPE = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
DISK_GUID = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
PART_GUID = bytes.fromhex("102030405060708090a0b0c0d0e0f001")
LBA_SIZE = 512
GPT_ENTRIES = 128
ENTRY_SIZE = 128
FIRST_USABLE = 34



def kernel_info(path):
    with open(path, "rb") as file:
        image = file.read()
    if len(image) < 64 or image[:4] != b"\x7fELF" or image[4] != 2 or image[5] != 1:
        raise SystemExit("kernel is not ELF64 little-endian")
    entry = struct.unpack_from("<Q", image, 24)[0]
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize = struct.unpack_from("<H", image, 54)[0]
    phnum = struct.unpack_from("<H", image, 56)[0]
    if phentsize < 56 or phoff + phentsize * phnum > len(image):
        raise SystemExit("invalid ELF64 program headers")
    end = BASE
    bss_off = 0
    bss_len = 0
    for index in range(phnum):
        position = phoff + index * phentsize
        p_type = struct.unpack_from("<I", image, position)[0]
        if p_type != 1:
            continue
        vaddr = struct.unpack_from("<Q", image, position + 16)[0]
        filesz = struct.unpack_from("<Q", image, position + 32)[0]
        memsz = struct.unpack_from("<Q", image, position + 40)[0]
        if memsz < filesz or vaddr + memsz < vaddr:
            raise SystemExit("invalid ELF64 load segment")
        end = max(end, vaddr + memsz)
        if memsz > filesz:
            bss_off = vaddr + filesz - BASE
            bss_len = memsz - filesz
    if entry < BASE or entry >= end:
        raise SystemExit("invalid ELF64 entry")
    return entry - BASE, bss_off, bss_len, (end + 0xFFF) & ~0xFFF


def read_modules(arguments):
    modules = []
    for specification in arguments:
        if "=" not in specification:
            raise SystemExit("bad module specification: " + specification)
        identity, path = specification.split("=", 1)
        if ":" in identity:
            name, capability_text = identity.rsplit(":", 1)
            capabilities = int(capability_text, 0)
        else:
            name = identity
            capabilities = 0
        encoded = name.encode("ascii")
        if not encoded or len(encoded) > 15 or capabilities < 0 or capabilities > 0xFFFFFFFF:
            raise SystemExit("invalid module identity: " + identity)
        with open(path, "rb") as file:
            data = file.read()
        if not data:
            raise SystemExit("empty module: " + path)
        modules.append((encoded, data, capabilities))
    if len(modules) > MAX_MODULES:
        raise SystemExit("too many modules")
    return modules

def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def encode_name(name):
    encoded = name.encode("ascii")
    if "." in name:
        stem, ext = name.split(".", 1)
    else:
        stem, ext = name, ""
    stem = stem.upper()[:8].ljust(8)
    ext = ext.upper()[:3].ljust(3)
    return (stem + ext).encode("ascii")


def dir_entry(name, attr, cluster, size):
    entry = bytearray(32)
    entry[0:11] = encode_name(name) if name != "." and name != ".." else (
        name.encode("ascii").ljust(11, b" "))
    entry[11] = attr
    struct.pack_into("<H", entry, 20, (cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", entry, 26, cluster & 0xFFFF)
    struct.pack_into("<I", entry, 28, size)
    return bytes(entry)


def fat16_layout(total_sectors):
    reserved = 1
    fats = 2
    root_entries = 512
    root_sectors = (root_entries * 32 + LBA_SIZE - 1) // LBA_SIZE
    for spc in (1, 2, 4, 8):
        for fat_sectors in range(1, 512):
            data = total_sectors - reserved - fats * fat_sectors - root_sectors
            if data <= 0:
                continue
            clusters = data // spc
            need = (clusters + 2) * 2
            if (need + LBA_SIZE - 1) // LBA_SIZE != fat_sectors:
                continue
            if 4085 <= clusters < 65525:
                return {
                    "spc": spc,
                    "reserved": reserved,
                    "fats": fats,
                    "root_entries": root_entries,
                    "root_sectors": root_sectors,
                    "fat_sectors": fat_sectors,
                    "clusters": clusters,
                    "data_start": reserved + fats * fat_sectors + root_sectors,
                }
    raise SystemExit("cannot layout FAT16")


def write_fat16(volume, files):
    layout = fat16_layout(len(volume) // LBA_SIZE)
    fat = [0] * (layout["clusters"] + 2)
    fat[0] = 0xFFF8
    fat[1] = 0xFFFF
    next_cluster = 2

    def alloc(count):
        nonlocal next_cluster
        if count < 1:
            count = 1
        first = next_cluster
        if first + count - 1 > layout["clusters"] + 1:
            raise SystemExit("FAT16 full")
        for index in range(count):
            cluster = first + index
            fat[cluster] = 0xFFFF if index == count - 1 else cluster + 1
        next_cluster += count
        return first

    cluster_bytes = layout["spc"] * LBA_SIZE

    def store(data, cluster):
        offset = (layout["data_start"] + (cluster - 2) * layout["spc"]) * LBA_SIZE
        volume[offset:offset + len(data)] = data

    def store_dir(entries, cluster):
        blob = bytearray(cluster_bytes)
        blob[:len(entries)] = entries
        store(blob, cluster)

    tree = {}
    for path, data in files:
        node = tree
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = data

    def build(node, parent_cluster):
        cluster = alloc(1)
        entries = bytearray()
        entries += dir_entry(".", 0x10, cluster, 0)
        entries += dir_entry("..", 0x10, parent_cluster, 0)
        for name in sorted(node):
            value = node[name]
            if isinstance(value, dict):
                child = build(value, cluster)
                entries += dir_entry(name, 0x10, child, 0)
            else:
                count = (len(value) + cluster_bytes - 1) // cluster_bytes
                first = alloc(count)
                padded = value + b"\x00" * (count * cluster_bytes - len(value))
                store(padded, first)
                entries += dir_entry(name, 0x20, first, len(value))
        if len(entries) > cluster_bytes:
            raise SystemExit("directory too large")
        store_dir(entries, cluster)
        return cluster

    root = bytearray(layout["root_sectors"] * LBA_SIZE)
    cursor = 0
    for name in sorted(tree):
        value = tree[name]
        if isinstance(value, dict):
            child = build(value, 0)
            entry = dir_entry(name, 0x10, child, 0)
        else:
            count = (len(value) + cluster_bytes - 1) // cluster_bytes
            first = alloc(count)
            padded = value + b"\x00" * (count * cluster_bytes - len(value))
            store(padded, first)
            entry = dir_entry(name, 0x20, first, len(value))
        root[cursor:cursor + 32] = entry
        cursor += 32

    fat_bytes = bytearray(layout["fat_sectors"] * LBA_SIZE)
    for index, value in enumerate(fat):
        struct.pack_into("<H", fat_bytes, index * 2, value)

    bpb = bytearray(LBA_SIZE)
    bpb[0:3] = b"\xEB\x3C\x90"
    bpb[3:11] = b"MICHCORE"
    struct.pack_into("<H", bpb, 11, LBA_SIZE)
    bpb[13] = layout["spc"]
    struct.pack_into("<H", bpb, 14, layout["reserved"])
    bpb[16] = layout["fats"]
    struct.pack_into("<H", bpb, 17, layout["root_entries"])
    total = len(volume) // LBA_SIZE
    if total < 0x10000:
        struct.pack_into("<H", bpb, 19, total)
    else:
        struct.pack_into("<I", bpb, 32, total)
    bpb[21] = 0xF8
    struct.pack_into("<H", bpb, 22, layout["fat_sectors"])
    struct.pack_into("<H", bpb, 24, 32)
    struct.pack_into("<H", bpb, 26, 2)
    struct.pack_into("<I", bpb, 28, FIRST_USABLE)
    bpb[36] = 0x80
    bpb[38] = 0x29
    struct.pack_into("<I", bpb, 39, 0x4D494348)
    bpb[43:54] = b"MICH ESP   "
    bpb[54:62] = b"FAT16   "
    bpb[510:512] = b"\x55\xAA"
    volume[0:LBA_SIZE] = bpb
    fat_off = layout["reserved"] * LBA_SIZE
    fat_len = layout["fat_sectors"] * LBA_SIZE
    volume[fat_off:fat_off + fat_len] = fat_bytes
    volume[fat_off + fat_len:fat_off + 2 * fat_len] = fat_bytes
    root_off = fat_off + 2 * fat_len
    volume[root_off:root_off + len(root)] = root


def gpt_header(my_lba, alt_lba, part_lba, disk_sectors, entries):
    header = bytearray(LBA_SIZE)
    header[0:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<Q", header, 24, my_lba)
    struct.pack_into("<Q", header, 32, alt_lba)
    struct.pack_into("<Q", header, 40, FIRST_USABLE)
    struct.pack_into("<Q", header, 48, disk_sectors - 34)
    header[56:72] = DISK_GUID
    struct.pack_into("<Q", header, 72, part_lba)
    struct.pack_into("<I", header, 80, GPT_ENTRIES)
    struct.pack_into("<I", header, 84, ENTRY_SIZE)
    struct.pack_into("<I", header, 88, crc32(entries))
    struct.pack_into("<I", header, 16, crc32(header[:92]))
    return header


def build_blob(kernel, modules, entry, bss_off, bss_len, module_base):
    kernel_offset = 0x1000
    cursor = (kernel_offset + len(kernel) + BLOCK - 1) & ~(BLOCK - 1)
    records = []
    for name, data, capabilities in modules:
        records.append((cursor, len(data), name, capabilities))
        cursor = (cursor + len(data) + BLOCK - 1) & ~(BLOCK - 1)
    blob = bytearray(cursor)
    blob[kernel_offset:kernel_offset + len(kernel)] = kernel
    for (_, data, _), (offset, size, _, _) in zip(modules, records):
        blob[offset:offset + size] = data
    struct.pack_into("<I", blob, 0, BLOB_MAGIC)
    struct.pack_into("<I", blob, 4, len(blob) // BLOCK)
    struct.pack_into("<I", blob, 8, kernel_offset)
    struct.pack_into("<I", blob, 12, len(kernel))
    struct.pack_into("<I", blob, 16, entry)
    struct.pack_into("<I", blob, 20, len(records))
    for index, (offset, size, name, capabilities) in enumerate(records):
        position = 24 + index * 24
        struct.pack_into("<II", blob, position, offset, size)
        blob[position + 8:position + 8 + len(name)] = name
        struct.pack_into("<I", blob, 236 + index * 4, capabilities)
    struct.pack_into("<I", blob, 224, module_base)
    struct.pack_into("<I", blob, 228, bss_off)
    struct.pack_into("<I", blob, 232, bss_len)
    return blob, records


def main():
    args = sys.argv[1:]
    kernel_elf = "bin/x86_64/mich-kernel.elf"
    kernel_flat = "bin/x86_64/mich-kernel.bin"
    efi_path = "bin/x86_64/BOOTX64.EFI"
    while args and args[0].startswith("--"):
        if len(args) < 2 or args[0] not in ("--kernel", "--kernel-flat", "--efi"):
            raise SystemExit("bad kernel option")
        if args[0] == "--kernel":
            kernel_elf = args[1]
        elif args[0] == "--kernel-flat":
            kernel_flat = args[1]
        else:
            efi_path = args[1]
        args = args[2:]
    if not args:
        raise SystemExit(
            "usage: mkuefi64.py [--kernel ELF] [--kernel-flat BIN] [--efi EFI] "
            "OUTPUT [NAME:CAPS=MODULE ...]")
    output = args[0]
    modules = read_modules(args[1:])
    entry, bss_off, bss_len, module_base = kernel_info(kernel_elf)
    # Refusing an oversized layout here beats a boot that dies inside the
    # loader with the kernel already past the last free byte.
    span = module_base
    for _, data, _ in modules:
        span += (len(data) + 0xFFF) & ~0xFFF
    if span > MODULE_LIMIT:
        raise SystemExit(
            "kernel and modules do not fit below 0x%x: %d bytes" %
            (MODULE_LIMIT, span))
    with open(kernel_flat, "rb") as file:
        kernel = file.read()
    with open(efi_path, "rb") as file:
        efi = file.read()
    if not efi:
        raise SystemExit("empty EFI image")
    blob, records = build_blob(kernel, modules, entry, bss_off, bss_len, module_base)

    disk_sectors = 16384
    last = disk_sectors - 1
    disk = bytearray(disk_sectors * LBA_SIZE)
    disk[0:LBA_SIZE] = bytearray(LBA_SIZE)
    disk[446:462] = bytes([
        0x00, 0x00, 0x02, 0x00, 0xEE, 0xFF, 0xFF, 0xFF,
    ]) + struct.pack("<II", 1, disk_sectors - 1)
    disk[510:512] = b"\x55\xAA"

    entries = bytearray(GPT_ENTRIES * ENTRY_SIZE)
    entries[0:16] = ESP_TYPE
    entries[16:32] = PART_GUID
    struct.pack_into("<Q", entries, 32, FIRST_USABLE)
    struct.pack_into("<Q", entries, 40, last - 33)
    name = "EFI System".encode("utf-16le")
    entries[56:56 + len(name)] = name
    disk[LBA_SIZE:2 * LBA_SIZE] = gpt_header(1, last, 2, disk_sectors, entries)
    disk[2 * LBA_SIZE:2 * LBA_SIZE + len(entries)] = entries
    disk[(last - 32) * LBA_SIZE:(last - 32) * LBA_SIZE + len(entries)] = entries
    disk[last * LBA_SIZE:(last + 1) * LBA_SIZE] = gpt_header(
        last, 1, last - 32, disk_sectors, entries)

    esp_sectors = (last - 33) - FIRST_USABLE + 1
    volume = bytearray(esp_sectors * LBA_SIZE)
    write_fat16(volume, [
        (["EFI", "BOOT", "BOOTX64.EFI"], efi),
        (["EFI", "MICH", "BLOB"], bytes(blob)),
    ])
    start = FIRST_USABLE * LBA_SIZE
    disk[start:start + len(volume)] = volume
    with open(output, "wb") as file:
        file.write(disk)
    print("mkuefi64: efi %dB, blob %dB, entry +0x%x, modules %d" %
          (len(efi), len(blob), entry, len(records)))


if __name__ == "__main__":
    main()
