#include "types.h"
#include "bootinfo.h"

#define EFI_BUFFER_TOO_SMALL (0x8000000000000005ULL)
#define EFI_LOADER_DATA 2
#define EFI_FILE_MODE_READ 1ULL
#define BLOB_MAGIC 0x424F4C42u
#define MAX_MMAP 32
#define MAX_MMAP_RAW 128
#define MAX_MODS 8
#define COM1 0x3F8
#define E820_USABLE 1
#define E820_RESERVED 2
#define E820_ACPI 3
#define E820_NVS 4
#define INFO_BASE 0x78000ULL
#define PAGE_BASE 0x70000ULL
// Must match --image-base in the Makefile rule for BOOTX64.EFI. The firmware
// refused bases above the 64MB line, so the loader sits inside the kernel bss
// and the clear has to work around it.
#define LOADER_BASE 0x3000000ULL
#define LOADER_SPAN 0x40000ULL
// Scratch page for the handover stub: below the kernel load address, clear of
// the bss, the loader image and the blob.
#define STUB_BASE 0x90000ULL
// The kernel bss spans tens of megabytes from 0x100000 and the modules are
// laid out directly above it, up to the MODULE_LIMIT checked below. That
// limit bounds the low window the kernel and its modules claim; RAM from
// the kernel's bss end up to the limit stays free for the allocator. The
// staging blob must therefore sit above that whole region: at 0x2800000 it
// was inside the bss and was erased before the kernel and modules had been
// copied out of it.
#define BLOB_BASE 0x6000000ULL
// Kernel plus modules must fit below this. The task pool and the network test
// arenas live in the kernel bss, so the ceiling has to leave room for both
// while RAM above the bss stays allocatable. Raising it costs no RAM: the
// window it opens is allocator memory either way. It must stay clear of
// BLOB_BASE or the module copy would overwrite the staging blob, so the gap
// above it is what bounds the choice. The same number sits in mkuefi64.py,
// which refuses an oversized layout at build time.
#define MODULE_LIMIT 0x5800000ULL

typedef u64 efi_status;
typedef void *efi_handle;
typedef u64 efi_phys;

struct efi_guid {
    u32 data1;
    u16 data2;
    u16 data3;
    u8 data4[8];
};

struct efi_table_header {
    u64 signature;
    u32 revision;
    u32 header_size;
    u32 crc32;
    u32 reserved;
};

struct efi_memory_desc {
    u32 type;
    u32 pad;
    u64 physical;
    u64 virtual;
    u64 pages;
    u64 attribute;
};

struct efi_file;

typedef efi_status __attribute__((ms_abi)) (*efi_get_memory_map_fn)(
    u64 *size, struct efi_memory_desc *map, u64 *key, u64 *desc_size,
    u32 *desc_version);
typedef efi_status __attribute__((ms_abi)) (*efi_allocate_pool_fn)(
    u32 memory_type, u64 size, void **buffer);
typedef efi_status __attribute__((ms_abi)) (*efi_free_pool_fn)(void *buffer);
typedef efi_status __attribute__((ms_abi)) (*efi_handle_protocol_fn)(
    efi_handle handle, struct efi_guid *protocol, void **interface);
typedef efi_status __attribute__((ms_abi)) (*efi_locate_protocol_fn)(
    struct efi_guid *protocol, void *registration, void **interface);
typedef efi_status __attribute__((ms_abi)) (*efi_exit_boot_fn)(
    efi_handle image, u64 map_key);
typedef efi_status __attribute__((ms_abi)) (*efi_open_volume_fn)(
    void *this, struct efi_file **root);
typedef efi_status __attribute__((ms_abi)) (*efi_file_open_fn)(
    struct efi_file *this, struct efi_file **new_handle, u16 *name,
    u64 mode, u64 attributes);
typedef efi_status __attribute__((ms_abi)) (*efi_file_close_fn)(
    struct efi_file *this);
typedef efi_status __attribute__((ms_abi)) (*efi_file_read_fn)(
    struct efi_file *this, u64 *size, void *buffer);

struct efi_boot_services {
    struct efi_table_header hdr;
    void *raise_tpl;
    void *restore_tpl;
    void *allocate_pages;
    void *free_pages;
    efi_get_memory_map_fn get_memory_map;
    efi_allocate_pool_fn allocate_pool;
    efi_free_pool_fn free_pool;
    void *create_event;
    void *set_timer;
    void *wait_for_event;
    void *signal_event;
    void *close_event;
    void *check_event;
    void *install_protocol_interface;
    void *reinstall_protocol_interface;
    void *uninstall_protocol_interface;
    efi_handle_protocol_fn handle_protocol;
    void *reserved;
    void *register_protocol_notify;
    void *locate_handle;
    void *locate_device_path;
    void *install_configuration_table;
    void *load_image;
    void *start_image;
    void *exit;
    void *unload_image;
    efi_exit_boot_fn exit_boot_services;
    void *get_next_monotonic_count;
    void *stall;
    void *set_watchdog_timer;
    void *connect_controller;
    void *disconnect_controller;
    void *open_protocol;
    void *close_protocol;
    void *open_protocol_information;
    void *protocols_per_handle;
    void *locate_handle_buffer;
    efi_locate_protocol_fn locate_protocol;
};

struct efi_config_table {
    struct efi_guid vendor_guid;
    void *vendor_table;
};

struct efi_system_table {
    struct efi_table_header hdr;
    u16 *firmware_vendor;
    u32 firmware_revision;
    u32 pad;
    efi_handle console_in_handle;
    void *con_in;
    efi_handle console_out_handle;
    void *con_out;
    efi_handle standard_error_handle;
    void *std_err;
    void *runtime_services;
    struct efi_boot_services *boot_services;
    u64 number_of_table_entries;
    struct efi_config_table *configuration_table;
};

struct efi_loaded_image {
    u32 revision;
    u32 pad;
    efi_handle parent_handle;
    struct efi_system_table *system_table;
    efi_handle device_handle;
};

struct efi_simple_fs {
    u64 revision;
    efi_open_volume_fn open_volume;
};

struct efi_file {
    u64 revision;
    efi_file_open_fn open;
    efi_file_close_fn close;
    void *delete;
    efi_file_read_fn read;
};

struct efi_gop_mode_info {
    u32 version;
    u32 width;
    u32 height;
    u32 pixel_format;
    u32 pixel_bitmask[4];
    u32 pixels_per_scanline;
};

struct efi_gop_mode {
    u32 max_mode;
    u32 mode;
    struct efi_gop_mode_info *info;
    u64 info_size;
    efi_phys framebuffer;
    u64 framebuffer_size;
};

struct efi_gop {
    void *query_mode;
    void *set_mode;
    void *blt;
    struct efi_gop_mode *mode;
};

struct efi_rsdp {
    char signature[8];
    u8 checksum;
    char oem_id[6];
    u8 revision;
    u32 rsdt_address;
    u32 length;
    u64 xsdt_address;
    u8 extended_checksum;
    u8 reserved[3];
} __attribute__((packed));

struct e820_entry {
    u64 addr;
    u64 len;
    u32 type;
    u32 acpi;
};

static struct efi_guid loaded_image_guid = {
    0x5B1B31A1, 0x9562, 0x11d2,
    {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};
static struct efi_guid simple_fs_guid = {
    0x964E5B22, 0x6459, 0x11D2,
    {0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};
static struct efi_guid gop_guid = {
    0x9042A9DE, 0x23DC, 0x4A38,
    {0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A}
};
static struct efi_guid acpi20_guid = {
    0x8868e871, 0xe4f1, 0x11d3,
    {0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81}
};
static struct efi_guid acpi10_guid = {
    0xeb9d2d30, 0x2d88, 0x11d3,
    {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}
};

static void outb(u16 port, u8 value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static u8 inb(u16 port) {
    u8 value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void serial_init(void) {
    outb(0x3FB, 0x80);
    outb(COM1, 0x01);
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x03);
    outb(0x3FA, 0xC7);
    outb(0x3FC, 0x0B);
}

static void serial_putc(char c) {
    while (!(inb(0x3FD) & 0x20)) {}
    outb(COM1, (u8)c);
}

static void serial_puts(const char *s) {
    while (*s) serial_putc(*s++);
}

static void serial_hex(u64 value) {
    for (int i = 15; i >= 0; i--) {
        u8 nibble = (u8)((value >> (i * 4)) & 0xF);
        serial_putc((char)(nibble < 10 ? '0' + nibble : 'a' + nibble - 10));
    }
}

static void fail(const char *msg) {
    serial_puts(msg);
    for (;;) __asm__ volatile("cli; hlt");
}

static int guid_equal(const struct efi_guid *a, const struct efi_guid *b) {
    const u8 *left = (const u8 *)a;
    const u8 *right = (const u8 *)b;
    for (u32 i = 0; i < sizeof(struct efi_guid); i++)
        if (left[i] != right[i]) return 0;
    return 1;
}

// Overlap-safe: allocate_pool can hand back a buffer that sits only a little
// below a fixed destination such as BLOB_BASE, in which case a forward copy
// starts re-reading bytes it has already written and smears the source over
// itself. Copy backwards whenever the destination overlaps ahead of the source.
static void copy_bytes(void *dst, const void *src, u64 n) {
    u64 d = (u64)dst;
    u64 s = (u64)src;
    u64 c = n;
    if (!c || d == s) return;
    if (d > s && d - s < c) {
        d += c - 1;
        s += c - 1;
        __asm__ volatile("std; rep movsb; cld"
                         : "+D"(d), "+S"(s), "+c"(c)
                         :
                         : "memory");
        return;
    }
    __asm__ volatile("cld; rep movsb" : "+D"(d), "+S"(s), "+c"(c) : : "memory");
}

static void zero_bytes(void *dst, u64 n) {
    u64 d = (u64)dst;
    u64 c = n;
    u64 ax = 0;
    __asm__ volatile("cld; rep stosb" : "+D"(d), "+c"(c), "+a"(ax) : : "memory");
}

static u32 e820_type(u32 efi_type) {
    if (efi_type == 1 || efi_type == 2 || efi_type == 3 || efi_type == 4 ||
        efi_type == 7)
        return E820_USABLE;
    if (efi_type == 9) return E820_ACPI;
    if (efi_type == 10) return E820_NVS;
    return E820_RESERVED;
}

static u32 coalesce_mmap(struct e820_entry *entries, u32 count) {
    for (;;) {
        int merged = 0;
        for (u32 i = 0; i < count; i++) {
            for (u32 j = i + 1; j < count; j++) {
                u64 a0;
                u64 a1;
                u64 b0;
                u64 b1;
                u64 start;
                u64 end;
                if (entries[i].type != entries[j].type) continue;
                a0 = entries[i].addr;
                a1 = a0 + entries[i].len;
                b0 = entries[j].addr;
                b1 = b0 + entries[j].len;
                if (a1 < b0 || b1 < a0) continue;
                start = a0 < b0 ? a0 : b0;
                end = a1 > b1 ? a1 : b1;
                entries[i].addr = start;
                entries[i].len = end - start;
                entries[j] = entries[count - 1];
                count--;
                merged = 1;
                break;
            }
            if (merged) break;
        }
        if (!merged) break;
    }
    return count;
}

static u32 shrink_mmap(struct e820_entry *entries, u32 count) {
    while (count > MAX_MMAP) {
        int dropped = 0;
        for (u32 i = 0; i < count; i++) {
            if (entries[i].type == E820_USABLE) continue;
            entries[i] = entries[count - 1];
            count--;
            dropped = 1;
            break;
        }
        if (!dropped) break;
    }
    return count > MAX_MMAP ? MAX_MMAP : count;
}

static int ascii_to_utf16(u16 *out, u32 cap, const char *in) {
    u32 n = 0;
    while (in[n] && n + 1 < cap) {
        out[n] = (u8)in[n];
        n++;
    }
    if (in[n]) return -1;
    out[n] = 0;
    return 0;
}

static efi_status read_file(struct efi_file *root, const char *path,
                            void *buffer, u64 size) {
    u16 name[64];
    struct efi_file *file = 0;
    u64 got = size;
    efi_status st;
    if (ascii_to_utf16(name, 64, path)) return 1;
    st = root->open(root, &file, name, EFI_FILE_MODE_READ, 0);
    if (st || !file) return st ? st : 1;
    st = file->read(file, &got, buffer);
    file->close(file);
    if (st) return st;
    return got == size ? 0 : 1;
}

static void *find_rsdp(struct efi_system_table *st) {
    void *acpi10 = 0;
    for (u64 i = 0; i < st->number_of_table_entries; i++) {
        struct efi_config_table *t = &st->configuration_table[i];
        if (guid_equal(&t->vendor_guid, &acpi20_guid)) return t->vendor_table;
        if (guid_equal(&t->vendor_guid, &acpi10_guid)) acpi10 = t->vendor_table;
    }
    return acpi10;
}

static void load_pages(efi_phys pml4) {
    u64 *l4 = (u64 *)pml4;
    u64 *l3 = (u64 *)(pml4 + 4096);
    u64 *l2 = (u64 *)(pml4 + 8192);
    zero_bytes(l4, 4096 * 3);
    l4[0] = (pml4 + 4096) | 3;
    l3[0] = (pml4 + 8192) | 3;
    for (u32 i = 0; i < 512; i++)
        l2[i] = ((u64)i << 21) | 0x83;
}

efi_status __attribute__((ms_abi)) efi_main(efi_handle image,
                                            struct efi_system_table *st) {
    struct efi_boot_services *bs;
    struct efi_loaded_image *loaded = 0;
    struct efi_simple_fs *fs = 0;
    struct efi_file *root = 0;
    struct efi_gop *gop = 0;
    u8 header[512];
    void *blob = 0;
    u32 blob_bytes;
    u32 kernel_off;
    u32 kernel_len;
    u32 entry_off;
    u32 mod_count;
    u32 module_base;
    u32 bss_off;
    u32 bss_len;
    u32 kernel_span;
    struct bd_info *info;
    struct e820_entry *mmap;
    struct bd_module *mods;
    char *strings;
    struct efi_rsdp *rsdp_src;
    struct efi_rsdp rsdp_local;
    struct efi_memory_desc *efi_map = 0;
    struct e820_entry raw[MAX_MMAP_RAW];
    u64 fb_addr = 0;
    u32 fb_width = 0;
    u32 fb_height = 0;
    u32 fb_pitch = 0;
    u8 fb_bpp = 0;
    u8 fb_type = 0;
    u64 map_size = 8192;
    u64 map_key = 0;
    u64 desc_size = 0;
    u32 desc_version = 0;
    u32 e820_n = 0;
    efi_status status;
    u64 cr4;

    serial_init();
    serial_puts("BigDevBoot UEFI 0.2.0 by ukdaemonz\r\n");
    if (!st || !st->boot_services) fail("uefi: no boot services\r\n");
    bs = st->boot_services;

    if (bs->handle_protocol(image, &loaded_image_guid, (void **)&loaded) ||
        !loaded || !loaded->device_handle)
        fail("uefi: loaded image FAIL\r\n");
    if (bs->handle_protocol(loaded->device_handle, &simple_fs_guid,
                            (void **)&fs) || !fs)
        fail("uefi: file system FAIL\r\n");
    if (fs->open_volume(fs, &root) || !root)
        fail("uefi: volume FAIL\r\n");
    if (read_file(root, "\\EFI\\MICH\\BLOB", header, 512))
        fail("uefi: blob header FAIL\r\n");
    if (*(u32 *)header != BLOB_MAGIC) fail("uefi: blob magic FAIL\r\n");
    blob_bytes = *(u32 *)(header + 4) * 512;
    kernel_off = *(u32 *)(header + 8);
    kernel_len = *(u32 *)(header + 12);
    entry_off = *(u32 *)(header + 16);
    mod_count = *(u32 *)(header + 20);
    module_base = *(u32 *)(header + 224);
    bss_off = *(u32 *)(header + 228);
    bss_len = *(u32 *)(header + 232);
    kernel_span = kernel_len;
    if (bss_len && bss_off + bss_len > kernel_span)
        kernel_span = bss_off + bss_len;
    // The kernel and the modules laid out above it share the window below
    // MODULE_LIMIT, and the module copy below enforces its half of that
    // limit. A kernel image that alone overflows the window has nowhere to
    // go, so this check holds the same ceiling.
    if (!blob_bytes || blob_bytes > 0x200000 || kernel_off < 512 ||
        !kernel_len || kernel_span > MODULE_LIMIT ||
        kernel_off + kernel_len > blob_bytes || mod_count > MAX_MODS ||
        module_base < 0x100000 || module_base >= MODULE_LIMIT)
        fail("uefi: blob bounds FAIL\r\n");

    status = bs->allocate_pool(EFI_LOADER_DATA, blob_bytes, &blob);
    if (status || !blob) fail("uefi: blob pool FAIL\r\n");
    if (read_file(root, "\\EFI\\MICH\\BLOB", blob, blob_bytes))
        fail("uefi: blob read FAIL\r\n");
    serial_puts("uefi: blob loaded\r\n");

    if (!bs->locate_protocol(&gop_guid, 0, (void **)&gop) && gop &&
        gop->mode && gop->mode->info && gop->mode->framebuffer &&
        gop->mode->info->pixel_format < 2) {
        fb_addr = gop->mode->framebuffer;
        fb_width = gop->mode->info->width;
        fb_height = gop->mode->info->height;
        fb_pitch = gop->mode->info->pixels_per_scanline * 4;
        fb_bpp = 32;
        fb_type = 1;
    }

    rsdp_src = find_rsdp(st);
    if (!rsdp_src) fail("uefi: RSDP FAIL\r\n");
    {
        u32 n = 20;
        zero_bytes(&rsdp_local, sizeof(rsdp_local));
        if (rsdp_src->revision >= 2 && rsdp_src->length >= 36 &&
            rsdp_src->length <= sizeof(rsdp_local))
            n = rsdp_src->length;
        copy_bytes(&rsdp_local, rsdp_src, n);
    }
    serial_puts("uefi: rsdp ");
    serial_hex((u64)(uptr_t)rsdp_src);
    serial_puts(" xsdt ");
    serial_hex(rsdp_local.revision >= 2 ? rsdp_local.xsdt_address :
               rsdp_local.rsdt_address);
    serial_puts("\r\n");

    if (bs->allocate_pool(EFI_LOADER_DATA, map_size, (void **)&efi_map))
        fail("uefi: mmap pool FAIL\r\n");
    for (;;) {
        status = bs->get_memory_map(&map_size, efi_map, &map_key, &desc_size,
                                    &desc_version);
        if (!status) break;
        if (status != EFI_BUFFER_TOO_SMALL) fail("uefi: mmap FAIL\r\n");
        if (bs->free_pool(efi_map)) fail("uefi: mmap grow FAIL\r\n");
        map_size += 4096;
        if (bs->allocate_pool(EFI_LOADER_DATA, map_size, (void **)&efi_map))
            fail("uefi: mmap pool FAIL\r\n");
    }
    if (desc_size < 32) fail("uefi: mmap desc FAIL\r\n");
    {
        u8 *cursor = (u8 *)efi_map;
        u8 *end = cursor + map_size;
        while (cursor + desc_size <= end && e820_n < MAX_MMAP_RAW) {
            struct efi_memory_desc *d = (struct efi_memory_desc *)cursor;
            if (d->pages) {
                raw[e820_n].addr = d->physical;
                raw[e820_n].len = d->pages * 4096;
                raw[e820_n].type = e820_type(d->type);
                raw[e820_n].acpi = 1;
                e820_n++;
            }
            cursor += desc_size;
        }
    }
    e820_n = shrink_mmap(raw, coalesce_mmap(raw, e820_n));
    if (!e820_n) fail("uefi: empty mmap FAIL\r\n");
    serial_puts("uefi: mmap done\r\n");

    status = bs->exit_boot_services(image, map_key);
    if (status) {
        status = bs->get_memory_map(&map_size, efi_map, &map_key, &desc_size,
                                    &desc_version);
        if (status || bs->exit_boot_services(image, map_key))
            fail("uefi: ExitBootServices FAIL\r\n");
    }
    serial_puts("uefi: boot services exited\r\n");
    copy_bytes((void *)BLOB_BASE, blob, blob_bytes);
    blob = (void *)BLOB_BASE;
    serial_puts("uefi: blob relocated\r\n");
    load_pages(PAGE_BASE);
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 &= ~(1ULL << 17);
    __asm__ volatile("mov %0, %%cr4" : : "r"(cr4) : "memory");
    __asm__ volatile("mov %0, %%cr3" : : "r"(PAGE_BASE) : "memory");
    serial_puts("uefi: cr3 loaded\r\n");
    copy_bytes((void *)0x100000, (u8 *)blob + kernel_off, kernel_len);
    {
        u32 i;
        u32 cursor = module_base;
        for (i = 0; i < mod_count; i++) {
            u32 off = *(u32 *)((u8 *)blob + 24 + i * 24);
            u32 size = *(u32 *)((u8 *)blob + 24 + i * 24 + 4);
            u32 aligned;
            if (!size || off + size > blob_bytes)
                fail("uefi: mod FAIL\r\n");
            aligned = (size + 0xFFF) & ~0xFFFu;
            copy_bytes((void *)(uptr_t)cursor, (u8 *)blob + off, size);
            cursor += aligned;
            if (cursor > MODULE_LIMIT) fail("uefi: mod overflow FAIL\r\n");
        }
    }
    // The kernel bss spans tens of megabytes and this loader is linked at
    // LOADER_BASE, inside that span: zeroing it in one pass erases the code
    // currently executing. Clear everything except the window the loader
    // occupies; the jump stub below clears that window as its last act, once
    // no further C code will run. The bss must also be cleared only after the
    // kernel and modules have been copied out of the blob.
    if (bss_len) {
        u64 lo = 0x100000 + bss_off;
        u64 hi = lo + bss_len;
        u64 keep_lo = LOADER_BASE;
        u64 keep_hi = LOADER_BASE + LOADER_SPAN;
        if (hi <= keep_lo || lo >= keep_hi) {
            zero_bytes((void *)(uptr_t)lo, bss_len);
        } else {
            if (lo < keep_lo) zero_bytes((void *)(uptr_t)lo, keep_lo - lo);
            if (hi > keep_hi)
                zero_bytes((void *)(uptr_t)keep_hi, hi - keep_hi);
        }
    }

    zero_bytes((void *)INFO_BASE, 8192);
    info = (struct bd_info *)INFO_BASE;
    mmap = (struct e820_entry *)(info + 1);
    mods = (struct bd_module *)(mmap + MAX_MMAP);
    strings = (char *)(mods + MAX_MODS);
    {
        struct efi_rsdp *rsdp_copy = (struct efi_rsdp *)(strings + MAX_MODS * 24);
        u32 i;
        u32 cursor = module_base;
        copy_bytes(mmap, raw, (u64)e820_n * sizeof(raw[0]));
        for (i = 0; i < mod_count; i++) {
            u32 size = *(u32 *)((u8 *)blob + 24 + i * 24 + 4);
            u32 aligned = (size + 0xFFF) & ~0xFFFu;
            copy_bytes(strings + i * 24, (u8 *)blob + 24 + i * 24 + 8, 16);
            mods[i].start = cursor;
            mods[i].end = cursor + size;
            mods[i].cmdline = (u32)(uptr_t)(strings + i * 24);
            mods[i].flags = *(u32 *)((u8 *)blob + 236 + i * 4);
            cursor += aligned;
        }
        copy_bytes(rsdp_copy, &rsdp_local, sizeof(rsdp_local));
        info->magic = BD_MAGIC;
        info->version = BD_VERSION_UEFI;
        info->fb_addr = fb_addr;
        info->fb_width = fb_width;
        info->fb_height = fb_height;
        info->fb_pitch = fb_pitch;
        info->fb_bpp = fb_bpp;
        info->fb_type = fb_type;
        info->mmap_count = e820_n;
        info->mmap_ptr = (u32)(uptr_t)mmap;
        info->mods_count = mod_count;
        info->mods_ptr = (u32)(uptr_t)mods;
        info->rsdp_ptr = (u32)(uptr_t)rsdp_copy;
    }

    // The kernel writes to the UART without polling the line status register,
    // so anything still in flight here is lost and its first markers come out
    // corrupted. Drain the transmitter before handing over.
    {
        u32 spin = 0;
        while (spin++ < 100000 && (inb(0x3FD) & 0x60) != 0x60) {}
    }
    serial_puts("uefi: jumping to kernel\r\n");
    {
        u32 spin = 0;
        while (spin++ < 100000 && (inb(0x3FD) & 0x60) != 0x60) {}
    }
    {
        // The bss window this image occupies cannot be cleared by code living
        // inside it: rep stosb would erase the instructions queued behind it.
        // Copy a tiny stub to a scratch page outside both the bss and the
        // loader, jump to it, and let it do the clear and the handover from
        // there. The stub takes rdi/rcx/rax for the clear and r8/r9/r10 for
        // the kernel arguments and target.
        static const u8 stub[] = {
            0xFC,                          // cld
            0xF3, 0xAA,                    // rep stosb
            0x4C, 0x89, 0xC7,              // mov rdi, r8
            0x4C, 0x89, 0xCE,              // mov rsi, r9
            0x41, 0xFF, 0xE2               // jmp r10
        };
        u64 lo = 0x100000 + bss_off;
        u64 hi = bss_len ? lo + bss_len : 0;
        u64 clear_from = LOADER_BASE;
        u64 clear_count = 0;
        if (bss_len && hi > LOADER_BASE && lo < LOADER_BASE + LOADER_SPAN) {
            clear_from = lo > LOADER_BASE ? lo : LOADER_BASE;
            u64 end = hi < LOADER_BASE + LOADER_SPAN
                          ? hi : LOADER_BASE + LOADER_SPAN;
            clear_count = end - clear_from;
        }
        copy_bytes((void *)STUB_BASE, stub, sizeof(stub));
        register u64 arg_magic __asm__("r8") = BD_MAGIC;
        register u64 arg_info __asm__("r9") = INFO_BASE;
        register u64 arg_entry __asm__("r10") = 0x100000 + entry_off;
        register u64 arg_stub __asm__("r11") = STUB_BASE;
        __asm__ volatile(
            "cli\n\t"
            "jmp *%%r11\n\t"
            :
            : "D"(clear_from), "c"(clear_count), "a"(0ULL),
              "r"(arg_magic), "r"(arg_info), "r"(arg_entry), "r"(arg_stub)
            : "memory");
    }
    fail("uefi: kernel return FAIL\r\n");
    return 1;
}
