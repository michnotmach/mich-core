#include "pmm.h"
#include "serial.h"
#include "protos.h"
#include "klock.h"
#include "scheduler.h"

#define PAGE_SIZE 4096
#define BITMAP_SIZE 0x20000
#define BITMAP_BITS (BITMAP_SIZE * 8)
#define E820_USABLE 1

// S2's transitional cover for the allocator: the bitmap, the page refcounts
// and the free count move together, and two CPUs reach them at once now.
static struct klock pmm_klock = KLOCK_INIT(KLOCK_LEVEL_PMM);

// The single page path used to rescan the bitmap on every call, and that
// scan is what made the allocator lock queue up as CPUs were added. The
// reserve turns a call into a pop and scans once per refill instead. A
// cached page stays claimed, bitmap bit set and refcount one, so no scan
// can hand it out twice and pmm_free_pages adds the reserve back: the
// leak checks compare that count for exact equality.
#define PMM_RESERVE_MAX 8u
#define PMM_HIGH_START (0x1000000 / PAGE_SIZE)

static u32 pmm_page_reserve[KLOCK_MAX_CPUS][PMM_RESERVE_MAX];
static u32 pmm_reserve_count[KLOCK_MAX_CPUS];
static u32 pmm_cached_pages;

struct e820_entry {
    unsigned long long addr;
    unsigned long long len;
    unsigned int type;
    unsigned int acpi;
};

static unsigned char bitmap[BITMAP_SIZE];
static unsigned char ram_bitmap[BITMAP_SIZE];
static unsigned short page_refs[BITMAP_BITS];
static unsigned int free_pages = 0;
static unsigned int max_page = 0;
static unsigned int alloc_page_limit = BITMAP_BITS;

void pmm_init(uptr_t mmap_addr, usize_t mmap_length, u32 entry_size, paddr_t kernel_end) {
    if (entry_size < 20 || !mmap_length || mmap_length % entry_size)
        panic_str("invalid E820 map");

    free_pages = 0;
    max_page = 0;
    alloc_page_limit = BITMAP_BITS;
    for (u32 i = 0; i < BITMAP_SIZE; i++) {
        bitmap[i] = 0xFF;
        ram_bitmap[i] = 0;
    }
    for (u32 i = 0; i < BITMAP_BITS; i++) page_refs[i] = 0;

    u32 ignored = 0;
    usize_t count = mmap_length / entry_size;
    for (usize_t index = 0; index < count; index++) {
        struct e820_entry *entry = (struct e820_entry *)(uptr_t)
            (mmap_addr + index * entry_size);
        if (entry->type != E820_USABLE) continue;
        u64 region_end = entry->addr + entry->len;
        if (region_end < entry->addr) region_end = ~0ULL;
        u64 start = (entry->addr + PAGE_SIZE - 1) & ~(u64)(PAGE_SIZE - 1);
        u64 end = region_end & ~(u64)(PAGE_SIZE - 1);
        if (start < entry->addr) start = ~0ULL;
        for (u64 addr = start; addr < end; addr += PAGE_SIZE) {
            u64 page = addr / PAGE_SIZE;
            if (page < BITMAP_BITS) {
                u8 mask = (u8)(1u << (page % 8));
                ram_bitmap[page / 8] |= mask;
                if (bitmap[page / 8] & mask) {
                    bitmap[page / 8] &= (u8)~mask;
                    free_pages++;
                }
                if ((u32)page > max_page) max_page = (u32)page;
            } else {
                ignored = 1;
            }
        }
    }

    const u64 managed_end = (u64)BITMAP_BITS * PAGE_SIZE;
    for (usize_t index = 0; index < count; index++) {
        struct e820_entry *entry = (struct e820_entry *)(uptr_t)
            (mmap_addr + index * entry_size);
        if (entry->type == E820_USABLE || entry->addr >= managed_end) continue;
        u64 length = entry->len;
        if (length > managed_end - entry->addr) length = managed_end - entry->addr;
        pmm_reserve((paddr_t)entry->addr, (usize_t)length);
    }

    if (ignored) serial_write("PMM: WARNING RAM above 4GB ignored\n");
    pmm_reserve(0, 0x100000);
    pmm_reserve(0x100000, kernel_end - 0x100000);
}

void pmm_reserve(paddr_t addr, usize_t len) {
    if (!len) return;

    const unsigned long long managed_end = (unsigned long long)BITMAP_BITS * PAGE_SIZE;
    unsigned long long first = (unsigned long long)addr & ~(unsigned long long)(PAGE_SIZE - 1);
    unsigned long long end = (unsigned long long)addr + len;
    if (end > ~0ULL - (PAGE_SIZE - 1)) end = ~0ULL;
    else end = (end + PAGE_SIZE - 1) & ~(unsigned long long)(PAGE_SIZE - 1);

    if (first >= managed_end) return;
    if (end > managed_end) {
        end = managed_end;
        serial_write("PMM: WARNING reservation truncated at 4GB\n");
    }

    for (unsigned long long a = first; a < end; a += PAGE_SIZE) {
        unsigned int page = (unsigned int)(a / PAGE_SIZE);
        unsigned char mask = (unsigned char)(1u << (page % 8));
        if (!(bitmap[page / 8] & mask)) {
            bitmap[page / 8] |= mask;
            free_pages--;
        }
    }
}

void pmm_set_alloc_limit(paddr_t end) {
    u64 pages = (u64)end / PAGE_SIZE;
    if (pages > BITMAP_BITS) pages = BITMAP_BITS;
    alloc_page_limit = (u32)pages;
    for (u32 page = alloc_page_limit; page < BITMAP_BITS; page++) {
        u8 mask = (u8)(1u << (page % 8));
        if (!(bitmap[page / 8] & mask)) {
            bitmap[page / 8] |= mask;
            free_pages--;
        }
    }
}

static u32 pmm_cpu(void) {
    int cpu = scheduler_cpu_id();
    return cpu > 0 && (u32)cpu < KLOCK_MAX_CPUS ? (u32)cpu : 0;
}

// Only high pages are cached. Handing a low page back from the reserve
// would spend the memory pmm_alloc_page_low exists to keep available.
static void pmm_refill_locked(u32 cpu, u32 limit) {
    u32 count = 0;
    for (u32 page = PMM_HIGH_START; page < limit && count < PMM_RESERVE_MAX;
         page++) {
        if (bitmap[page / 8] & (1u << (page % 8))) continue;
        bitmap[page / 8] |= (u8)(1u << (page % 8));
        page_refs[page] = 1;
        free_pages--;
        pmm_page_reserve[cpu][count++] = page;
    }
    pmm_reserve_count[cpu] = count;
    pmm_cached_pages += count;
}

static paddr_t pmm_take_page(u32 page) {
    bitmap[page / 8] |= (u8)(1u << (page % 8));
    page_refs[page] = 1;
    free_pages--;
    return (paddr_t)page * PAGE_SIZE;
}

// The clear runs after the caller drops the lock, because the page is
// claimed by then and nobody else can reach it. Zeroing 4096 bytes under
// the allocator turns every other CPU's allocation into a wait, and the
// wait count grows faster than the allocation count as CPUs are added.
static void pmm_zero_page(paddr_t phys) {
#if __SIZEOF_POINTER__ == 8
    u8 *pointer = (u8 *)(uptr_t)phys;
    for (u32 i = 0; i < PAGE_SIZE; i++) pointer[i] = 0;
#else
    if (phys < 0x1000000) {
        u8 *pointer = (u8 *)(uptr_t)phys;
        for (u32 i = 0; i < PAGE_SIZE; i++) pointer[i] = 0;
    }
#endif
}

paddr_t pmm_alloc_page_range(paddr_t start, paddr_t end) {
    if (end <= start) return 0;
#if __SIZEOF_POINTER__ == 8
    if ((u64)start > ~0ULL - (PAGE_SIZE - 1)) return 0;
#endif
    u64 first64 = ((u64)start + PAGE_SIZE - 1) / PAGE_SIZE;
    u64 limit64 = (u64)end / PAGE_SIZE;
    if (first64 >= BITMAP_BITS) return 0;
    if (limit64 > alloc_page_limit) limit64 = alloc_page_limit;
    if (limit64 > (u64)max_page + 1) limit64 = (u64)max_page + 1;
    if (first64 < 1) first64 = 1;
    klock_acquire(&pmm_klock);
    for (u32 page = (u32)first64; page < (u32)limit64; page++) {
        if (!(bitmap[page / 8] & (1u << (page % 8)))) {
            paddr_t physical = pmm_take_page(page);
            klock_release(&pmm_klock);
            pmm_zero_page(physical);
            return physical;
        }
    }
    klock_release(&pmm_klock);
    return 0;
}

paddr_t pmm_alloc_page(void) {
    u32 high_start = PMM_HIGH_START;
    u32 limit = max_page + 1;
    if (limit > alloc_page_limit) limit = alloc_page_limit;
    klock_acquire(&pmm_klock);
    u32 cpu = pmm_cpu();
    if (!pmm_reserve_count[cpu] && limit > high_start)
        pmm_refill_locked(cpu, limit);
    if (pmm_reserve_count[cpu]) {
        u32 page = pmm_page_reserve[cpu][--pmm_reserve_count[cpu]];
        pmm_cached_pages--;
        paddr_t physical = (paddr_t)page * PAGE_SIZE;
        klock_release(&pmm_klock);
        pmm_zero_page(physical);
        return physical;
    }
    for (u32 page = 1; page < high_start && page < limit; page++) {
        if (!(bitmap[page / 8] & (1u << (page % 8)))) {
            paddr_t physical = pmm_take_page(page);
            klock_release(&pmm_klock);
            pmm_zero_page(physical);
            return physical;
        }
    }
    klock_release(&pmm_klock);
    return 0;
}

paddr_t pmm_alloc_page_low(void) {
    u32 limit = 0x1000000 / PAGE_SIZE;
    if (limit > alloc_page_limit) limit = alloc_page_limit;
    if (limit > max_page + 1) limit = max_page + 1;
    klock_acquire(&pmm_klock);
    for (u32 page = 1; page < limit; page++) {
        if (!(bitmap[page / 8] & (1u << (page % 8)))) {
            paddr_t physical = pmm_take_page(page);
            klock_release(&pmm_klock);
            pmm_zero_page(physical);
            return physical;
        }
    }
    klock_release(&pmm_klock);
    return 0;
}

paddr_t pmm_alloc_contiguous(u32 pages, paddr_t max_addr) {
    klock_acquire(&pmm_klock);
    if (!pages || pages > free_pages) {
        klock_release(&pmm_klock);
        return 0;
    }

    u64 address_limit = (u64)max_addr + 1;
    u32 page_limit = address_limit ? (u32)(address_limit / PAGE_SIZE)
                                   : alloc_page_limit;
    if (page_limit > alloc_page_limit) page_limit = alloc_page_limit;
    if (page_limit > max_page + 1) page_limit = max_page + 1;
    if (pages > page_limit) {
        klock_release(&pmm_klock);
        return 0;
    }

    unsigned int run = 0;
    unsigned int run_start = 0;
    for (unsigned int page = 1; page < page_limit; page++) {
        if (!(bitmap[page / 8] & (1u << (page % 8)))) {
            if (!run) run_start = page;
            run++;
            if (run == pages) {
                for (unsigned int i = 0; i < pages; i++) {
                    bitmap[(run_start + i) / 8] |=
                        (unsigned char)(1u << ((run_start + i) % 8));
                    page_refs[run_start + i] = 1;
                }
                free_pages -= pages;
                klock_release(&pmm_klock);
                return run_start * PAGE_SIZE;
            }
        } else {
            run = 0;
        }
    }
    klock_release(&pmm_klock);
    return 0;
}

void pmm_free_page(paddr_t addr) {
    if (addr & (PAGE_SIZE - 1)) panic_str("PMM unaligned free");
    u64 page64 = (u64)addr / PAGE_SIZE;
    if (!page64 || page64 >= BITMAP_BITS) panic_str("PMM invalid free");
    unsigned int page = (unsigned int)page64;
    klock_acquire(&pmm_klock);
    if (!page_refs[page]) panic_str("PMM double free");
    page_refs[page]--;
    if (!page_refs[page]) {
        u32 cpu = pmm_cpu();
        if (page >= PMM_HIGH_START &&
            pmm_reserve_count[cpu] < PMM_RESERVE_MAX) {
            page_refs[page] = 1;
            pmm_page_reserve[cpu][pmm_reserve_count[cpu]++] = page;
            pmm_cached_pages++;
        } else {
            bitmap[page / 8] &= (unsigned char)~(1u << (page % 8));
            free_pages++;
        }
    }
    klock_release(&pmm_klock);
}

int pmm_retain_page(paddr_t addr) {
    if (addr & (PAGE_SIZE - 1)) return -1;
    u64 page64 = (u64)addr / PAGE_SIZE;
    if (page64 >= BITMAP_BITS) return -1;
    unsigned int page = (unsigned int)page64;
    klock_acquire(&pmm_klock);
    if (!page_refs[page] || page_refs[page] == 0xFFFF) {
        klock_release(&pmm_klock);
        return -1;
    }
    page_refs[page]++;
    klock_release(&pmm_klock);
    return 0;
}

u32 pmm_page_refs(paddr_t addr) {
    u64 page = (u64)addr / PAGE_SIZE;
    if (page >= BITMAP_BITS) return 0;
    klock_acquire(&pmm_klock);
    u32 refs = page_refs[(u32)page];
    klock_release(&pmm_klock);
    return refs;
}

u32 pmm_free_pages(void) {
    klock_acquire(&pmm_klock);
    u32 count = free_pages + pmm_cached_pages;
    klock_release(&pmm_klock);
    return count;
}

int pmm_range_is_ram(paddr_t addr, usize_t len) {
    if (!len) return 0;
    unsigned long long start = (unsigned long long)addr &
                               ~(unsigned long long)(PAGE_SIZE - 1);
    unsigned long long address = (unsigned long long)addr;
    unsigned long long end;
    if ((unsigned long long)len > ~0ULL - address)
        end = ~0ULL;
    else
        end = address + (unsigned long long)len;
    if (end > 0x100000000ULL) end = 0x100000000ULL;
    if (end < 0x100000000ULL)
        end = (end + PAGE_SIZE - 1) &
              ~(unsigned long long)(PAGE_SIZE - 1);

    for (unsigned long long a = start; a < end; a += PAGE_SIZE) {
        unsigned long long page = a / PAGE_SIZE;
        if (page < BITMAP_BITS &&
            (ram_bitmap[page / 8] & (unsigned char)(1u << (page % 8))))
            return 1;
    }
    return 0;
}
