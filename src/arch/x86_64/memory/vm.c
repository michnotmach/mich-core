#include "vm64.h"
#include "pmm.h"
#include "object.h"
#include "resource.h"
#include "klock.h"

// One lock over the whole address-space table: a fork marks the
// parent pages copy-on-write and a revoke unmaps mappings that
// belong to other spaces, so both write page tables another CPU
// is executing from.
static struct klock vm_klock = KLOCK_INIT(KLOCK_LEVEL_VM);

#define PAGE_HUGE 0x80ULL
#define PAGE_OWNED 0x200ULL
#define PAGE_COW VM64_PAGE_COW
#define VM64_MAX_SPACES 16
#define VM64_MAPPING_MAX 16
#define VM64_PHYS_MASK 0x000FFFFFFFFFF000ULL
#define KERNEL_MMIO_PTS (VM64_KERNEL_MMIO_SIZE >> 21)
#define KERNEL_MMIO_PAGES (VM64_KERNEL_MMIO_SIZE >> 12)
#define MSR_PAT 0x277

struct vm64_object_mapping {
    struct kernel_object *object;
    vaddr_t virtual;
    usize_t length;
};

struct vm64_space {
    paddr_t pml4;
    paddr_t pdpt;
    paddr_t identity_pd;
    paddr_t identity_pt0;
    paddr_t user_pd;
    paddr_t user_pts[512];
    struct vm64_object_mapping mappings[VM64_MAPPING_MAX];
};

static struct vm64_space spaces[VM64_MAX_SPACES];
static paddr_t kernel_mmio_pdpt;
static paddr_t kernel_mmio_pd;
static paddr_t kernel_mmio_pts[KERNEL_MMIO_PTS];
static u8 kernel_mmio_used[KERNEL_MMIO_PAGES];

extern u8 _text_start;
extern u8 _text_end;
extern u8 _rodata_start;
extern u8 _rodata_end;

static u64 *table(paddr_t physical) {
    return (u64 *)(uptr_t)physical;
}

static void invlpg(vaddr_t virtual) {
    __asm__ volatile("invlpg (%0)" : : "r"(virtual) : "memory");
}

static void copy_page(paddr_t destination, paddr_t source) {
    // GPR copies only: the kernel is built with -mgeneral-regs-only because
    // fault/interrupt/syscall entries do not save user XMM state, so an SSE
    // copy here would corrupt live user XMM registers.
    u64 *dst = (u64 *)(uptr_t)destination;
    const u64 *src = (const u64 *)(uptr_t)source;
    for (u32 index = 0; index < 4096 / sizeof(u64); index++)
        dst[index] = src[index];
}

static u64 rdmsr(u32 msr) {
    u32 low;
    u32 high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((u64)high << 32) | low;
}

static void wrmsr(u32 msr, u64 value) {
    __asm__ volatile("wrmsr" : : "c"(msr), "a"((u32)value),
                     "d"((u32)(value >> 32)) : "memory");
}

static u64 cache_flags(u32 cache_mode) {
    if (cache_mode == VM64_CACHE_UC) return 0x18;
    if (cache_mode == VM64_CACHE_WC) return 0x08;
    return cache_mode == VM64_CACHE_WB ? 0 : ~0ULL;
}

void vm64_activate(paddr_t root) {
    __asm__ volatile("mov %0, %%cr3" : : "r"(root) : "memory");
}

static int allocate_space_tables(struct vm64_space *space) {
    space->pml4 = pmm_alloc_page();
    space->pdpt = pmm_alloc_page();
    space->identity_pd = pmm_alloc_page();
    space->identity_pt0 = pmm_alloc_page();
    space->user_pd = pmm_alloc_page();
    if (!space->pml4 || !space->pdpt || !space->identity_pd ||
        !space->identity_pt0 || !space->user_pd) {
        if (space->pml4) pmm_free_page(space->pml4);
        if (space->pdpt) pmm_free_page(space->pdpt);
        if (space->identity_pd) pmm_free_page(space->identity_pd);
        if (space->identity_pt0) pmm_free_page(space->identity_pt0);
        if (space->user_pd) pmm_free_page(space->user_pd);
        space->pml4 = 0;
        space->pdpt = 0;
        space->identity_pd = 0;
        space->identity_pt0 = 0;
        space->user_pd = 0;
        return -1;
    }
    return 0;
}

static int vm64_create_space_locked(u32 *space_out) {
    if (!space_out) return -1;
    for (u32 index = 0; index < VM64_MAX_SPACES; index++) {
        struct vm64_space *space = &spaces[index];
        if (space->pml4) continue;
        if (allocate_space_tables(space)) return -1;
        for (u32 page = 0; page < 512; page++) space->user_pts[page] = 0;
        for (u32 map = 0; map < VM64_MAPPING_MAX; map++) {
            space->mappings[map].object = 0;
            space->mappings[map].virtual = 0;
            space->mappings[map].length = 0;
        }
        u64 *pml4 = table(space->pml4);
        u64 *pdpt = table(space->pdpt);
        u64 *identity_pd = table(space->identity_pd);
        u64 *identity_pt0 = table(space->identity_pt0);
        pml4[0] = space->pdpt | VM64_PAGE_PRESENT | VM64_PAGE_WRITE |
                  VM64_PAGE_USER;
        pml4[256] = kernel_mmio_pdpt | VM64_PAGE_PRESENT | VM64_PAGE_WRITE;
        pdpt[0] = space->identity_pd | VM64_PAGE_PRESENT | VM64_PAGE_WRITE;
        pdpt[4] = space->user_pd | VM64_PAGE_PRESENT | VM64_PAGE_WRITE |
                  VM64_PAGE_USER;
        identity_pd[0] = space->identity_pt0 |
                         VM64_PAGE_PRESENT | VM64_PAGE_WRITE;
        u64 text_start = (u64)(uptr_t)&_text_start;
        u64 text_end = (u64)(uptr_t)&_text_end;
        u64 rodata_start = (u64)(uptr_t)&_rodata_start;
        u64 rodata_end = (u64)(uptr_t)&_rodata_end;
        for (u32 entry = 0; entry < 512; entry++) {
            u64 physical = (u64)entry << 12;
            u64 flags = VM64_PAGE_PRESENT | VM64_PAGE_WRITE | VM64_PAGE_NX;
            if (physical >= text_start && physical < text_end)
                flags = VM64_PAGE_PRESENT;
            else if (physical >= rodata_start && physical < rodata_end)
                flags = VM64_PAGE_PRESENT | VM64_PAGE_NX;
            identity_pt0[entry] = physical | flags;
        }
        for (u32 entry = 1; entry < 512; entry++)
            identity_pd[entry] = ((u64)entry << 21) | VM64_PAGE_PRESENT |
                                 VM64_PAGE_WRITE | VM64_PAGE_NX | PAGE_HUGE;
        *space_out = index;
        return 0;
    }
    return -1;
}

paddr_t vm64_root(u32 index) {
    return index < VM64_MAX_SPACES ? spaces[index].pml4 : 0;
}

u32 vm64_available_pages(void) {
    return pmm_free_pages();
}

paddr_t vm64_alloc_page(void) {
    return pmm_alloc_page();
}

int vm64_free_page(paddr_t physical) {
    if (!physical || (physical & 0xFFF) || !pmm_page_refs(physical)) return -1;
    pmm_free_page(physical);
    return 0;
}

static u64 *ensure_user_pt(struct vm64_space *space, u32 pd_index) {
    if (pd_index >= 512) return 0;
    if (!space->user_pts[pd_index]) {
        paddr_t physical = pmm_alloc_page();
        if (!physical) return 0;
        space->user_pts[pd_index] = physical;
        table(space->user_pd)[pd_index] = physical | VM64_PAGE_PRESENT |
                                          VM64_PAGE_WRITE | VM64_PAGE_USER;
    }
    return table(space->user_pts[pd_index]);
}

static u64 *user_pte(struct vm64_space *space, vaddr_t virtual, int create) {
    if (!space || !space->pml4 || virtual < VM64_USER_BASE ||
        virtual >= VM64_USER_LIMIT)
        return 0;
    u64 relative = virtual - VM64_USER_BASE;
    u32 pd_index = (u32)(relative >> 21);
    u32 pt_index = (u32)((relative >> 12) & 0x1FF);
    u64 *pt = create ? ensure_user_pt(space, pd_index) :
                       space->user_pts[pd_index] ?
                       table(space->user_pts[pd_index]) : 0;
    return pt ? &pt[pt_index] : 0;
}

static void release_empty_pt(struct vm64_space *space, u32 pd_index) {
    if (!space->user_pts[pd_index]) return;
    u64 *pt = table(space->user_pts[pd_index]);
    for (u32 index = 0; index < 512; index++)
        if (pt[index] & VM64_PAGE_PRESENT) return;
    pmm_free_page(space->user_pts[pd_index]);
    space->user_pts[pd_index] = 0;
    table(space->user_pd)[pd_index] = 0;
}

static void vm64_destroy_space_locked(u32 index) {
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4) return;
    struct vm64_space *space = &spaces[index];
    for (u32 pd_index = 0; pd_index < 512; pd_index++) {
        if (!space->user_pts[pd_index]) continue;
        u64 *pt = table(space->user_pts[pd_index]);
        for (u32 entry = 0; entry < 512; entry++) {
            if ((pt[entry] & (VM64_PAGE_PRESENT | PAGE_OWNED)) ==
                (VM64_PAGE_PRESENT | PAGE_OWNED))
                vm64_free_page(pt[entry] & VM64_PHYS_MASK);
            pt[entry] = 0;
        }
        pmm_free_page(space->user_pts[pd_index]);
        space->user_pts[pd_index] = 0;
    }
    for (u32 map = 0; map < VM64_MAPPING_MAX; map++) {
        if (space->mappings[map].object) {
            page_resource_mapping_close(space->mappings[map].object);
            object_release(space->mappings[map].object);
        }
        space->mappings[map].object = 0;
    }
    pmm_free_page(space->user_pd);
    pmm_free_page(space->identity_pt0);
    pmm_free_page(space->identity_pd);
    pmm_free_page(space->pdpt);
    pmm_free_page(space->pml4);
    space->pml4 = 0;
    space->pdpt = 0;
    space->identity_pd = 0;
    space->identity_pt0 = 0;
    space->user_pd = 0;
}

static int vm64_handle_cow_locked(u32 index, vaddr_t virtual) {
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4) return -1;
    u64 *pte = user_pte(&spaces[index], virtual, 0);
    if (!pte) return -1;
    u64 old = *pte;
    if ((old & (VM64_PAGE_PRESENT | PAGE_OWNED | PAGE_COW | VM64_PAGE_USER)) !=
        (VM64_PAGE_PRESENT | PAGE_OWNED | PAGE_COW | VM64_PAGE_USER))
        return -1;
    paddr_t old_phys = (paddr_t)(old & VM64_PHYS_MASK);
    u64 flags = (old & ~VM64_PHYS_MASK & ~PAGE_COW) | VM64_PAGE_WRITE;
    u32 refs = pmm_page_refs(old_phys);
    if (!refs) return -1;
    if (refs == 1) {
        *pte = old_phys | flags;
        invlpg(virtual & ~0xFFFULL);
        return 0;
    }
    paddr_t fresh = vm64_alloc_page();
    if (!fresh) return -1;
    copy_page(fresh, old_phys);
    *pte = fresh | flags;
    pmm_free_page(old_phys);
    invlpg(virtual & ~0xFFFULL);
    return 0;
}

static int vm64_clone_space_locked(u32 source, u32 *destination) {
    if (source >= VM64_MAX_SPACES || !spaces[source].pml4 || !destination)
        return -1;
    u32 copy_index;
    if (vm64_create_space_locked(&copy_index)) return -1;
    struct vm64_space *src = &spaces[source];
    struct vm64_space *copy = &spaces[copy_index];
    for (u32 pd_index = 0; pd_index < 512; pd_index++) {
        if (!src->user_pts[pd_index]) continue;
        u64 *spt = table(src->user_pts[pd_index]);
        for (u32 entry = 0; entry < 512; entry++) {
            u64 pte = spt[entry];
            if ((pte & (VM64_PAGE_PRESENT | PAGE_OWNED)) !=
                (VM64_PAGE_PRESENT | PAGE_OWNED))
                continue;
            paddr_t phys = (paddr_t)(pte & VM64_PHYS_MASK);
            u64 flags = pte & ~VM64_PHYS_MASK;
            if (flags & VM64_PAGE_WRITE) {
                flags = (flags & ~VM64_PAGE_WRITE) | PAGE_COW;
                spt[entry] = phys | flags;
                vaddr_t virtual = VM64_USER_BASE + ((u64)pd_index << 21) +
                                  ((u64)entry << 12);
                invlpg(virtual);
            }
            if (pmm_retain_page(phys)) {
                vm64_destroy_space_locked(copy_index);
                return -1;
            }
            u64 *dpt = ensure_user_pt(copy, pd_index);
            if (!dpt || (dpt[entry] & VM64_PAGE_PRESENT)) {
                pmm_free_page(phys);
                vm64_destroy_space_locked(copy_index);
                return -1;
            }
            dpt[entry] = phys | flags;
        }
    }
    *destination = copy_index;
    return 0;
}

static int map_page(struct vm64_space *space, vaddr_t virtual,
                    paddr_t physical, u64 flags) {
    u64 *pte = user_pte(space, virtual, 1);
    if (!pte || (*pte & VM64_PAGE_PRESENT)) return -1;
    *pte = physical | flags;
    return 0;
}

static int vm64_map_locked(u32 index, vaddr_t virtual, paddr_t physical,
                           int writable, int executable) {
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4 ||
        (virtual & 0xFFF) || (physical & 0xFFF) ||
        !pmm_page_refs(physical))
        return -1;
    u64 flags = VM64_PAGE_PRESENT | VM64_PAGE_USER | PAGE_OWNED;
    if (writable) flags |= VM64_PAGE_WRITE;
    if (!executable) flags |= VM64_PAGE_NX;
    return map_page(&spaces[index], virtual, physical, flags);
}

static int vm64_unmap_locked(u32 index, vaddr_t virtual) {
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4 || (virtual & 0xFFF))
        return -1;
    u64 *pte = user_pte(&spaces[index], virtual, 0);
    if (!pte || (*pte & VM64_PAGE_PRESENT) == 0 ||
        (*pte & PAGE_OWNED) == 0)
        return -1;
    paddr_t phys = (paddr_t)(*pte & VM64_PHYS_MASK);
    *pte = 0;
    invlpg(virtual);
    pmm_free_page(phys);
    release_empty_pt(&spaces[index], (u32)((virtual - VM64_USER_BASE) >> 21));
    return 0;
}

u64 vm64_user_flags(u32 index, vaddr_t virtual) {
    if (index >= VM64_MAX_SPACES) return 0;
    u64 *pte = user_pte(&spaces[index], virtual, 0);
    return pte ? *pte & (VM64_PAGE_PRESENT | VM64_PAGE_WRITE |
                         VM64_PAGE_USER | PAGE_COW | VM64_PAGE_NX) : 0;
}

int vm64_init(void) {
    for (u32 index = 0; index < VM64_MAX_SPACES; index++)
        spaces[index].pml4 = 0;
    for (u32 index = 0; index < KERNEL_MMIO_PAGES; index++)
        kernel_mmio_used[index] = 0;
    kernel_mmio_pdpt = pmm_alloc_page();
    kernel_mmio_pd = pmm_alloc_page();
    if (!kernel_mmio_pdpt || !kernel_mmio_pd) {
        if (kernel_mmio_pdpt) pmm_free_page(kernel_mmio_pdpt);
        if (kernel_mmio_pd) pmm_free_page(kernel_mmio_pd);
        return -1;
    }
    table(kernel_mmio_pdpt)[0] = kernel_mmio_pd |
        VM64_PAGE_PRESENT | VM64_PAGE_WRITE;
    for (u32 index = 0; index < KERNEL_MMIO_PTS; index++) {
        kernel_mmio_pts[index] = pmm_alloc_page();
        if (!kernel_mmio_pts[index]) {
            for (u32 undo = 0; undo < index; undo++)
                pmm_free_page(kernel_mmio_pts[undo]);
            pmm_free_page(kernel_mmio_pd);
            pmm_free_page(kernel_mmio_pdpt);
            return -1;
        }
        table(kernel_mmio_pd)[index] = kernel_mmio_pts[index] |
            VM64_PAGE_PRESENT | VM64_PAGE_WRITE;
    }
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1), "c"(0));
    (void)eax;
    (void)ebx;
    (void)ecx;
    if (!(edx & (1u << 16))) {
        for (u32 index = 0; index < KERNEL_MMIO_PTS; index++)
            pmm_free_page(kernel_mmio_pts[index]);
        pmm_free_page(kernel_mmio_pd);
        pmm_free_page(kernel_mmio_pdpt);
        return -1;
    }
    u64 pat = rdmsr(MSR_PAT);
    pat = (pat & ~(0xFFULL << 8)) | (1ULL << 8);
    wrmsr(MSR_PAT, pat);
    u64 cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 1ULL << 16;
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
    return 0;
}

static struct vm64_space *space_from_root(paddr_t root) {
    if (!root) return 0;
    for (u32 index = 0; index < VM64_MAX_SPACES; index++)
        if (spaces[index].pml4 == root) return &spaces[index];
    return 0;
}

int vm64_user_access(paddr_t root, vaddr_t address, usize_t length,
                     int writable) {
    struct vm64_space *space = space_from_root(root);
    if (!space || address < VM64_USER_BASE || address >= VM64_USER_LIMIT ||
        length > VM64_USER_LIMIT - address)
        return -1;
    u32 index = (u32)(space - spaces);
    usize_t done = 0;
    while (done < length) {
        vaddr_t current = address + done;
        u64 *pte = user_pte(space, current, 0);
        if (!pte ||
            ((*pte & (VM64_PAGE_PRESENT | VM64_PAGE_USER)) !=
             (VM64_PAGE_PRESENT | VM64_PAGE_USER)))
            return -1;
        if (writable && !(*pte & VM64_PAGE_WRITE)) {
            if (!(*pte & PAGE_COW) || vm64_handle_cow(index, current))
                return -1;
            pte = user_pte(space, current, 0);
            if (!pte || !(*pte & VM64_PAGE_WRITE)) return -1;
        }
        usize_t count = 4096 - (current & 0xFFF);
        if (count > length - done) count = length - done;
        done += count;
    }
    return 0;
}

static int vm64_copy(paddr_t root, void *kernel_destination,
                     const void *kernel_source, vaddr_t user_address,
                     usize_t length, int to_user) {
    struct vm64_space *space = space_from_root(root);
    if (vm64_user_access(root, user_address, length, to_user)) return -1;
    u8 *kernel_dst = (u8 *)kernel_destination;
    const u8 *kernel_src = (const u8 *)kernel_source;
    usize_t done = 0;
    while (done < length) {
        vaddr_t address = user_address + done;
        u64 *pte = user_pte(space, address, 0);
        usize_t offset = address & 0xFFF;
        usize_t count = 4096 - offset;
        if (count > length - done) count = length - done;
        u8 *user = (u8 *)(uptr_t)(*pte & VM64_PHYS_MASK) + offset;
        for (usize_t byte = 0; byte < count; byte++) {
            if (to_user) user[byte] = kernel_src[done + byte];
            else kernel_dst[done + byte] = user[byte];
        }
        done += count;
    }
    return 0;
}

int vm64_copy_from(paddr_t root, void *kernel_dst, vaddr_t user_src,
                   usize_t length) {
    return vm64_copy(root, kernel_dst, 0, user_src, length, 0);
}

int vm64_copy_to(paddr_t root, vaddr_t user_dst, const void *kernel_src,
                 usize_t length) {
    return vm64_copy(root, 0, kernel_src, user_dst, length, 1);
}

static int vm64_map_object_locked(u32 index, vaddr_t virtual,
                                  struct kernel_object *object,
                                  paddr_t physical, usize_t length,
                                  int writable, u32 cache_mode) {
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4 || !object ||
        !object->active || virtual < VM64_DRIVER_BASE ||
        virtual >= VM64_DRIVER_LIMIT || !length || (virtual & 0xFFF) ||
        (physical & 0xFFF) || (length & 0xFFF) ||
        length > VM64_DRIVER_LIMIT - virtual)
        return -1;
    u64 caching = cache_flags(cache_mode);
    if (caching == ~0ULL) return -1;
    struct vm64_space *space = &spaces[index];
    u32 mapping_index = VM64_MAPPING_MAX;
    for (u32 map = 0; map < VM64_MAPPING_MAX; map++)
        if (!space->mappings[map].object) {
            mapping_index = map;
            break;
        }
    if (mapping_index == VM64_MAPPING_MAX || object_retain(object)) return -1;
    usize_t mapped = 0;
    u64 flags = VM64_PAGE_PRESENT | VM64_PAGE_USER | VM64_PAGE_NX | caching;
    if (writable) flags |= VM64_PAGE_WRITE;
    while (mapped < length) {
        if (map_page(space, virtual + mapped, physical + mapped, flags)) {
            while (mapped) {
                mapped -= 4096;
                u64 *pte = user_pte(space, virtual + mapped, 0);
                if (pte) *pte = 0;
            }
            u32 first_pd = (u32)((virtual - VM64_USER_BASE) >> 21);
            u32 last_pd = (u32)((virtual + length - 1 - VM64_USER_BASE) >> 21);
            for (u32 pd = first_pd; pd <= last_pd; pd++)
                release_empty_pt(space, pd);
            object_release(object);
            return -1;
        }
        mapped += 4096;
    }
    space->mappings[mapping_index].object = object;
    space->mappings[mapping_index].virtual = virtual;
    space->mappings[mapping_index].length = length;
    return 0;
}

static int vm64_map_page_object_locked(u32 index, vaddr_t virtual,
                                       struct kernel_object *object,
                                       int writable) {
    struct page_resource *resource = page_resource_get(object);
    usize_t length = resource ? (usize_t)resource->pages * 4096 : 0;
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4 || !resource ||
        resource->revoked || virtual < VM64_DRIVER_BASE ||
        virtual >= VM64_DRIVER_LIMIT || !length || (virtual & 0xFFF) ||
        length > VM64_DRIVER_LIMIT - virtual)
        return -1;
    struct vm64_space *space = &spaces[index];
    u32 mapping_index = VM64_MAPPING_MAX;
    for (u32 map = 0; map < VM64_MAPPING_MAX; map++)
        if (!space->mappings[map].object) {
            mapping_index = map;
            break;
        }
    if (mapping_index == VM64_MAPPING_MAX || object_retain(object)) return -1;
    if (page_resource_mapping_open(object)) {
        object_release(object);
        return -1;
    }
    usize_t mapped = 0;
    u64 flags = VM64_PAGE_PRESENT | VM64_PAGE_USER | VM64_PAGE_NX;
    if (writable) flags |= VM64_PAGE_WRITE;
    while (mapped < length) {
        u32 page = (u32)(mapped / 4096);
        if (map_page(space, virtual + mapped, resource->physical[page], flags)) {
            while (mapped) {
                mapped -= 4096;
                u64 *pte = user_pte(space, virtual + mapped, 0);
                if (pte) *pte = 0;
            }
            u32 first_pd = (u32)((virtual - VM64_USER_BASE) >> 21);
            u32 last_pd = (u32)((virtual + length - 1 - VM64_USER_BASE) >> 21);
            for (u32 pd = first_pd; pd <= last_pd; pd++)
                release_empty_pt(space, pd);
            page_resource_mapping_close(object);
            object_release(object);
            return -1;
        }
        mapped += 4096;
    }
    space->mappings[mapping_index].object = object;
    space->mappings[mapping_index].virtual = virtual;
    space->mappings[mapping_index].length = length;
    return 0;
}

static int vm64_unmap_object_locked(u32 index, vaddr_t virtual,
                                    usize_t length) {
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4) return -1;
    struct vm64_space *space = &spaces[index];
    u32 mapping_index = VM64_MAPPING_MAX;
    for (u32 map = 0; map < VM64_MAPPING_MAX; map++)
        if (space->mappings[map].object &&
            space->mappings[map].virtual == virtual &&
            space->mappings[map].length == length) {
            mapping_index = map;
            break;
        }
    if (mapping_index == VM64_MAPPING_MAX) return -1;
    for (usize_t offset = 0; offset < length; offset += 4096) {
        u64 *pte = user_pte(space, virtual + offset, 0);
        if (!pte || !(*pte & VM64_PAGE_PRESENT)) return -1;
    }
    for (usize_t offset = 0; offset < length; offset += 4096) {
        vaddr_t current = virtual + offset;
        u64 *pte = user_pte(space, current, 0);
        if (!pte) return -1;
        *pte = 0;
        __asm__ volatile("invlpg (%0)" : : "r"(current) : "memory");
    }
    u32 first_pd = (u32)((virtual - VM64_USER_BASE) >> 21);
    u32 last_pd = (u32)((virtual + length - 1 - VM64_USER_BASE) >> 21);
    for (u32 pd = first_pd; pd <= last_pd; pd++) release_empty_pt(space, pd);
    page_resource_mapping_close(space->mappings[mapping_index].object);
    object_release(space->mappings[mapping_index].object);
    space->mappings[mapping_index].object = 0;
    space->mappings[mapping_index].virtual = 0;
    space->mappings[mapping_index].length = 0;
    return 0;
}

static u32 vm64_revoke_objects_locked(u32 index,
                                      struct kernel_object **objects,
                                      u32 count) {
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4 ||
        (!objects && count))
        return 0;
    struct vm64_space *space = &spaces[index];
    u32 revoked = 0;
    for (u32 map = 0; map < VM64_MAPPING_MAX; map++) {
        struct kernel_object *mapped = space->mappings[map].object;
        if (!mapped) continue;
        int match = 0;
        for (u32 object = 0; object < count; object++)
            if (objects[object] == mapped) match = 1;
        if (!match) continue;
        vaddr_t virtual = space->mappings[map].virtual;
        usize_t length = space->mappings[map].length;
        if (!vm64_unmap_object_locked(index, virtual, length)) revoked++;
    }
    return revoked;
}

static int vm64_revoke_object_all_locked(struct kernel_object *object) {
    if (!object) return -1;
    int result = 0;
    for (u32 index = 0; index < VM64_MAX_SPACES; index++) {
        struct vm64_space *space = &spaces[index];
        if (!space->pml4) continue;
        for (u32 map = 0; map < VM64_MAPPING_MAX; map++) {
            if (space->mappings[map].object != object) continue;
            vaddr_t virtual = space->mappings[map].virtual;
            usize_t length = space->mappings[map].length;
            if (vm64_unmap_object_locked(index, virtual, length)) result = -1;
        }
    }
    return result;
}

u32 vm64_object_mapping_count(u32 index) {
    if (index >= VM64_MAX_SPACES || !spaces[index].pml4) return 0;
    u32 count = 0;
    for (u32 map = 0; map < VM64_MAPPING_MAX; map++)
        if (spaces[index].mappings[map].object) count++;
    return count;
}

static void *vm64_ioremap_locked(paddr_t physical, usize_t length,
                                 u32 cache_mode) {
    if (!length || (physical & 0xFFF) || (length & 0xFFF) ||
        length > VM64_KERNEL_MMIO_SIZE || length > ~(paddr_t)0 - physical)
        return 0;
    u64 caching = cache_flags(cache_mode);
    if (caching == ~0ULL) return 0;
    u32 pages = (u32)(length / 4096);
    u32 run = 0;
    u32 start = 0;
    for (u32 index = 0; index < KERNEL_MMIO_PAGES; index++) {
        if (!kernel_mmio_used[index]) {
            if (!run) start = index;
            run++;
            if (run == pages) break;
        } else {
            run = 0;
        }
    }
    if (run != pages) return 0;
    for (u32 page = 0; page < pages; page++) {
        u32 index = start + page;
        u32 pd = index >> 9;
        u32 pt = index & 0x1FF;
        kernel_mmio_used[index] = 1;
        table(kernel_mmio_pts[pd])[pt] =
            (physical + (paddr_t)page * 4096) | VM64_PAGE_PRESENT |
            VM64_PAGE_WRITE | VM64_PAGE_NX | caching;
    }
    return (void *)(uptr_t)(VM64_KERNEL_MMIO_BASE + (u64)start * 4096);
}

static int vm64_iounmap_locked(void *address, usize_t length) {
    vaddr_t virtual = (vaddr_t)(uptr_t)address;
    if (!address || !length || (virtual & 0xFFF) || (length & 0xFFF) ||
        virtual < VM64_KERNEL_MMIO_BASE ||
        virtual >= VM64_KERNEL_MMIO_BASE + VM64_KERNEL_MMIO_SIZE ||
        length > VM64_KERNEL_MMIO_BASE + VM64_KERNEL_MMIO_SIZE - virtual)
        return -1;
    u32 start = (u32)((virtual - VM64_KERNEL_MMIO_BASE) / 4096);
    u32 pages = (u32)(length / 4096);
    for (u32 page = 0; page < pages; page++)
        if (!kernel_mmio_used[start + page]) return -1;
    for (u32 page = 0; page < pages; page++) {
        u32 index = start + page;
        u32 pd = index >> 9;
        u32 pt = index & 0x1FF;
        kernel_mmio_used[index] = 0;
        table(kernel_mmio_pts[pd])[pt] = 0;
        vaddr_t current = VM64_KERNEL_MMIO_BASE + (u64)index * 4096;
        __asm__ volatile("invlpg (%0)" : : "r"(current) : "memory");
    }
    return 0;
}

// The locked bodies above are the implementation; these are the only
// entries the rest of the kernel reaches, so the lock has one place.
int vm64_revoke_object_all(struct kernel_object *object) {
    klock_acquire(&vm_klock);
    int result = vm64_revoke_object_all_locked(object);
    klock_release(&vm_klock);
    return result;
}

int vm64_map_page_object(u32 index, vaddr_t virtual,
                         struct kernel_object *object, int writable) {
    klock_acquire(&vm_klock);
    int result = vm64_map_page_object_locked(index, virtual, object, writable);
    klock_release(&vm_klock);
    return result;
}

u32 vm64_revoke_objects(u32 index, struct kernel_object **objects, u32 count) {
    klock_acquire(&vm_klock);
    u32 revoked = vm64_revoke_objects_locked(index, objects, count);
    klock_release(&vm_klock);
    return revoked;
}

void vm64_destroy_space(u32 index) {
    klock_acquire(&vm_klock);
    vm64_destroy_space_locked(index);
    klock_release(&vm_klock);
}

int vm64_create_space(u32 *space_out) {
    klock_acquire(&vm_klock);
    int result = vm64_create_space_locked(space_out);
    klock_release(&vm_klock);
    return result;
}

int vm64_unmap_object(u32 index, vaddr_t virtual, usize_t length) {
    klock_acquire(&vm_klock);
    int result = vm64_unmap_object_locked(index, virtual, length);
    klock_release(&vm_klock);
    return result;
}

int vm64_clone_space(u32 source, u32 *destination) {
    klock_acquire(&vm_klock);
    int result = vm64_clone_space_locked(source, destination);
    klock_release(&vm_klock);
    return result;
}

int vm64_handle_cow(u32 index, vaddr_t virtual) {
    klock_acquire(&vm_klock);
    int result = vm64_handle_cow_locked(index, virtual);
    klock_release(&vm_klock);
    return result;
}

int vm64_map_object(u32 index, vaddr_t virtual, struct kernel_object *object,
                    paddr_t physical, usize_t length, int writable,
                    u32 cache_mode) {
    klock_acquire(&vm_klock);
    int result = vm64_map_object_locked(index, virtual, object, physical,
                                        length, writable, cache_mode);
    klock_release(&vm_klock);
    return result;
}

void *vm64_ioremap(paddr_t physical, usize_t length, u32 cache_mode) {
    klock_acquire(&vm_klock);
    void *address = vm64_ioremap_locked(physical, length, cache_mode);
    klock_release(&vm_klock);
    return address;
}

int vm64_iounmap(void *address, usize_t length) {
    klock_acquire(&vm_klock);
    int result = vm64_iounmap_locked(address, length);
    klock_release(&vm_klock);
    return result;
}

int vm64_unmap(u32 index, vaddr_t virtual) {
    klock_acquire(&vm_klock);
    int result = vm64_unmap_locked(index, virtual);
    klock_release(&vm_klock);
    return result;
}

int vm64_map(u32 index, vaddr_t virtual, paddr_t physical, int writable,
             int executable) {
    klock_acquire(&vm_klock);
    int result = vm64_map_locked(index, virtual, physical, writable,
                                 executable);
    klock_release(&vm_klock);
    return result;
}

