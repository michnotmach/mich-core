#include "types.h"
#include "object.h"
#include "resource.h"
#include "pmm.h"
#include "vm64.h"
#include "sg.h"
#include "ring.h"
#include "iommu.h"
#include "tests64.h"

int test_resource64(void) {
    u32 free_before = pmm_free_pages();
    struct kernel_object *mmio =
        mmio_resource_create(0xFEC10000ULL, 4096, MMIO_CACHE_UC);
    struct kernel_object *irq =
        irq_resource_create(7, 48, IRQ_TRIGGER_LEVEL, IRQ_POLARITY_LOW);
    struct kernel_object *dma = dma_resource_allocate(2, 0x3FFFFFFFULL);
    struct kernel_object *dma_wide =
        dma_resource_allocate(1, ~(paddr_t)0);
    struct pci_resource description;
    description.segment = 0;
    description.bus = 0;
    description.device = 1;
    description.function = 0;
    description.vendor_id = 0x1234;
    description.device_id = 0x5678;
    description.class_code = 1;
    description.subclass = 8;
    description.programming_interface = 2;
    description.revision = 1;
    description.capability_flags = PCI_CAP_MSI | PCI_CAP_MSIX;
    description.msi_offset = 0x50;
    description.msix_offset = 0x60;
    description.pcie_offset = 0;
    description.active = 0;
    for (u32 index = 0; index < 6; index++) {
        description.bars[index].address = 0;
        description.bars[index].length = 0;
        description.bars[index].flags = 0;
    }
    description.bars[0].address = 0xF0000000ULL;
    description.bars[0].length = 4096;
    struct kernel_object *pci = pci_resource_create(&description);
    struct kernel_object *msix = pci ?
        msix_table_resource_create(pci, 0, 0, 0, 2048, 8) : 0;
    if (!mmio || !irq || !dma || !dma_wide || !pci || !msix ||
        !mmio_resource_get(mmio) || !irq_resource_get(irq) ||
        !dma_resource_get(dma) || !dma_resource_get(dma_wide) ||
        !pci_resource_get(pci) ||
        !msix_table_resource_get(msix)) {
        if (mmio) object_release(mmio);
        if (irq) object_release(irq);
        if (dma) object_release(dma);
        if (dma_wide) object_release(dma_wide);
        if (msix) object_release(msix);
        if (pci) object_release(pci);
        return -1;
    }
    const struct dma_resource *dma_info = dma_resource_get(dma);
    if (!dma_info || dma_info->pages != 2 ||
        dma_info->physical > dma_info->address_mask) {
        object_release(mmio);
        object_release(irq);
        object_release(dma);
        object_release(dma_wide);
        object_release(msix);
        object_release(pci);
        return -1;
    }
    object_release(mmio);
    object_release(irq);
    object_release(dma);
    object_release(dma_wide);
    object_release(msix);
    object_release(pci);
    // VUL-004: a DMA grant is fail-closed. With the opt-in off, permission must
    // track IOMMU presence exactly; the boot opt-in must always permit. Restore
    // the boot policy so later driver tests keep their granted DMA.
    int dma_saved = iommu_unconfined_dma_allowed();
    iommu_set_unconfined_dma_allowed(0);
    int dma_base = iommu_dma_permitted();
    iommu_set_unconfined_dma_allowed(1);
    int dma_opt_in = iommu_dma_permitted();
    iommu_set_unconfined_dma_allowed(dma_saved);
    if (dma_base != iommu_present() || !dma_opt_in) return -1;
    return pmm_free_pages() == free_before ? 0 : -1;
}

int test_page64(const struct test64_env *env) {
    u32 free_pages = pmm_free_pages();
    u32 objects = object_active_count();
    u32 pages = resource_active_count(KOBJECT_PAGE);
    u32 shared = resource_active_count(KOBJECT_SHARED_MEMORY);
    u32 mappings_one = vm64_object_mapping_count(env->owner_space);
    u32 mappings_two = vm64_object_mapping_count(env->target_space);
    struct kernel_object *page = page_resource_create();
    struct kernel_object *memory = shared_memory_resource_create(2);
    if (!page || !memory) {
        if (page) object_release(page);
        if (memory) object_release(memory);
        return -1;
    }
    struct page_resource *page_info = page_resource_get(page);
    struct page_resource *memory_info = page_resource_get(memory);
    if (!page_info || !memory_info || page_info->pages != 1 ||
        memory_info->pages != 2 || page_resource_pin(memory) ||
        page_resource_pin(memory) ||
        vm64_map_page_object(env->owner_space,
                             VM64_DRIVER_BASE, memory, 1) ||
        vm64_map_page_object(env->target_space,
                             VM64_DRIVER_BASE, memory, 0)) {
        vm64_revoke_object_all(memory);
        if (memory_info && memory_info->pin_count) page_resource_unpin(memory);
        if (memory_info && memory_info->pin_count) page_resource_unpin(memory);
        object_release(page);
        object_release(memory);
        return -1;
    }
    volatile u64 *physical =
        (volatile u64 *)(uptr_t)memory_info->physical[0];
    physical[0] = 0x4D49434850414745ULL;
    u64 copied = 0;
    int valid = !vm64_copy_from(env->target->page_dir, &copied,
                                VM64_DRIVER_BASE, sizeof(copied)) &&
        copied == 0x4D49434850414745ULL &&
        (vm64_user_flags(env->owner_space, VM64_DRIVER_BASE) &
         VM64_PAGE_WRITE) &&
        !(vm64_user_flags(env->target_space, VM64_DRIVER_BASE) &
          VM64_PAGE_WRITE) &&
        memory_info->map_count == 2 &&
        page_resource_revoke(memory) < 0 && memory_info->revoked &&
        memory_info->pin_count == 2 && !memory_info->map_count &&
        !vm64_user_flags(env->owner_space, VM64_DRIVER_BASE) &&
        !vm64_user_flags(env->target_space, VM64_DRIVER_BASE) &&
        vm64_map_page_object(env->owner_space,
                             VM64_DRIVER_BASE, memory, 1) < 0 &&
        !page_resource_unpin(memory) && !page_resource_unpin(memory) &&
        !vm64_map_page_object(env->owner_space,
                              VM64_DRIVER_BASE, page, 1) &&
        !vm64_unmap_object(env->owner_space,
                           VM64_DRIVER_BASE, 4096);
    object_release(page);
    object_release(memory);
    valid = valid && pmm_free_pages() == free_pages &&
        object_active_count() == objects &&
        resource_active_count(KOBJECT_PAGE) == pages &&
        resource_active_count(KOBJECT_SHARED_MEMORY) == shared &&
        vm64_object_mapping_count(env->owner_space) == mappings_one &&
        vm64_object_mapping_count(env->target_space) == mappings_two;
    return valid ? 0 : -1;
}

int test_sg64(void) {
    u32 free_pages = pmm_free_pages();
    u32 objects = object_active_count();
    u32 sg_count = resource_active_count(KOBJECT_SG_LIST);
    struct kernel_object *shared = shared_memory_resource_create(2);
    struct kernel_object *page = page_resource_create();
    if (!shared || !page) {
        if (shared) object_release(shared);
        if (page) object_release(page);
        return -1;
    }
    struct kernel_object *sources[3] = {shared, page, shared};
    u32 page_indices[3] = {0, 0, 1};
    u32 offsets[3] = {100, 0, 50};
    u32 lengths[3] = {1000, 4096, 200};
    // The exhaustion case holds every object at once, which is far too much
    // for a syscall stack. The battery is single-CPU, so the reuse is safe.
    static struct kernel_object *fillers[KOBJECT_MAX];
    u32 filler_count = 0;
    while (filler_count < KOBJECT_MAX) {
        struct kernel_object *filler = object_create(
            KOBJECT_FILE, filler_count + 1, 0);
        if (!filler) break;
        fillers[filler_count++] = filler;
    }
    struct page_resource *shared_info = page_resource_get(shared);
    struct page_resource *page_info = page_resource_get(page);
    struct kernel_object *failed = sg_resource_create(
        sources, page_indices, offsets, lengths, 3);
    int valid = !failed && shared_info && page_info &&
                !shared_info->pin_count && !page_info->pin_count;
    if (failed) object_release(failed);
    while (filler_count) object_release(fillers[--filler_count]);
    struct kernel_object *sg = sg_resource_create(
        sources, page_indices, offsets, lengths, 3);
    struct sg_resource *sg_info = sg_resource_get(sg);
    valid = valid && sg && sg_info && sg_resource_usable(sg) &&
            sg_info->entry_count == 3 && sg_info->total_length == 5296 &&
            shared_info->pin_count == 2 && page_info->pin_count == 1 &&
            sg_info->entries[0].physical ==
                shared_info->physical[0] + 100 &&
            sg_info->entries[1].physical == page_info->physical[0] &&
            sg_info->entries[2].physical ==
                shared_info->physical[1] + 50 &&
            !sg_resource_revoke(sg) && !sg_resource_usable(sg) &&
            !shared_info->pin_count && !page_info->pin_count &&
            !page_resource_revoke(shared) &&
            !page_resource_revoke(page);
    if (sg) object_release(sg);
    object_release(shared);
    object_release(page);
    valid = valid && pmm_free_pages() == free_pages &&
            object_active_count() == objects &&
            resource_active_count(KOBJECT_SG_LIST) == sg_count;
    return valid ? 0 : -1;
}

int test_ring64(const struct test64_env *env) {
    u32 free_pages = pmm_free_pages();
    u32 objects = object_active_count();
    u32 rings = ring_active_count();
    u32 shared = resource_active_count(KOBJECT_SHARED_MEMORY);
    u32 mappings_one = vm64_object_mapping_count(env->owner_space);
    u32 mappings_two = vm64_object_mapping_count(env->target_space);
    struct kernel_object *object = ring_resource_create(8, 32);
    struct ring_resource *ring = ring_resource_get(object);
    struct kernel_object *backing = ring_resource_backing(object);
    struct page_resource *memory = page_resource_get(backing);
    if (!object || !ring || !backing || !memory || memory->pages != 1 ||
        vm64_map_page_object(env->owner_space,
                             VM64_DRIVER_BASE, backing, 1) ||
        vm64_map_page_object(env->target_space,
                             VM64_DRIVER_BASE, backing, 0)) {
        if (backing) vm64_revoke_object_all(backing);
        if (object) object_release(object);
        return -1;
    }
    struct ring_shared_header *header =
        (struct ring_shared_header *)(uptr_t)memory->physical[0];
    u64 *first = (u64 *)ring_resource_descriptor(object, 0);
    u64 *last = (u64 *)ring_resource_descriptor(object, 7);
    u64 *wrapped = (u64 *)ring_resource_descriptor(object, 8);
    if (first) first[0] = 0x52494E4746495253ULL;
    if (last) last[0] = 0x52494E474C415354ULL;
    header->producer = ~0ULL;
    header->consumer = ~0ULL;
    header->generation = 0;
    header->capacity = 0xFFFFFFFFu;
    int valid = first && last && wrapped == first &&
        !ring_resource_submit(object, 8) &&
        ring_resource_submit(object, 1) < 0 &&
        header->producer == 8 && header->consumer == 0 &&
        header->generation == 1 && header->capacity == 8 &&
        header->descriptor_size == 32 && header->data_offset == 64 &&
        !ring_resource_consume(object, 3) &&
        !ring_resource_submit(object, 3) &&
        header->producer == 11 && header->consumer == 3 &&
        !ring_resource_consume(object, 8) &&
        header->producer == 11 && header->consumer == 11 &&
        !ring_resource_revoke(object) && ring->revoked &&
        ring->generation == 2 && header->generation == 2 &&
        header->flags == 1 &&
        !vm64_user_flags(env->owner_space, VM64_DRIVER_BASE) &&
        !vm64_user_flags(env->target_space, VM64_DRIVER_BASE) &&
        ring_resource_submit(object, 1) < 0 &&
        !ring_resource_descriptor(object, 0);
    object_release(object);
    struct kernel_object *wide = ring_resource_create(32, 128);
    struct ring_resource *wide_info = ring_resource_get(wide);
    valid = valid && wide && wide_info && wide_info->data_offset == 128;
    for (u32 index = 0; index < 32 && valid; index++)
        if (!ring_resource_descriptor(wide, index)) valid = 0;
    if (wide) object_release(wide);
    valid = valid && pmm_free_pages() == free_pages &&
        object_active_count() == objects && ring_active_count() == rings &&
        resource_active_count(KOBJECT_SHARED_MEMORY) == shared &&
        vm64_object_mapping_count(env->owner_space) == mappings_one &&
        vm64_object_mapping_count(env->target_space) == mappings_two;
    return valid ? 0 : -1;
}


int test_page_grow64(void) {
    u32 objects = object_active_count();
    u32 free_pages = pmm_free_pages();
    struct kernel_object *page = page_resource_create();
    struct page_resource *resource = page ? page_resource_get(page) : 0;
    int valid = page && resource && resource->pages == 1 &&
        page_resource_grow(page, 0) < 0 &&
        page_resource_grow(page, 1) < 0 &&
        page_resource_grow(page, RESOURCE_PAGE_PAGES_MAX + 1) < 0;
    u8 *bytes = resource ? (u8 *)(uptr_t)resource->physical[0] : 0;
    if (bytes)
        for (u32 index = 0; index < 4096; index++)
            bytes[index] = (u8)(index ^ 0x5A);
    valid = valid && bytes && !page_resource_grow(page, 4);
    struct page_resource *grown = page ? page_resource_get(page) : 0;
    valid = valid && grown && grown->pages == 4;
    if (valid && grown) {
        bytes = (u8 *)(uptr_t)grown->physical[0];
        for (u32 index = 0; index < 4096; index++)
            if (bytes[index] != (u8)(index ^ 0x5A)) valid = 0;
        for (u32 page_index = 1; page_index < 4; page_index++) {
            u8 *fresh = (u8 *)(uptr_t)grown->physical[page_index];
            for (u32 index = 0; index < 4096; index++)
                if (fresh[index] != 0) valid = 0;
        }
    }
    valid = valid && page_resource_trim(page, 4) < 0 &&
        !page_resource_trim(page, 2);
    struct page_resource *trimmed = page ? page_resource_get(page) : 0;
    valid = valid && trimmed && trimmed->pages == 2;
    if (valid && trimmed) {
        bytes = (u8 *)(uptr_t)trimmed->physical[0];
        for (u32 index = 0; index < 4096; index++)
            if (bytes[index] != (u8)(index ^ 0x5A)) valid = 0;
    }
    valid = valid && !page_resource_trim(page, 0);
    struct page_resource *empty = page ? page_resource_get(page) : 0;
    valid = valid && empty && empty->pages == 0 &&
        !page_resource_grow(page, 3);
    struct page_resource *regrown = page ? page_resource_get(page) : 0;
    valid = valid && regrown && regrown->pages == 3;
    if (page) object_release(page);
    valid = valid && object_active_count() == objects &&
        pmm_free_pages() == free_pages;
    return valid ? 0 : -1;
}
