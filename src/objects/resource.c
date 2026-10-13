#include "resource.h"
#include "pmm.h"
#include "klock.h"
#include "event.h"
#include "endpoint.h"
#include "protos.h"

static struct mmio_resource mmio_resources[RESOURCE_MMIO_MAX];
static struct irq_resource irq_resources[RESOURCE_IRQ_MAX];
static struct dma_resource dma_resources[RESOURCE_DMA_MAX];
static struct pci_resource pci_resources[RESOURCE_PCI_MAX];
static struct msix_table_resource msix_resources[RESOURCE_MSIX_MAX];
static struct page_resource page_resources[RESOURCE_PAGE_MAX];
static struct sg_resource sg_resources[RESOURCE_SG_MAX];
static irq_mask_backend_fn irq_mask_backends[IRQ_CONTROLLER_MAX];
static irq_release_backend_fn irq_release_backends[IRQ_CONTROLLER_MAX];
static page_revoke_backend_fn page_revoke_backend;
static dma_iommu_unmap_fn dma_iommu_unmap;

// One lock for all seven tables: they are one namespace by construction, and
// the only use that is not a table lookup is a destroy racing a get. Slots
// reached from inside a locked body go through the slot helpers, because the
// checked takes do not nest on themselves.
static struct klock resource_klock = KLOCK_INIT(KLOCK_LEVEL_RESOURCE);

static struct mmio_resource *mmio_slot(const struct kernel_object *object) {
    if (!object || !object->active || object->type != KOBJECT_MMIO ||
        !object->value || object->value > RESOURCE_MMIO_MAX)
        return 0;
    struct mmio_resource *resource = &mmio_resources[object->value - 1];
    return resource->active ? resource : 0;
}

static struct irq_resource *irq_slot(const struct kernel_object *object) {
    if (!object || !object->active || object->type != KOBJECT_IRQ ||
        !object->value || object->value > RESOURCE_IRQ_MAX)
        return 0;
    struct irq_resource *resource = &irq_resources[object->value - 1];
    return resource->active ? resource : 0;
}

static struct dma_resource *dma_slot(const struct kernel_object *object) {
    if (!object || !object->active || object->type != KOBJECT_DMA ||
        !object->value || object->value > RESOURCE_DMA_MAX)
        return 0;
    struct dma_resource *resource = &dma_resources[object->value - 1];
    return resource->active ? resource : 0;
}

static struct pci_resource *pci_slot(const struct kernel_object *object) {
    if (!object || !object->active || object->type != KOBJECT_PCI ||
        !object->value || object->value > RESOURCE_PCI_MAX)
        return 0;
    struct pci_resource *resource = &pci_resources[object->value - 1];
    return resource->active ? resource : 0;
}

static struct msix_table_resource *msix_slot(
    const struct kernel_object *object) {
    if (!object || !object->active || object->type != KOBJECT_MSIX_TABLE ||
        !object->value || object->value > RESOURCE_MSIX_MAX)
        return 0;
    struct msix_table_resource *resource = &msix_resources[object->value - 1];
    return resource->active ? resource : 0;
}

static struct page_resource *page_slot(const struct kernel_object *object) {
    if (!object || !object->active ||
        (object->type != KOBJECT_PAGE &&
         object->type != KOBJECT_SHARED_MEMORY) ||
        !object->value || object->value > RESOURCE_PAGE_MAX)
        return 0;
    struct page_resource *resource = &page_resources[object->value - 1];
    return resource->active ? resource : 0;
}

static struct sg_resource *sg_slot(const struct kernel_object *object) {
    if (!object || !object->active || object->type != KOBJECT_SG_LIST ||
        !object->value || object->value > RESOURCE_SG_MAX)
        return 0;
    struct sg_resource *resource = &sg_resources[object->value - 1];
    return resource->active ? resource : 0;
}

static int page_pin_locked(struct kernel_object *object) {
    struct page_resource *resource = page_slot(object);
    if (!resource || resource->revoked || resource->pin_count == 0xFFFFFFFFu ||
        object_retain(object))
        return -1;
    resource->pin_count++;
    return 0;
}

static int page_unpin_locked(struct kernel_object *object) {
    struct page_resource *resource = page_slot(object);
    if (!resource || !resource->pin_count) return -1;
    resource->pin_count--;
    return 0;
}

static void mmio_destroy(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    u64 value = object->value;
    if (!value || value > RESOURCE_MMIO_MAX) {
        klock_release(&resource_klock);
        return;
    }
    struct mmio_resource *resource = &mmio_resources[value - 1];
    resource->physical = 0;
    resource->length = 0;
    resource->cache_mode = 0;
    resource->active = 0;
    klock_release(&resource_klock);
}

static void irq_destroy(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    u64 value = object->value;
    if (!value || value > RESOURCE_IRQ_MAX) {
        klock_release(&resource_klock);
        return;
    }
    struct irq_resource *resource = &irq_resources[value - 1];
    u32 controller = resource->controller;
    u32 source = resource->source;
    struct kernel_object *binding = resource->binding;
    resource->controller = 0;
    resource->source = 0;
    resource->vector = 0;
    resource->trigger = 0;
    resource->polarity = 0;
    resource->masked = 1;
    resource->binding = 0;
    resource->active = 0;
    klock_release(&resource_klock);
    // The mask and release backends are the interrupt controllers, which sit
    // below this lock's level, so they run with the table lock down.
    if (controller < IRQ_CONTROLLER_MAX && irq_mask_backends[controller])
        irq_mask_backends[controller](source, 1);
    if (binding) object_release(binding);
    if (controller < IRQ_CONTROLLER_MAX && irq_release_backends[controller])
        irq_release_backends[controller](source);
}

static void dma_destroy(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    u64 value = object->value;
    if (!value || value > RESOURCE_DMA_MAX) {
        klock_release(&resource_klock);
        return;
    }
    struct dma_resource *resource = &dma_resources[value - 1];
    u32 owner = resource->iommu_owner;
    paddr_t bus_address = resource->bus_address;
    u32 pages = resource->pages;
    paddr_t physical = resource->physical;
    u32 active = resource->active;
    resource->physical = 0;
    resource->bus_address = 0;
    resource->iommu_owner = 0;
    resource->pages = 0;
    resource->address_mask = 0;
    resource->active = 0;
    klock_release(&resource_klock);
    // The unmap crosses into the IOMMU, above this level, so it runs with
    // the table lock down; the page frees stay on this side of it.
    if (active && owner &&
        (!dma_iommu_unmap || dma_iommu_unmap(owner, bus_address, pages)))
        panic_str("DMA IOMMU unmap");
    if (active)
        for (u32 page = 0; page < pages; page++)
            pmm_free_page(physical + (paddr_t)page * 4096);
}

static void msix_destroy(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    u64 value = object->value;
    if (!value || value > RESOURCE_MSIX_MAX) {
        klock_release(&resource_klock);
        return;
    }
    struct msix_table_resource *resource = &msix_resources[value - 1];
    struct kernel_object *pci = resource->pci;
    resource->pci = 0;
    resource->table_bir = 0;
    resource->pba_bir = 0;
    resource->table_offset = 0;
    resource->pba_offset = 0;
    resource->entries = 0;
    resource->active = 0;
    klock_release(&resource_klock);
    if (pci) object_release(pci);
}

// The map is one page because 512 addresses at 8 bytes fill exactly that.
// Raising the ceiling past it needs a wider map, which is a compile error
// here rather than a silent overrun of the slot behind it.
_Static_assert(RESOURCE_PAGE_PAGES_MAX * sizeof(paddr_t) <= PMM_PAGE_SIZE,
               "the page resource map must fit inside one page");

static int page_map_open(struct page_resource *resource) {
    if (resource->physical) return 0;
    paddr_t page = pmm_alloc_page();
    if (!page) return -1;
    resource->physical = (paddr_t *)(uptr_t)page;
    for (u32 index = 0; index < RESOURCE_PAGE_PAGES_MAX; index++)
        resource->physical[index] = 0;
    return 0;
}

static void page_map_close(struct page_resource *resource) {
    if (!resource->physical) return;
    pmm_free_page((paddr_t)(uptr_t)resource->physical);
    resource->physical = 0;
}

static void page_destroy(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    u64 value = object->value;
    if (!value || value > RESOURCE_PAGE_MAX) {
        klock_release(&resource_klock);
        return;
    }
    struct page_resource *resource = &page_resources[value - 1];
    if (!resource->active) {
        klock_release(&resource_klock);
        return;
    }
    if (resource->pin_count || resource->map_count)
        panic_str("page resource reference invariant");
    for (u32 page = 0; page < resource->pages; page++) {
        if (resource->physical[page]) pmm_free_page(resource->physical[page]);
        resource->physical[page] = 0;
    }
    page_map_close(resource);
    resource->pages = 0;
    resource->pin_count = 0;
    resource->map_count = 0;
    resource->revoked = 0;
    resource->shared = 0;
    resource->active = 0;
    klock_release(&resource_klock);
}

static void sg_destroy(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    u64 value = object->value;
    if (!value || value > RESOURCE_SG_MAX) {
        klock_release(&resource_klock);
        return;
    }
    struct sg_resource *resource = &sg_resources[value - 1];
    if (!resource->active) {
        klock_release(&resource_klock);
        return;
    }
    struct kernel_object *unpin[RESOURCE_SG_ENTRY_MAX];
    u32 unpin_count = 0;
    for (u32 index = 0; index < resource->entry_count; index++) {
        if (resource->entries[index].page &&
            !page_unpin_locked(resource->entries[index].page))
            unpin[unpin_count++] = resource->entries[index].page;
        resource->entries[index].page = 0;
        resource->entries[index].physical = 0;
        resource->entries[index].page_index = 0;
        resource->entries[index].offset = 0;
        resource->entries[index].length = 0;
    }
    resource->entry_count = 0;
    resource->total_length = 0;
    resource->revoked = 0;
    resource->active = 0;
    klock_release(&resource_klock);
    for (u32 index = 0; index < unpin_count; index++)
        object_release(unpin[index]);
}

static void pci_destroy(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    u64 value = object->value;
    if (!value || value > RESOURCE_PCI_MAX) {
        klock_release(&resource_klock);
        return;
    }
    struct pci_resource *resource = &pci_resources[value - 1];
    for (u32 bar = 0; bar < 6; bar++) {
        resource->bars[bar].address = 0;
        resource->bars[bar].length = 0;
        resource->bars[bar].flags = 0;
    }
    resource->active = 0;
    klock_release(&resource_klock);
}

void resource_init(void) {
    page_revoke_backend = 0;
    dma_iommu_unmap = 0;
    for (u32 index = 0; index < IRQ_CONTROLLER_MAX; index++) {
        irq_mask_backends[index] = 0;
        irq_release_backends[index] = 0;
    }
    for (u32 index = 0; index < RESOURCE_MMIO_MAX; index++)
        mmio_resources[index].active = 0;
    for (u32 index = 0; index < RESOURCE_IRQ_MAX; index++)
        irq_resources[index].active = 0;
    for (u32 index = 0; index < RESOURCE_DMA_MAX; index++)
        dma_resources[index].active = 0;
    for (u32 index = 0; index < RESOURCE_PCI_MAX; index++)
        pci_resources[index].active = 0;
    for (u32 index = 0; index < RESOURCE_MSIX_MAX; index++)
        msix_resources[index].active = 0;
    for (u32 index = 0; index < RESOURCE_PAGE_MAX; index++) {
        page_resources[index].physical = 0;
        page_resources[index].active = 0;
    }
    for (u32 index = 0; index < RESOURCE_SG_MAX; index++)
        sg_resources[index].active = 0;
}

int irq_resource_set_backend(u32 controller, irq_mask_backend_fn mask,
                             irq_release_backend_fn release) {
    if (controller >= IRQ_CONTROLLER_MAX || !mask) return -1;
    klock_acquire(&resource_klock);
    irq_mask_backends[controller] = mask;
    irq_release_backends[controller] = release;
    klock_release(&resource_klock);
    return 0;
}

struct kernel_object *mmio_resource_create(paddr_t physical, usize_t length,
                                           u32 cache_mode) {
    if (!length || (physical & 0xFFF) || (length & 0xFFF) ||
        cache_mode > MMIO_CACHE_WB || length > ~(paddr_t)0 - physical ||
        pmm_range_is_ram(physical, length))
        return 0;
    klock_acquire(&resource_klock);
    for (u32 index = 0; index < RESOURCE_MMIO_MAX; index++) {
        struct mmio_resource *resource = &mmio_resources[index];
        if (resource->active) continue;
        resource->physical = physical;
        resource->length = length;
        resource->cache_mode = cache_mode;
        resource->active = 1;
        struct kernel_object *object =
            object_create(KOBJECT_MMIO, index + 1, mmio_destroy);
        if (!object) resource->active = 0;
        klock_release(&resource_klock);
        return object;
    }
    klock_release(&resource_klock);
    return 0;
}

const struct mmio_resource *mmio_resource_get(
    const struct kernel_object *object) {
    klock_acquire(&resource_klock);
    const struct mmio_resource *resource = mmio_slot(object);
    klock_release(&resource_klock);
    return resource;
}

static struct kernel_object *irq_create_kind_locked(u32 controller, u32 source,
                                                    u32 vector, u32 trigger,
                                                    u32 polarity) {
    for (u32 index = 0; index < RESOURCE_IRQ_MAX; index++) {
        struct irq_resource *resource = &irq_resources[index];
        if (resource->active) continue;
        resource->controller = controller;
        resource->source = source;
        resource->vector = vector;
        resource->trigger = trigger;
        resource->polarity = polarity;
        resource->masked = 1;
        resource->binding = 0;
        resource->active = 1;
        struct kernel_object *object =
            object_create(KOBJECT_IRQ, index + 1, irq_destroy);
        if (!object) resource->active = 0;
        return object;
    }
    return 0;
}

struct kernel_object *irq_resource_create_kind(u32 controller, u32 source,
                                               u32 vector, u32 trigger,
                                               u32 polarity) {
    if (controller >= IRQ_CONTROLLER_MAX || vector < 32 || vector > 255 ||
        trigger > IRQ_TRIGGER_LEVEL || polarity > IRQ_POLARITY_LOW)
        return 0;
    klock_acquire(&resource_klock);
    struct kernel_object *object = irq_create_kind_locked(
        controller, source, vector, trigger, polarity);
    klock_release(&resource_klock);
    return object;
}

struct kernel_object *irq_resource_create(u32 source, u32 vector,
                                          u32 trigger, u32 polarity) {
    klock_acquire(&resource_klock);
    struct kernel_object *object = irq_create_kind_locked(
        IRQ_CONTROLLER_IOAPIC, source, vector, trigger, polarity);
    klock_release(&resource_klock);
    return object;
}

struct irq_resource *irq_resource_get(const struct kernel_object *object) {
    klock_acquire(&resource_klock);
    struct irq_resource *resource = irq_slot(object);
    klock_release(&resource_klock);
    return resource;
}

int irq_resource_bind(struct kernel_object *irq,
                      struct kernel_object *target) {
    if (!target || (target->type != KOBJECT_EVENT &&
                    target->type != KOBJECT_ENDPOINT))
        return -1;
    klock_acquire(&resource_klock);
    struct irq_resource *resource = irq_slot(irq);
    if (!resource || !target->active || resource->binding ||
        !resource->masked || object_retain(target)) {
        klock_release(&resource_klock);
        return -1;
    }
    resource->binding = target;
    klock_release(&resource_klock);
    return 0;
}

int irq_resource_unbind(struct kernel_object *irq) {
    klock_acquire(&resource_klock);
    struct irq_resource *resource = irq_slot(irq);
    if (!resource || !resource->binding) {
        klock_release(&resource_klock);
        return -1;
    }
    u32 controller = resource->controller;
    u32 source = resource->source;
    int unmask_needed = !resource->masked;
    if (unmask_needed) resource->masked = 1;
    struct kernel_object *binding = resource->binding;
    resource->binding = 0;
    klock_release(&resource_klock);
    int masked = 0;
    if (unmask_needed && controller < IRQ_CONTROLLER_MAX &&
        irq_mask_backends[controller])
        masked = irq_mask_backends[controller](source, 1);
    if (masked) {
        klock_acquire(&resource_klock);
        if (irq_slot(irq) == resource) resource->masked = 0;
        klock_release(&resource_klock);
        return -1;
    }
    object_release(binding);
    return 0;
}

int irq_resource_set_mask(struct kernel_object *irq, int masked) {
    klock_acquire(&resource_klock);
    struct irq_resource *resource = irq_slot(irq);
    if (!resource || (!masked && !resource->binding) ||
        resource->controller >= IRQ_CONTROLLER_MAX ||
        !irq_mask_backends[resource->controller]) {
        klock_release(&resource_klock);
        return -1;
    }
    // The backend is the interrupt controller, below this level, so the
    // table records the request and the programming happens after the
    // release: the mask is a claim the resource makes, not the controller
    // state itself.
    resource->masked = masked != 0;
    u32 controller = resource->controller;
    u32 source = resource->source;
    klock_release(&resource_klock);
    return irq_mask_backends[controller](source, masked != 0);
}

int irq_resource_signal(struct kernel_object *irq) {
    klock_acquire(&resource_klock);
    struct irq_resource *resource = irq_slot(irq);
    if (!resource || resource->masked || !resource->binding) {
        klock_release(&resource_klock);
        return -1;
    }
    struct kernel_object *binding = resource->binding;
    u32 source = resource->source;
    int result = -1;
    if (binding->type == KOBJECT_EVENT)
        result = event_signal(binding);
    if (binding->type == KOBJECT_ENDPOINT)
        result = endpoint_signal(binding, source);
    klock_release(&resource_klock);
    return result;
}

struct kernel_object *dma_resource_allocate(u32 pages, paddr_t address_mask) {
    if (!pages || pages > 256 || address_mask < 0xFFFFF) return 0;
    klock_acquire(&resource_klock);
    for (u32 index = 0; index < RESOURCE_DMA_MAX; index++) {
        struct dma_resource *resource = &dma_resources[index];
        if (resource->active) continue;
        paddr_t physical = pmm_alloc_contiguous(pages, address_mask);
        if (!physical) {
            klock_release(&resource_klock);
            return 0;
        }
#if __SIZEOF_POINTER__ == 8
        u8 *memory = (u8 *)(uptr_t)physical;
        for (usize_t byte = 0; byte < (usize_t)pages * 4096; byte++)
            memory[byte] = 0;
#else
        if (physical >= 0x1000000) {
            for (u32 page = 0; page < pages; page++)
                pmm_free_page(physical + page * 4096);
            klock_release(&resource_klock);
            return 0;
        }
        u8 *memory = (u8 *)(uptr_t)physical;
        for (usize_t byte = 0; byte < (usize_t)pages * 4096; byte++)
            memory[byte] = 0;
#endif
        resource->physical = physical;
        resource->bus_address = physical;
        resource->iommu_owner = 0;
        resource->pages = pages;
        resource->address_mask = address_mask;
        resource->active = 1;
        struct kernel_object *object =
            object_create(KOBJECT_DMA, index + 1, dma_destroy);
        if (!object) {
            for (u32 page = 0; page < pages; page++)
                pmm_free_page(physical + (paddr_t)page * 4096);
            resource->active = 0;
        }
        klock_release(&resource_klock);
        return object;
    }
    klock_release(&resource_klock);
    return 0;
}

const struct dma_resource *dma_resource_get(const struct kernel_object *object) {
    klock_acquire(&resource_klock);
    const struct dma_resource *resource = dma_slot(object);
    klock_release(&resource_klock);
    return resource;
}

int dma_resource_set_iommu_backend(dma_iommu_unmap_fn unmap) {
    if (!unmap) return -1;
    klock_acquire(&resource_klock);
    int result = dma_iommu_unmap ? -1 : 0;
    if (!result) dma_iommu_unmap = unmap;
    klock_release(&resource_klock);
    return result;
}

int dma_resource_bind_iommu(struct kernel_object *object, u32 owner,
                            u64 address) {
    if (!owner || !address || (address & 0xFFF) || !dma_iommu_unmap)
        return -1;
    klock_acquire(&resource_klock);
    struct dma_resource *resource = dma_slot(object);
    if (!resource || resource->iommu_owner) {
        klock_release(&resource_klock);
        return -1;
    }
    resource->bus_address = address;
    resource->iommu_owner = owner;
    klock_release(&resource_klock);
    return 0;
}

struct kernel_object *pci_resource_create(
    const struct pci_resource *description) {
    if (!description || description->device > 31 || description->function > 7 ||
        description->vendor_id == 0xFFFF)
        return 0;
    klock_acquire(&resource_klock);
    for (u32 index = 0; index < RESOURCE_PCI_MAX; index++) {
        struct pci_resource *resource = &pci_resources[index];
        if (resource->active) continue;
        *resource = *description;
        resource->active = 1;
        struct kernel_object *object =
            object_create(KOBJECT_PCI, index + 1, pci_destroy);
        if (!object) resource->active = 0;
        klock_release(&resource_klock);
        return object;
    }
    klock_release(&resource_klock);
    return 0;
}

const struct pci_resource *pci_resource_get(const struct kernel_object *object) {
    klock_acquire(&resource_klock);
    const struct pci_resource *resource = pci_slot(object);
    klock_release(&resource_klock);
    return resource;
}


struct kernel_object *msix_table_resource_create(struct kernel_object *pci,
                                                  u8 table_bir,
                                                  u32 table_offset,
                                                  u8 pba_bir,
                                                  u32 pba_offset,
                                                  u32 entries) {
    if (table_bir >= 6 || pba_bir >= 6 || !entries || entries > 2048)
        return 0;
    struct kernel_object *release = 0;
    klock_acquire(&resource_klock);
    if (!pci_slot(pci)) {
        klock_release(&resource_klock);
        return 0;
    }
    for (u32 index = 0; index < RESOURCE_MSIX_MAX; index++) {
        struct msix_table_resource *resource = &msix_resources[index];
        if (resource->active) continue;
        if (object_retain(pci)) break;
        resource->pci = pci;
        resource->table_bir = table_bir;
        resource->pba_bir = pba_bir;
        resource->table_offset = table_offset;
        resource->pba_offset = pba_offset;
        resource->entries = entries;
        resource->active = 1;
        struct kernel_object *object =
            object_create(KOBJECT_MSIX_TABLE, index + 1, msix_destroy);
        if (!object) {
            resource->active = 0;
            resource->pci = 0;
            release = pci;
        }
        klock_release(&resource_klock);
        if (release) object_release(release);
        return object;
    }
    klock_release(&resource_klock);
    return 0;
}

const struct msix_table_resource *msix_table_resource_get(
    const struct kernel_object *object) {
    klock_acquire(&resource_klock);
    const struct msix_table_resource *resource = msix_slot(object);
    klock_release(&resource_klock);
    return resource;
}

u32 resource_active_count(u32 object_type) {
    klock_acquire(&resource_klock);
    u32 count = 0;
    if (object_type == KOBJECT_MMIO)
        for (u32 index = 0; index < RESOURCE_MMIO_MAX; index++)
            if (mmio_resources[index].active) count++;
    if (object_type == KOBJECT_IRQ)
        for (u32 index = 0; index < RESOURCE_IRQ_MAX; index++)
            if (irq_resources[index].active) count++;
    if (object_type == KOBJECT_DMA)
        for (u32 index = 0; index < RESOURCE_DMA_MAX; index++)
            if (dma_resources[index].active) count++;
    if (object_type == KOBJECT_PCI)
        for (u32 index = 0; index < RESOURCE_PCI_MAX; index++)
            if (pci_resources[index].active) count++;
    if (object_type == KOBJECT_MSIX_TABLE)
        for (u32 index = 0; index < RESOURCE_MSIX_MAX; index++)
            if (msix_resources[index].active) count++;
    if (object_type == KOBJECT_PAGE || object_type == KOBJECT_SHARED_MEMORY)
        for (u32 index = 0; index < RESOURCE_PAGE_MAX; index++)
            if (page_resources[index].active &&
                ((object_type == KOBJECT_PAGE && !page_resources[index].shared) ||
                 (object_type == KOBJECT_SHARED_MEMORY &&
                  page_resources[index].shared)))
                count++;
    if (object_type == KOBJECT_SG_LIST)
        for (u32 index = 0; index < RESOURCE_SG_MAX; index++)
            if (sg_resources[index].active) count++;
    klock_release(&resource_klock);
    return count;
}

int page_resource_set_revoke_backend(page_revoke_backend_fn revoke) {
    if (!revoke) return -1;
    klock_acquire(&resource_klock);
    page_revoke_backend = revoke;
    klock_release(&resource_klock);
    return 0;
}

static struct kernel_object *page_allocate_locked(u32 pages, int shared) {
    if (!pages || pages > RESOURCE_PAGE_PAGES_MAX) return 0;
    for (u32 index = 0; index < RESOURCE_PAGE_MAX; index++) {
        struct page_resource *resource = &page_resources[index];
        if (resource->active) continue;
        if (page_map_open(resource)) return 0;
        u32 allocated = 0;
        while (allocated < pages) {
            paddr_t physical = pmm_alloc_page();
            if (!physical) break;
            resource->physical[allocated++] = physical;
        }
        if (allocated != pages) {
            while (allocated) pmm_free_page(resource->physical[--allocated]);
            page_map_close(resource);
            return 0;
        }
        resource->pages = pages;
        resource->pin_count = 0;
        resource->map_count = 0;
        resource->revoked = 0;
        resource->shared = shared != 0;
        resource->active = 1;
        struct kernel_object *object = object_create(
            shared ? KOBJECT_SHARED_MEMORY : KOBJECT_PAGE,
            index + 1, page_destroy);
        if (!object) {
            for (u32 page = 0; page < pages; page++)
                pmm_free_page(resource->physical[page]);
            page_map_close(resource);
            resource->active = 0;
            resource->pages = 0;
        }
        return object;
    }
    return 0;
}

struct kernel_object *page_resource_create(void) {
    klock_acquire(&resource_klock);
    struct kernel_object *object = page_allocate_locked(1, 0);
    klock_release(&resource_klock);
    return object;
}

struct kernel_object *shared_memory_resource_create(u32 pages) {
    klock_acquire(&resource_klock);
    struct kernel_object *object = page_allocate_locked(pages, 1);
    klock_release(&resource_klock);
    return object;
}

struct page_resource *page_resource_get(const struct kernel_object *object) {
    klock_acquire(&resource_klock);
    struct page_resource *resource = page_slot(object);
    klock_release(&resource_klock);
    return resource;
}

paddr_t page_resource_dma_address(const struct kernel_object *object,
                                  u32 offset, u32 length) {
    klock_acquire(&resource_klock);
    struct page_resource *pool = page_slot(object);
    if (!pool || pool->revoked || !length) {
        klock_release(&resource_klock);
        return 0;
    }
    u64 total = (u64)pool->pages * 4096u;
    if (offset >= total || (u64)length > total - offset) {
        klock_release(&resource_klock);
        return 0;
    }
    u32 page = offset / 4096u;
    u32 page_off = offset % 4096u;
    // The backing pages come from pmm_alloc_page one at a time and are not
    // physically contiguous, so a device descriptor that straddled a page
    // boundary would run off one page into unrelated memory.
    if ((u64)page_off + length > 4096u) {
        klock_release(&resource_klock);
        return 0;
    }
    paddr_t physical = pool->physical[page];
    // Virtqueues are programmed within the low 1GB DMA window; a page the
    // allocator placed above it is unreachable by the device, so refuse rather
    // than hand the capsule a descriptor the device would fault or wild-write on.
    if (!physical || physical + page_off + length > 0x40000000ULL) {
        klock_release(&resource_klock);
        return 0;
    }
    klock_release(&resource_klock);
    return physical + page_off;
}

int page_resource_pin(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    int result = page_pin_locked(object);
    klock_release(&resource_klock);
    return result;
}

int page_resource_unpin(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    int result = page_unpin_locked(object);
    klock_release(&resource_klock);
    // The release can drop the last reference and reach page_destroy, so it
    // runs with the table lock down.
    if (!result) object_release(object);
    return result;
}

int page_resource_revoke(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    struct page_resource *resource = page_slot(object);
    if (!resource || resource->revoked) {
        klock_release(&resource_klock);
        return -1;
    }
    klock_release(&resource_klock);
    // The revoke backend unmaps the object's mappings, and the unmap path
    // calls back into this table to close them, so it runs with the lock
    // down; the slot is re-checked before the flag is set.
    if (page_revoke_backend && page_revoke_backend(object)) return -1;
    klock_acquire(&resource_klock);
    resource = page_slot(object);
    if (!resource) {
        klock_release(&resource_klock);
        return -1;
    }
    // Set revoked only after the backend succeeds so a failed
    // revoke remains retryable from the same caller.
    resource->revoked = 1;
    int held = resource->map_count || resource->pin_count;
    klock_release(&resource_klock);
    return held ? -1 : 0;
}

int page_resource_grow(struct kernel_object *object, u32 pages) {
    if (!pages || pages > RESOURCE_PAGE_PAGES_MAX) return -1;
    klock_acquire(&resource_klock);
    struct page_resource *resource = page_slot(object);
    if (!resource || resource->revoked || pages <= resource->pages) {
        klock_release(&resource_klock);
        return -1;
    }
    u32 grown = resource->pages;
    while (grown < pages) {
        paddr_t physical = pmm_alloc_page();
        if (!physical) break;
        resource->physical[grown++] = physical;
    }
    if (grown != pages) {
        while (grown > resource->pages)
            pmm_free_page(resource->physical[--grown]);
        klock_release(&resource_klock);
        return -1;
    }
    // pmm recycles frames; zero on attach so a hole never leaks prior data.
    for (u32 page = resource->pages; page < pages; page++) {
        u8 *bytes = (u8 *)(uptr_t)resource->physical[page];
        for (u32 index = 0; index < 4096; index++) bytes[index] = 0;
    }
    resource->pages = pages;
    klock_release(&resource_klock);
    return 0;
}

int page_resource_trim(struct kernel_object *object, u32 pages) {
    klock_acquire(&resource_klock);
    struct page_resource *resource = page_slot(object);
    if (!resource || resource->revoked || pages >= resource->pages ||
        resource->map_count || resource->pin_count) {
        klock_release(&resource_klock);
        return -1;
    }
    for (u32 page = pages; page < resource->pages; page++) {
        pmm_free_page(resource->physical[page]);
        resource->physical[page] = 0;
    }
    resource->pages = pages;
    klock_release(&resource_klock);
    return 0;
}

int page_resource_mapping_open(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    struct page_resource *resource = page_slot(object);
    if (!resource || resource->revoked ||
        resource->map_count == 0xFFFFFFFFu) {
        klock_release(&resource_klock);
        return -1;
    }
    resource->map_count++;
    klock_release(&resource_klock);
    return 0;
}

void page_resource_mapping_close(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    struct page_resource *resource = page_slot(object);
    if (resource && resource->map_count) resource->map_count--;
    klock_release(&resource_klock);
}

struct kernel_object *sg_resource_create(struct kernel_object **pages,
                                          const u32 *page_indices,
                                          const u32 *offsets,
                                          const u32 *lengths,
                                          u32 entry_count) {
    if (!pages || !page_indices || !offsets || !lengths || !entry_count ||
        entry_count > RESOURCE_SG_ENTRY_MAX)
        return 0;
    klock_acquire(&resource_klock);
    struct kernel_object *unpin[RESOURCE_SG_ENTRY_MAX];
    u32 unpin_count = 0;
    u32 total = 0;
    for (u32 index = 0; index < entry_count; index++) {
        struct page_resource *page = page_slot(pages[index]);
        if (!page || page->revoked || page_indices[index] >= page->pages ||
            offsets[index] >= 4096 || !lengths[index] ||
            lengths[index] > 4096 - offsets[index] ||
            lengths[index] > 0xFFFFFFFFu - total) {
            klock_release(&resource_klock);
            return 0;
        }
        total += lengths[index];
    }
    for (u32 slot = 0; slot < RESOURCE_SG_MAX; slot++) {
        struct sg_resource *resource = &sg_resources[slot];
        if (resource->active) continue;
        for (u32 index = 0; index < RESOURCE_SG_ENTRY_MAX; index++) {
            resource->entries[index].page = 0;
            resource->entries[index].physical = 0;
            resource->entries[index].page_index = 0;
            resource->entries[index].offset = 0;
            resource->entries[index].length = 0;
        }
        u32 pinned = 0;
        while (pinned < entry_count) {
            if (page_pin_locked(pages[pinned])) break;
            struct page_resource *page = page_slot(pages[pinned]);
            resource->entries[pinned].page = pages[pinned];
            resource->entries[pinned].physical =
                page->physical[page_indices[pinned]] + offsets[pinned];
            resource->entries[pinned].page_index = page_indices[pinned];
            resource->entries[pinned].offset = offsets[pinned];
            resource->entries[pinned].length = lengths[pinned];
            pinned++;
        }
        if (pinned != entry_count) {
            while (pinned) {
                pinned--;
                if (!page_unpin_locked(resource->entries[pinned].page))
                    unpin[unpin_count++] = resource->entries[pinned].page;
                resource->entries[pinned].page = 0;
            }
            klock_release(&resource_klock);
            while (unpin_count) object_release(unpin[--unpin_count]);
            return 0;
        }
        resource->entry_count = entry_count;
        resource->total_length = total;
        resource->revoked = 0;
        resource->active = 1;
        struct kernel_object *object = object_create(
            KOBJECT_SG_LIST, slot + 1, sg_destroy);
        if (!object) {
            resource->active = 0;
            while (pinned) {
                pinned--;
                if (!page_unpin_locked(resource->entries[pinned].page))
                    unpin[unpin_count++] = resource->entries[pinned].page;
                resource->entries[pinned].page = 0;
            }
            resource->entry_count = 0;
            resource->total_length = 0;
        }
        klock_release(&resource_klock);
        while (unpin_count) object_release(unpin[--unpin_count]);
        return object;
    }
    klock_release(&resource_klock);
    return 0;
}

struct sg_resource *sg_resource_get(const struct kernel_object *object) {
    klock_acquire(&resource_klock);
    struct sg_resource *resource = sg_slot(object);
    klock_release(&resource_klock);
    return resource;
}

int sg_resource_revoke(struct kernel_object *object) {
    klock_acquire(&resource_klock);
    struct sg_resource *resource = sg_slot(object);
    if (!resource || resource->revoked) {
        klock_release(&resource_klock);
        return -1;
    }
    resource->revoked = 1;
    int result = 0;
    struct kernel_object *unpin[RESOURCE_SG_ENTRY_MAX];
    u32 unpin_count = 0;
    for (u32 index = 0; index < resource->entry_count; index++) {
        if (!resource->entries[index].page) continue;
        if (page_unpin_locked(resource->entries[index].page)) result = -1;
        else unpin[unpin_count++] = resource->entries[index].page;
        resource->entries[index].page = 0;
    }
    klock_release(&resource_klock);
    for (u32 index = 0; index < unpin_count; index++)
        object_release(unpin[index]);
    return result;
}

int sg_resource_usable(const struct kernel_object *object) {
    klock_acquire(&resource_klock);
    struct sg_resource *resource = sg_slot(object);
    if (!resource || resource->revoked) {
        klock_release(&resource_klock);
        return 0;
    }
    int usable = 1;
    for (u32 index = 0; index < resource->entry_count; index++) {
        struct page_resource *page = page_slot(resource->entries[index].page);
        if (!page || page->revoked) {
            usable = 0;
            break;
        }
    }
    klock_release(&resource_klock);
    return usable;
}
