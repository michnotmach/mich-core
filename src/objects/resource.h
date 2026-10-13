#ifndef RESOURCE_H
#define RESOURCE_H

#include "types.h"
#include "object.h"

#define RESOURCE_MMIO_MAX 32
#define RESOURCE_IRQ_MAX 64
#define RESOURCE_DMA_MAX 32
#define RESOURCE_PCI_MAX 64
#define RESOURCE_MSIX_MAX 32
#define RESOURCE_PAGE_MAX 64
#define RESOURCE_PAGE_PAGES_MAX 512
#define RESOURCE_SG_MAX 32
#define RESOURCE_SG_ENTRY_MAX 32

#define MMIO_CACHE_UC 0
#define MMIO_CACHE_WC 1
#define MMIO_CACHE_WT 2
#define MMIO_CACHE_WB 3

#define IRQ_TRIGGER_EDGE 0
#define IRQ_TRIGGER_LEVEL 1
#define IRQ_POLARITY_HIGH 0
#define IRQ_POLARITY_LOW 1

#define IRQ_CONTROLLER_IOAPIC 0
#define IRQ_CONTROLLER_MSI 1
#define IRQ_CONTROLLER_MSIX 2
#define IRQ_CONTROLLER_MAX 3

#define PCI_CAP_MSI (1u << 0)
#define PCI_CAP_MSIX (1u << 1)
#define PCI_CAP_PCIE (1u << 2)
#define PCI_CAP_FLR (1u << 3)

struct mmio_resource {
    paddr_t physical;
    usize_t length;
    u32 cache_mode;
    u32 active;
};

struct irq_resource {
    u32 controller;
    u32 source;
    u32 vector;
    u32 trigger;
    u32 polarity;
    u32 masked;
    struct kernel_object *binding;
    u32 active;
};

struct dma_resource {
    paddr_t physical;
    u64 bus_address;
    u32 iommu_owner;
    u32 pages;
    paddr_t address_mask;
    u32 active;
};

struct pci_bar_resource {
    u64 address;
    u64 length;
    u32 flags;
};

struct msix_table_resource {
    struct kernel_object *pci;
    u8 table_bir;
    u8 pba_bir;
    u32 table_offset;
    u32 pba_offset;
    u32 entries;
    u32 active;
};

struct page_resource {
    // The page map is allocated rather than inline. Inline, it sized every
    // slot for the largest possible resource while most hold a handful of
    // pages, and it is what kept the slot count pinned at 64.
    paddr_t *physical;
    u32 pages;
    u32 pin_count;
    u32 map_count;
    u32 revoked;
    u32 shared;
    u32 active;
};

struct sg_resource_entry {
    struct kernel_object *page;
    paddr_t physical;
    u32 page_index;
    u32 offset;
    u32 length;
};

struct sg_resource {
    struct sg_resource_entry entries[RESOURCE_SG_ENTRY_MAX];
    u32 entry_count;
    u32 total_length;
    u32 revoked;
    u32 active;
};

struct pci_resource {
    u16 segment;
    u8 bus;
    u8 device;
    u8 function;
    u16 vendor_id;
    u16 device_id;
    u8 class_code;
    u8 subclass;
    u8 programming_interface;
    u8 revision;
    u32 capability_flags;
    u8 msi_offset;
    u8 msix_offset;
    u8 pcie_offset;
    struct pci_bar_resource bars[6];
    u32 active;
};

typedef int (*irq_mask_backend_fn)(u32 source, int masked);
typedef void (*irq_release_backend_fn)(u32 source);
typedef int (*page_revoke_backend_fn)(struct kernel_object *object);
typedef int (*dma_iommu_unmap_fn)(u32 owner, u64 address, u32 pages);

void resource_init(void);
int irq_resource_set_backend(u32 controller, irq_mask_backend_fn mask,
                             irq_release_backend_fn release);
struct kernel_object *mmio_resource_create(paddr_t physical, usize_t length,
                                            u32 cache_mode);
const struct mmio_resource *mmio_resource_get(const struct kernel_object *object);
struct kernel_object *irq_resource_create(u32 source, u32 vector,
                                           u32 trigger, u32 polarity);
struct kernel_object *irq_resource_create_kind(u32 controller, u32 source,
                                                u32 vector, u32 trigger,
                                                u32 polarity);
struct irq_resource *irq_resource_get(const struct kernel_object *object);
int irq_resource_bind(struct kernel_object *irq,
                      struct kernel_object *target);
int irq_resource_unbind(struct kernel_object *irq);
int irq_resource_set_mask(struct kernel_object *irq, int masked);
int irq_resource_signal(struct kernel_object *irq);
struct kernel_object *dma_resource_allocate(u32 pages, paddr_t address_mask);
const struct dma_resource *dma_resource_get(const struct kernel_object *object);
int dma_resource_set_iommu_backend(dma_iommu_unmap_fn unmap);
int dma_resource_bind_iommu(struct kernel_object *object, u32 owner,
                            u64 address);
struct kernel_object *pci_resource_create(const struct pci_resource *description);
const struct pci_resource *pci_resource_get(const struct kernel_object *object);
struct kernel_object *msix_table_resource_create(struct kernel_object *pci,
                                                  u8 table_bir,
                                                  u32 table_offset,
                                                  u8 pba_bir,
                                                  u32 pba_offset,
                                                  u32 entries);
const struct msix_table_resource *msix_table_resource_get(
    const struct kernel_object *object);
int page_resource_set_revoke_backend(page_revoke_backend_fn revoke);
struct kernel_object *page_resource_create(void);
struct kernel_object *shared_memory_resource_create(u32 pages);
struct page_resource *page_resource_get(const struct kernel_object *object);
paddr_t page_resource_dma_address(const struct kernel_object *object,
                                  u32 offset, u32 length);
int page_resource_pin(struct kernel_object *object);
int page_resource_unpin(struct kernel_object *object);
int page_resource_revoke(struct kernel_object *object);
int page_resource_grow(struct kernel_object *object, u32 pages);
int page_resource_trim(struct kernel_object *object, u32 pages);
int page_resource_mapping_open(struct kernel_object *object);
void page_resource_mapping_close(struct kernel_object *object);
struct kernel_object *sg_resource_create(struct kernel_object **pages,
                                          const u32 *page_indices,
                                          const u32 *offsets,
                                          const u32 *lengths,
                                          u32 entry_count);
struct sg_resource *sg_resource_get(const struct kernel_object *object);
int sg_resource_revoke(struct kernel_object *object);
int sg_resource_usable(const struct kernel_object *object);
u32 resource_active_count(u32 object_type);

#endif
