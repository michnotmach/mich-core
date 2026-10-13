#include "object.h"
#include "task.h"
#include "posix_fd.h"
#include "klock.h"
#include "pmm.h"

struct handle_slot {
    struct kernel_object *object;
    u32 rights;
    u32 generation;
};

// One slab is one page. The free chain is per slab rather than global so an
// emptied slab can be unlinked and its page handed back without walking any
// other slab's free slots: the tree asserts that a test leaves the page
// allocator exactly as it found it, so slabs are borrowed, not claimed.
struct object_slab {
    struct object_slab *next;
    struct object_slab *prev;
    struct kernel_object *free;
    u32 live;
    struct kernel_object slots[OBJECT_SLAB_SLOTS];
};

_Static_assert(sizeof(struct object_slab) <= PMM_PAGE_SIZE,
               "an object slab must fit inside one page");

static struct object_slab *object_slabs;
static struct object_slab *object_room;
static u32 object_slab_count;
static struct handle_slot handles[MAX_TASKS][KHANDLE_MAX];

// A slab is page aligned and exactly one page long, so the header is found by
// masking rather than by a search. The mask is widened before the complement:
// inverting a 32-bit constant would zero every address bit above 4 GiB.
static struct object_slab *object_slab_of(const struct kernel_object *object) {
    return (struct object_slab *)((uptr_t)object &
                                   ~((uptr_t)PMM_PAGE_SIZE - 1u));
}

static void object_slab_unlink(struct object_slab *slab) {
    if (slab->prev) slab->prev->next = slab->next;
    else object_slabs = slab->next;
    if (slab->next) slab->next->prev = slab->prev;
    slab->next = 0;
    slab->prev = 0;
}

// S2's transitional cover for the object table, the handle tables and the
// refcounts. A destroy callback runs outside it: releasing a vfs file
// releases its node object, so the callback would take the lock again.
static struct klock object_klock = KLOCK_INIT(KLOCK_LEVEL_OBJECT);

static int task_index(const struct task *task) {
    uptr_t address = (uptr_t)task;
    uptr_t base = (uptr_t)task_pool;
    uptr_t size = sizeof(task_pool);
    if (!task || address < base || address >= base + size ||
        (address - base) % sizeof(struct task))
        return -1;
    int index = (int)((address - base) / sizeof(struct task));
    if (task_pool[index].state == TASK_FREE ||
        task_pool[index].state == TASK_ZOMBIE)
        return -1;
    return index;
}

static u32 handle_value(const struct handle_slot *slot, u32 index) {
    return (slot->generation << 8) | (index + 1);
}

static struct handle_slot *handle_slot_for(struct task *task, u32 handle) {
    int owner = task_index(task);
    u32 low = handle & 0xFFu;
    if (owner < 0 || !low || low > KHANDLE_MAX) return 0;
    struct handle_slot *slot = &handles[owner][low - 1];
    if (!slot->object || slot->generation != (handle >> 8)) return 0;
    return slot;
}

static int object_slab_grow(void) {
    if (object_slab_count == OBJECT_SLAB_MAX) return -1;
    paddr_t page = pmm_alloc_page();
    if (!page) return -1;
    struct object_slab *slab = (struct object_slab *)(uptr_t)page;
    slab->free = 0;
    slab->live = 0;
    for (u32 index = 0; index < OBJECT_SLAB_SLOTS; index++) {
        struct kernel_object *object = &slab->slots[index];
        object->type = KOBJECT_NONE;
        object->references = 0;
        object->destroy = 0;
        object->active = 0;
        // An inactive slot has no owner to read value, so the free link rides
        // there; object_create overwrites it before handing the slot out.
        object->value = (u64)(uptr_t)slab->free;
        slab->free = object;
    }
    slab->next = object_slabs;
    slab->prev = 0;
    if (object_slabs) object_slabs->prev = slab;
    object_slabs = slab;
    object_room = slab;
    object_slab_count++;
    return 0;
}

void object_init(void) {
    object_slabs = 0;
    object_room = 0;
    object_slab_count = 0;
    for (u32 owner = 0; owner < MAX_TASKS; owner++) {
        for (u32 index = 0; index < KHANDLE_MAX; index++) {
            handles[owner][index].object = 0;
            handles[owner][index].rights = 0;
            handles[owner][index].generation = 1;
        }
    }
}

struct kernel_object *object_create(u32 type, u64 value,
                                    object_destroy_fn destroy) {
    if (type == KOBJECT_NONE) return 0;
    klock_acquire(&object_klock);
    struct object_slab *slab = object_room;
    if (!slab || !slab->free) {
        slab = 0;
        for (struct object_slab *scan = object_slabs; scan; scan = scan->next)
            if (scan->free) {
                slab = scan;
                break;
            }
        // Growing reaches the page allocator from inside the object lock,
        // which the lock order allows: the allocator sits at the deeper level.
        if (!slab && object_slab_grow()) {
            klock_release(&object_klock);
            return 0;
        }
        if (!slab) slab = object_room;
    }
    struct kernel_object *object = slab->free;
    if (!object) {
        klock_release(&object_klock);
        return 0;
    }
    slab->free = (struct kernel_object *)(uptr_t)object->value;
    slab->live++;
    object_room = slab->free ? slab : 0;
    object->type = type;
    object->references = 1;
    object->value = value;
    object->destroy = destroy;
    object->active = 1;
    klock_release(&object_klock);
    return object;
}

static int object_retain_locked(struct kernel_object *object) {
    if (!object->active || !object->references ||
        object->references == 0xFFFFFFFFu)
        return -1;
    object->references++;
    return 0;
}

int object_retain(struct kernel_object *object) {
    if (!object) return -1;
    klock_acquire(&object_klock);
    int answer = object_retain_locked(object);
    klock_release(&object_klock);
    return answer;
}

void object_release(struct kernel_object *object) {
    if (!object) return;
    klock_acquire(&object_klock);
    if (!object->active || !object->references) {
        klock_release(&object_klock);
        return;
    }
    object->references--;
    if (object->references) {
        klock_release(&object_klock);
        return;
    }
    object_destroy_fn destroy = object->destroy;
    object->destroy = 0;
    klock_release(&object_klock);
    // The slot stays claimed while the callback runs: it sees the object's
    // type and value, which are how a vfs file destroy finds its state, and
    // object_create cannot hand the slot out and have its fields cleared
    // underneath by this release. The reference count is already zero, so no
    // caller can retain it back to life from here.
    if (destroy) destroy(object);
    klock_acquire(&object_klock);
    object->type = KOBJECT_NONE;
    object->active = 0;
    struct object_slab *slab = object_slab_of(object);
    object->value = (u64)(uptr_t)slab->free;
    slab->free = object;
    // A slab whose last object just died holds nothing but free slots, so its
    // page goes back. The destroy callback above is the only holder of a
    // pointer into the slab and it has already returned.
    if (!--slab->live) {
        object_slab_unlink(slab);
        object_slab_count--;
        if (object_room == slab) object_room = 0;
        pmm_free_page((paddr_t)(uptr_t)slab);
    }
    klock_release(&object_klock);
}

static u32 handle_open_locked(int owner, struct kernel_object *object,
                              u32 rights) {
    for (u32 index = 0; index < KHANDLE_MAX; index++) {
        struct handle_slot *slot = &handles[owner][index];
        if (slot->object) continue;
        if (object_retain_locked(object)) return 0;
        slot->object = object;
        slot->rights = rights;
        return handle_value(slot, index);
    }
    return 0;
}

u32 handle_open(struct task *task, struct kernel_object *object, u32 rights) {
    int owner = task_index(task);
    if (owner < 0 || !object || !rights || (rights & ~KRIGHT_ALL))
        return 0;
    klock_acquire(&object_klock);
    if (!object->active) {
        klock_release(&object_klock);
        return 0;
    }
    u32 handle = handle_open_locked(owner, object, rights);
    klock_release(&object_klock);
    return handle;
}

struct kernel_object *handle_get(struct task *task, u32 handle,
                                 u32 required_rights, u32 required_type) {
    klock_acquire(&object_klock);
    struct handle_slot *slot = handle_slot_for(task, handle);
    if (!slot || (required_rights & ~slot->rights) ||
        (required_type != KOBJECT_NONE &&
         slot->object->type != required_type)) {
        klock_release(&object_klock);
        return 0;
    }
    struct kernel_object *object = slot->object;
    klock_release(&object_klock);
    return object;
}

int handle_close(struct task *task, u32 handle) {
    klock_acquire(&object_klock);
    struct handle_slot *slot = handle_slot_for(task, handle);
    if (!slot) {
        klock_release(&object_klock);
        return -1;
    }
    struct kernel_object *object = slot->object;
    slot->object = 0;
    slot->rights = 0;
    slot->generation = (slot->generation + 1) & 0xFFFFFFu;
    if (!slot->generation) slot->generation = 1;
    klock_release(&object_klock);
    object_release(object);
    return 0;
}

u32 handle_duplicate(struct task *source, struct task *target,
                     u32 handle, u32 rights) {
    int owner = task_index(target);
    if (owner < 0) return 0;
    klock_acquire(&object_klock);
    struct handle_slot *slot = handle_slot_for(source, handle);
    if (!slot || !(slot->rights & KRIGHT_TRANSFER) || !rights ||
        (rights & ~slot->rights)) {
        klock_release(&object_klock);
        return 0;
    }
    u32 duplicate = handle_open_locked(owner, slot->object, rights);
    klock_release(&object_klock);
    return duplicate;
}

u32 handle_revoke_object(struct kernel_object *object) {
    if (!object) return 0;
    klock_acquire(&object_klock);
    if (!object->active) {
        klock_release(&object_klock);
        return 0;
    }
    klock_release(&object_klock);
    posix_fd_revoke_object(object);
    u32 revoked = 0;
    // One slot per pass, with the table lock dropped before the release: the
    // release can run the destroy callback, and that takes the lock again.
    for (;;) {
        klock_acquire(&object_klock);
        struct kernel_object *found = 0;
        for (u32 owner = 0; owner < MAX_TASKS && !found; owner++) {
            for (u32 index = 0; index < KHANDLE_MAX; index++) {
                struct handle_slot *slot = &handles[owner][index];
                if (slot->object != object) continue;
                slot->object = 0;
                slot->rights = 0;
                slot->generation = (slot->generation + 1) & 0xFFFFFFu;
                if (!slot->generation) slot->generation = 1;
                found = object;
                break;
            }
        }
        klock_release(&object_klock);
        if (!found) break;
        object_release(object);
        revoked++;
    }
    return revoked;
}

void handle_close_all(struct task *task) {
    int owner = task_index(task);
    if (owner < 0) return;
    for (u32 index = 0; index < KHANDLE_MAX; index++) {
        struct handle_slot *slot = &handles[owner][index];
        if (!slot->object) continue;
        u32 handle = handle_value(slot, index);
        handle_close(task, handle);
    }
}

u32 object_active_count(void) {
    u32 count = 0;
    klock_acquire(&object_klock);
    for (struct object_slab *slab = object_slabs; slab; slab = slab->next)
        for (u32 index = 0; index < OBJECT_SLAB_SLOTS; index++)
            if (slab->slots[index].active) count++;
    klock_release(&object_klock);
    return count;
}

u32 handle_active_count(void) {
    u32 count = 0;
    klock_acquire(&object_klock);
    for (u32 owner = 0; owner < MAX_TASKS; owner++)
        for (u32 index = 0; index < KHANDLE_MAX; index++)
            if (handles[owner][index].object) count++;
    klock_release(&object_klock);
    return count;
}

u32 handle_task_count(struct task *task) {
    int owner = task_index(task);
    if (owner < 0) return 0;
    u32 count = 0;
    klock_acquire(&object_klock);
    for (u32 index = 0; index < KHANDLE_MAX; index++)
        if (handles[owner][index].object) count++;
    klock_release(&object_klock);
    return count;
}
