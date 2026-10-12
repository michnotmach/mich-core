#include "vector64.h"

struct klock irq_program_klock = KLOCK_INIT(KLOCK_LEVEL_MSI);

// The dispatch path reads a single owner on every MSI interrupt, so the
// table is published with release stores and read with an acquire load
// instead of taking the allocator lock: a naturally aligned uptr_t cannot
// tear, and the object a vector names is built before the vector is
// published. Writers still serialize on the lock among themselves.
static uptr_t owners[256];
static u32 next_vector;

void vector64_init(void) {
    for (u32 vector = 0; vector < 256; vector++)
        __atomic_store_n(&owners[vector], 0, __ATOMIC_RELAXED);
    next_vector = VECTOR64_MSI_FIRST;
}

int vector64_allocate(uptr_t owner) {
    klock_acquire(&irq_program_klock);
    int vector = vector64_allocate_locked(owner);
    klock_release(&irq_program_klock);
    return vector;
}

int vector64_allocate_locked(uptr_t owner) {
    if (!owner) return -1;
    u32 count = VECTOR64_MSI_LAST - VECTOR64_MSI_FIRST + 1;
    for (u32 offset = 0; offset < count; offset++) {
        u32 vector = VECTOR64_MSI_FIRST +
                     (next_vector - VECTOR64_MSI_FIRST + offset) % count;
        if (owners[vector]) continue;
        __atomic_store_n(&owners[vector], owner, __ATOMIC_RELEASE);
        next_vector = vector == VECTOR64_MSI_LAST ? VECTOR64_MSI_FIRST
                                                  : vector + 1;
        return (int)vector;
    }
    return -1;
}

int vector64_allocate_group(uptr_t owner, u32 count, u8 *vectors) {
    klock_acquire(&irq_program_klock);
    int result = vector64_allocate_group_locked(owner, count, vectors);
    klock_release(&irq_program_klock);
    return result;
}

int vector64_allocate_group_locked(uptr_t owner, u32 count, u8 *vectors) {
    u32 total = VECTOR64_MSI_LAST - VECTOR64_MSI_FIRST + 1;
    if (!owner || !vectors || !count || count > 32 ||
        (count & (count - 1)) || count > total)
        return -1;
    u32 first = (VECTOR64_MSI_FIRST + count - 1) & ~(count - 1);
    for (u32 base = first;
         base + count - 1 <= VECTOR64_MSI_LAST; base += count) {
        int free = 1;
        for (u32 index = 0; index < count; index++)
            if (owners[base + index]) free = 0;
        if (!free) continue;
        for (u32 index = 0; index < count; index++) {
            __atomic_store_n(&owners[base + index], owner, __ATOMIC_RELEASE);
            vectors[index] = (u8)(base + index);
        }
        next_vector = base + count > VECTOR64_MSI_LAST
            ? VECTOR64_MSI_FIRST : base + count;
        return 0;
    }
    return -1;
}

int vector64_release_group(const u8 *vectors, u32 count, uptr_t owner) {
    if (!vectors || !count || count > 32 || !owner) return -1;
    klock_acquire(&irq_program_klock);
    int result = 0;
    for (u32 index = 0; index < count; index++)
        if (vectors[index] < VECTOR64_MSI_FIRST ||
            vectors[index] > VECTOR64_MSI_LAST ||
            owners[vectors[index]] != owner) {
            result = -1;
            break;
        }
    if (!result)
        for (u32 index = 0; index < count; index++)
            __atomic_store_n(&owners[vectors[index]], 0, __ATOMIC_RELEASE);
    klock_release(&irq_program_klock);
    return result;
}

int vector64_release(u8 vector, uptr_t owner) {
    klock_acquire(&irq_program_klock);
    int result = vector64_release_locked(vector, owner);
    klock_release(&irq_program_klock);
    return result;
}

int vector64_release_locked(u8 vector, uptr_t owner) {
    if (vector < VECTOR64_MSI_FIRST || vector > VECTOR64_MSI_LAST || !owner)
        return -1;
    if (owners[vector] != owner) return -1;
    __atomic_store_n(&owners[vector], 0, __ATOMIC_RELEASE);
    return 0;
}

int vector64_transfer(u8 vector, uptr_t old_owner, uptr_t new_owner) {
    klock_acquire(&irq_program_klock);
    int result = vector64_transfer_locked(vector, old_owner, new_owner);
    klock_release(&irq_program_klock);
    return result;
}

int vector64_transfer_locked(u8 vector, uptr_t old_owner, uptr_t new_owner) {
    if (vector < VECTOR64_MSI_FIRST || vector > VECTOR64_MSI_LAST ||
        !old_owner || !new_owner)
        return -1;
    if (owners[vector] != old_owner) return -1;
    __atomic_store_n(&owners[vector], new_owner, __ATOMIC_RELEASE);
    return 0;
}

u32 vector64_available(void) {
    klock_acquire(&irq_program_klock);
    u32 available = 0;
    for (u32 vector = VECTOR64_MSI_FIRST; vector <= VECTOR64_MSI_LAST; vector++)
        if (!__atomic_load_n(&owners[vector], __ATOMIC_RELAXED)) available++;
    klock_release(&irq_program_klock);
    return available;
}

uptr_t vector64_owner(u8 vector) {
    return vector64_owner_locked(vector);
}

uptr_t vector64_owner_locked(u8 vector) {
    if (vector < VECTOR64_MSI_FIRST || vector > VECTOR64_MSI_LAST) return 0;
    return __atomic_load_n(&owners[vector], __ATOMIC_ACQUIRE);
}
