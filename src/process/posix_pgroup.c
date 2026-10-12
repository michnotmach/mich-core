#include "posix_pgroup.h"
#include "task.h"

static u32 groups[MAX_TASKS];

static u32 slot_of(const struct task *task) {
    if (!task) return MAX_TASKS;
    u32 slot = (u32)(task - task_pool);
    return slot < (u32)MAX_TASKS ? slot : MAX_TASKS;
}

void posix_pgroup_init(void) {
    for (u32 slot = 0; slot < MAX_TASKS; slot++) groups[slot] = 0;
}

u32 posix_pgroup_get(struct task *task) {
    u32 slot = slot_of(task);
    if (slot == MAX_TASKS) return 0;
    // A task that never named a group leads its own, which is what a shell
    // relies on before its first setpgid.
    return groups[slot] ? groups[slot] : (u32)task->id;
}

int posix_pgroup_set(struct task *task, u32 pgid) {
    u32 slot = slot_of(task);
    if (slot == MAX_TASKS || !pgid) return -1;
    // A task naming its own pid creates the group it then leads, which is
    // what every shell does before its first exec; any other id must name
    // a group somebody is already in, since the profile has one session
    // and no orphaned groups to join.
    if (pgid != (u32)task->id && !posix_pgroup_live(pgid)) return -1;
    groups[slot] = pgid;
    return 0;
}

int posix_pgroup_fork(struct task *parent, struct task *child) {
    u32 from = slot_of(parent);
    u32 to = slot_of(child);
    if (from == MAX_TASKS || to == MAX_TASKS) return -1;
    groups[to] = posix_pgroup_get(parent);
    return 0;
}

void posix_pgroup_reset(struct task *task) {
    u32 slot = slot_of(task);
    if (slot == MAX_TASKS) return;
    groups[slot] = 0;
}

int posix_pgroup_live(u32 pgid) {
    if (!pgid) return 0;
    for (u32 slot = 1; slot < (u32)task_pool_count; slot++) {
        if (task_pool[slot].state == TASK_FREE) continue;
        if (task_pool[slot].state == TASK_ZOMBIE) continue;
        if (posix_pgroup_get(&task_pool[slot]) == pgid) return 1;
    }
    return 0;
}

u32 posix_pgroup_members_from(u32 pgid, u32 from, struct task **members,
                              u32 capacity, u32 *next) {
    u32 count = 0;
    if (!pgid || !members || !next) return 0;
    u32 slot = from < 1 ? 1 : from;
    u32 limit = (u32)task_pool_count;
    for (; slot < limit && count < capacity; slot++) {
        struct task *candidate = &task_pool[slot];
        if (candidate->state == TASK_FREE) continue;
        if (candidate->state == TASK_ZOMBIE) continue;
        if (posix_pgroup_get(candidate) != pgid) continue;
        members[count++] = candidate;
    }
    *next = slot;
    return count;
}

u32 posix_pgroup_members(u32 pgid, struct task **members, u32 capacity) {
    u32 next = 0;
    return posix_pgroup_members_from(pgid, 0, members, capacity, &next);
}

u32 posix_pgroup_id_of(struct task *task) {
    return posix_pgroup_get(task);
}
