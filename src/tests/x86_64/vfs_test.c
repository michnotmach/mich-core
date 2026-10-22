#include "types.h"
#include "object.h"
#include "pmm.h"
#include "vfs.h"
#include "firmware.h"


int test_vfs64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 mounts = vfs_mount_active_count();
    struct kernel_object *root = vfs_root();
    struct kernel_object *mount = vfs_mount_root();
    struct kernel_object *directory = root ?
        vfs_create(root, "etc", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *node = directory ?
        vfs_create_mode(directory, "config", VFS_NODE_REGULAR, 0640) : 0;
    struct kernel_object *invalid_mode = directory ?
        vfs_create_mode(directory, "bad-mode", VFS_NODE_REGULAR, 01000) : 0;
    struct kernel_object *duplicate = directory ?
        vfs_create(directory, "config", VFS_NODE_REGULAR) : 0;
    struct kernel_object *invalid = root ?
        vfs_create(root, "../escape", VFS_NODE_REGULAR) : 0;
    struct kernel_object *lookup = directory ?
        vfs_lookup(directory, "config") : 0;
    struct kernel_object *opened = node ? vfs_open(node) : 0;
    u8 payload[32];
    u8 received[32];
    for (u32 index = 0; index < sizeof(payload); index++) payload[index] = (u8)index;
    u32 transferred = 0;
    u32 appended_position = 0;
    u8 append_first[2] = { 'a', 'b' };
    u8 append_second[2] = { 'c', 'd' };
    struct kernel_object *boot_directory = root ?
        vfs_resolve(root, "/boot") : 0;
    struct kernel_object *boot_node = root ?
        vfs_resolve(root, "/boot/init64") : 0;
    struct kernel_object *boot_parent = boot_directory ?
        vfs_resolve(boot_directory, "..") : 0;
    struct kernel_object *boot_file = boot_node ? vfs_open(boot_node) : 0;
    u32 firmware_size = 0;
    struct kernel_object *firmware_file = firmware_open("init64", &firmware_size);
    struct vfs_node_info boot_info;
    int boot_valid = boot_directory && boot_node && boot_parent == root &&
        boot_file && firmware_file && firmware_size > 4 &&
        !firmware_open("../init64", &firmware_size) &&
        !vfs_stat(boot_file, &boot_info) &&
        boot_info.filesystem == VFS_FILESYSTEM_BOOTFS && boot_info.readonly &&
        boot_info.mode == 0555u &&
        !vfs_read(boot_file, 0, received, 4, &transferred) && transferred == 4 &&
        received[0] == 0x7F && received[1] == 'E' &&
        received[2] == 'L' && received[3] == 'F' &&
        vfs_write(boot_file, 0, payload, 1, &transferred) < 0 &&
        vfs_append(boot_file, payload, 1, &transferred,
                   &appended_position) < 0 &&
        vfs_truncate(boot_file, 0) < 0 &&
        !vfs_create(boot_directory, "mutable", VFS_NODE_REGULAR) &&
        vfs_unlink(root, "boot") < 0;
    int valid = boot_valid && root && mount && directory && node &&
        !duplicate && !invalid && !invalid_mode && lookup == node && opened &&
        !vfs_write(opened, 0, payload, sizeof(payload), &transferred) &&
        transferred == sizeof(payload) &&
        !vfs_read(opened, 0, received, sizeof(received), &transferred) &&
        transferred == sizeof(received);
    for (u32 index = 0; index < sizeof(payload); index++)
        if (received[index] != payload[index]) valid = 0;
    struct vfs_node_info info;
    valid = valid && !vfs_stat(opened, &info) &&
        info.type == VFS_NODE_REGULAR && info.size == sizeof(payload) &&
        info.mode == 0640 && info.linked && !vfs_truncate(opened, 8) &&
        !vfs_stat(node, &info) && info.size == 8 &&
        !vfs_append(opened, append_first, sizeof(append_first), &transferred,
                    &appended_position) &&
        transferred == sizeof(append_first) && appended_position == 10 &&
        !vfs_truncate(opened, 9) &&
        !vfs_append(opened, append_second, sizeof(append_second), &transferred,
                    &appended_position) &&
        transferred == sizeof(append_second) && appended_position == 11 &&
        !vfs_stat(node, &info) && info.size == 11 &&
        vfs_unlink(root, "etc") < 0 &&
        !vfs_unlink(directory, "config") &&
        !vfs_stat(opened, &info) && !info.linked &&
        !vfs_read(opened, 0, received, sizeof(received), &transferred) &&
        transferred == 11 && received[8] == append_first[0] &&
        received[9] == append_second[0] && received[10] == append_second[1] &&
        !vfs_unlink(root, "etc");
    // Hard links: one inode under two names, the primary name promotes an
    // alias on unlink, and the listing shows both names with one inode.
    struct kernel_object *hard = root ?
        vfs_create(root, "hard", VFS_NODE_REGULAR) : 0;
    struct kernel_object *alias_lookup = hard && !vfs_link(hard, root, "alias")
        ? vfs_lookup(root, "alias") : 0;
    valid = valid && hard && alias_lookup == hard &&
        !vfs_stat(hard, &info) && info.links == 2 &&
        !vfs_unlink(root, "hard") &&
        !vfs_stat(hard, &info) && info.links == 1 && info.linked &&
        !vfs_unlink(root, "alias") && !vfs_lookup(root, "alias") &&
        vfs_link(hard, root, "busy") < 0;
    if (alias_lookup) object_release(alias_lookup);
    if (hard) object_release(hard);
    struct kernel_object *linked_dir = root ?
        vfs_create(root, "linked", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *linked_file = linked_dir ?
        vfs_create(linked_dir, "one", VFS_NODE_REGULAR) : 0;
    struct kernel_object *linked_listing = 0;
    u64 linked_cursor = 0;
    u32 linked_seen_one = 0;
    u32 linked_seen_two = 0;
    u64 linked_inode = 0;
    if (linked_file && !vfs_link(linked_file, linked_dir, "two"))
        linked_listing = vfs_open(linked_dir);
    for (;;) {
        char linked_name[VFS_NAME_MAX + 1];
        u32 linked_len = 0;
        u64 entry_inode = 0;
        u32 entry_type = 0;
        if (!linked_listing) break;
        int step = vfs_read_dir(linked_listing, &linked_cursor, linked_name,
                                &linked_len, &entry_inode, &entry_type);
        if (step == 1) break;
        if (step) {
            valid = 0;
            break;
        }
        if (entry_type != VFS_NODE_REGULAR) valid = 0;
        if (linked_name[0] == 'o' && linked_name[1] == 'n' &&
            linked_name[2] == 'e' && !linked_name[3]) {
            linked_seen_one++;
        } else if (linked_name[0] == 't' && linked_name[1] == 'w' &&
                   linked_name[2] == 'o' && !linked_name[3]) {
            linked_seen_two++;
        } else {
            valid = 0;
        }
        if (!linked_inode) linked_inode = entry_inode;
        else if (entry_inode != linked_inode) valid = 0;
    }
    valid = valid && linked_dir && linked_file && linked_listing &&
        linked_seen_one == 1 && linked_seen_two == 1 &&
        !vfs_stat(linked_file, &info) && info.links == 2 &&
        !vfs_unlink(linked_dir, "one") &&
        !vfs_stat(linked_file, &info) && info.links == 1 &&
        !vfs_unlink(linked_dir, "two");
    if (linked_listing) object_release(linked_listing);
    if (linked_file) object_release(linked_file);
    valid = valid && linked_dir && !vfs_unlink(root, "linked");
    if (linked_dir) object_release(linked_dir);
    // Rename moves one name, the primary dentry or an alias, across
    // directories or in place, replaces a same-kind target, and refuses
    // to loop a directory into its own subtree.
    struct kernel_object *home = root ?
        vfs_create(root, "home", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *away = root ?
        vfs_create(root, "away", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *file = home ?
        vfs_create(home, "file", VFS_NODE_REGULAR) : 0;
    struct kernel_object *taken = home ?
        vfs_create(home, "taken", VFS_NODE_REGULAR) : 0;
    struct kernel_object *folder = home ?
        vfs_create(home, "folder", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *elsewhere = 0;
    struct kernel_object *reached = 0;
    struct kernel_object *leaf_found = 0;
    struct kernel_object *leaf_made = 0;
    int rc_noop = vfs_rename(home, "file", home, "file");
    int rc_link = vfs_link(file, home, "twin");
    int rc_self = vfs_rename(home, "file", home, "twin");
    int rc_move = vfs_rename(home, "twin", away, "elsewhere");
    elsewhere = vfs_lookup(away, "elsewhere");
    int rc_replace = vfs_rename(away, "elsewhere", home, "taken");
    reached = vfs_lookup(home, "taken");
    int rc_stat = vfs_stat(file, &info);
    u32 link_count = info.links;
    leaf_made = vfs_create(folder, "leaf", VFS_NODE_REGULAR);
    int rc_dir = vfs_rename(home, "folder", root, "parked");
    leaf_found = vfs_resolve(root, "/parked/leaf");
    int rc_cycle = vfs_rename(root, "parked", folder, "deeper");
    int rc_dots = vfs_rename(root, ".", home, "dot");
    int rc_dir_onto_file = vfs_rename(root, "parked", home, "file");
    int rc_file_onto_dir = vfs_rename(home, "file", root, "parked");
    valid = valid && home && away && file && taken && folder && leaf_made &&
        !rc_noop && !rc_link && !rc_self && !rc_move && !rc_replace &&
        elsewhere == file && reached == file && !rc_stat &&
        link_count == 2 && !rc_dir && leaf_found && rc_cycle < 0 &&
        rc_dots < 0 && rc_dir_onto_file < 0 && rc_file_onto_dir < 0;
    if (reached) object_release(reached);
    if (elsewhere) object_release(elsewhere);
    if (leaf_found) object_release(leaf_found);
    if (leaf_made) object_release(leaf_made);
    int rc_leaf = vfs_unlink_path(root, "/parked/leaf");
    int rc_parked = vfs_unlink(root, "parked");
    int rc_taken = vfs_unlink(home, "taken");
    int rc_file = vfs_unlink(home, "file");
    int rc_home = vfs_unlink(root, "home");
    int rc_away = vfs_unlink(root, "away");
    valid = valid && !rc_leaf && !rc_parked && !rc_taken && !rc_file &&
        !rc_home && !rc_away;
    if (folder) object_release(folder);
    if (taken) object_release(taken);
    if (file) object_release(file);
    if (away) object_release(away);
    if (home) object_release(home);
    // A symlink is a name whose node carries a target string: lookup
    // finds the link itself, the kernel resolver leaves it alone, and
    // rename and unlink move it like any other name.
    const char guide_target[] = "/boot/nowhere";
    struct kernel_object *guide = root ?
        vfs_symlink(root, "guide", guide_target) : 0;
    struct kernel_object *link_found = guide ? vfs_lookup(root, "guide") : 0;
    struct kernel_object *link_resolved = guide ?
        vfs_resolve(root, "/guide") : 0;
    struct kernel_object *second_link = guide ?
        vfs_symlink(root, "guide", guide_target) : 0;
    char stretched_target[VFS_PATH_MAX];
    for (u32 index = 0; index < VFS_PATH_MAX; index++)
        stretched_target[index] = (char)('a' + (index % 26));
    struct kernel_object *long_link = guide ?
        vfs_symlink(root, "stretch", stretched_target) : 0;
    char link_target[VFS_PATH_MAX];
    u32 link_length = 0;
    int rc_readlink = vfs_readlink(guide, link_target,
                                   sizeof(link_target), &link_length);
    int target_matches = !rc_readlink &&
        link_length == sizeof(guide_target) - 1;
    for (u32 index = 0; target_matches && index < link_length; index++)
        if (link_target[index] != guide_target[index]) target_matches = 0;
    int rc_link_stat = vfs_stat(guide, &info);
    int rc_rename = vfs_rename(root, "guide", root, "moved");
    int rc_reread = vfs_readlink(guide, link_target,
                                 sizeof(link_target), &link_length);
    int rc_unlink = vfs_unlink(root, "moved");
    valid = valid && guide && link_found == guide &&
        link_resolved == guide && !second_link && !long_link &&
        !rc_readlink && target_matches && !rc_link_stat &&
        info.type == VFS_NODE_SYMLINK &&
        info.size == sizeof(guide_target) - 1 && info.links == 1 &&
        !rc_rename && !rc_reread && !rc_unlink;
    if (link_resolved) object_release(link_resolved);
    if (link_found) object_release(link_found);
    if (guide) object_release(guide);
    // Targets live in a table of their own, so a node that goes away has to
    // hand its slot back or the table runs dry while the node table is still
    // nearly empty. The round count is past that bound, and the link created
    // afterwards is what proves a slot came back rather than the loop merely
    // fitting inside it.
    int slots_reclaimed = root != 0;
    for (u32 round = 0; slots_reclaimed && round < 160; round++) {
        char name[12];
        char reversed[8];
        u32 digits = 0;
        u32 copy = round;
        name[0] = 'l';
        if (!copy) reversed[digits++] = '0';
        while (copy) {
            reversed[digits++] = (char)('0' + (copy % 10u));
            copy /= 10u;
        }
        for (u32 index = 0; index < digits; index++)
            name[1 + index] = reversed[digits - 1u - index];
        name[1 + digits] = 0;
        struct kernel_object *link = vfs_symlink(root, name, guide_target);
        if (!link) {
            slots_reclaimed = 0;
            break;
        }
        object_release(link);
        if (vfs_unlink(root, name)) {
            slots_reclaimed = 0;
        }
    }
    struct kernel_object *after = root ?
        vfs_symlink(root, "after", guide_target) : 0;
    u32 after_length = 0;
    int rc_after = after ?
        vfs_readlink(after, link_target, sizeof(link_target), &after_length) :
        -1;
    valid = valid && slots_reclaimed && after && !rc_after &&
        after_length == sizeof(guide_target) - 1;
    if (after) object_release(after);
    // Unlinked as well, so the accounting at the end of the test sees the
    // table where it started: a linked node is supposed to outlive the handle
    // that created it.
    if (root) vfs_unlink(root, "after");
    struct kernel_object *usr = root ?
        vfs_create_path(root, "/usr", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *lib = root ?
        vfs_create_path(root, "/usr/lib", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *mich = root ?
        vfs_create_path(root, "/usr/lib/mich", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *path_file = root ?
        vfs_create_path(root, "/usr/lib/mich/config", VFS_NODE_REGULAR) : 0;
    struct kernel_object *absolute = root ? vfs_resolve(
        root, "///usr//lib/./mich/../mich/config") : 0;
    struct kernel_object *relative = mich ?
        vfs_resolve(mich, "../mich/config") : 0;
    struct kernel_object *clamped = root ?
        vfs_resolve(root, "/../../usr") : 0;
    struct kernel_object *trailing = root ?
        vfs_resolve(root, "/usr/lib/mich/config/") : 0;
    struct kernel_object *beneath_ok = mich ?
        vfs_resolve_beneath(mich, "config") : 0;
    struct kernel_object *beneath_dotdot = usr ?
        vfs_resolve_beneath(usr, "lib/../lib/mich/config") : 0;
    int beneath_confined = usr && mich && boot_directory &&
        !vfs_resolve_beneath(usr, "..") &&
        !vfs_resolve_beneath(usr, "lib/../..") &&
        !vfs_resolve_beneath(mich, "../mich/config") &&
        !vfs_resolve_beneath(mich, "/usr/lib/mich/config") &&
        !vfs_resolve_beneath(boot_directory, "..");
    char deep[VFS_PATH_MAX];
    u32 deep_length = 0;
    for (u32 component = 0; component < VFS_PATH_COMPONENT_MAX + 1;
         component++) {
        deep[deep_length++] = '/';
        deep[deep_length++] = '.';
    }
    deep[deep_length] = 0;
    valid = valid && usr && lib && mich && path_file &&
        absolute == path_file && relative == path_file && clamped == usr &&
        beneath_ok == path_file && beneath_dotdot == path_file &&
        beneath_confined &&
        !trailing && !vfs_resolve(root, deep) &&
        !vfs_unlink_path(root, "/usr/lib/mich/config") &&
        !vfs_unlink_path(root, "/usr/lib/mich") &&
        !vfs_unlink_path(root, "/usr/lib") &&
        !vfs_unlink_path(root, "/usr");
    if (absolute) object_release(absolute);
    if (relative) object_release(relative);
    if (clamped) object_release(clamped);
    if (beneath_ok) object_release(beneath_ok);
    if (beneath_dotdot) object_release(beneath_dotdot);
    if (path_file) object_release(path_file);
    if (mich) object_release(mich);
    if (lib) object_release(lib);
    if (usr) object_release(usr);
    for (u32 iteration = 0; iteration < 4096; iteration++) {
        char mutation[VFS_PATH_MAX];
        u32 mutation_length = 1 + (iteration % 96);
        for (u32 index = 0; index < mutation_length; index++) {
            u32 value = (iteration * 17 + index * 13) % 7;
            mutation[index] = value == 0 ? '/' : value == 1 ? '.' :
                (char)('a' + value - 2);
        }
        mutation[mutation_length] = 0;
        struct kernel_object *resolved = vfs_resolve(root, mutation);
        if (resolved) object_release(resolved);
    }
    if (firmware_file) object_release(firmware_file);
    if (boot_file) object_release(boot_file);
    if (boot_parent) object_release(boot_parent);
    if (boot_node) object_release(boot_node);
    if (boot_directory) object_release(boot_directory);
    if (opened) object_release(opened);
    if (lookup) object_release(lookup);
    if (node) object_release(node);
    if (directory) object_release(directory);
    if (mount) object_release(mount);
    if (root) object_release(root);
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        vfs_mount_active_count() == mounts;
    return valid ? 0 : -1;
}


int test_vfs_pages64(void) {
    u32 objects = object_active_count();
    u32 nodes = vfs_node_active_count();
    u32 files = vfs_file_active_count();
    u32 free_pages = pmm_free_pages();
    static u8 payload[3 * 4096 + 100];
    static u8 received[3 * 4096 + 100];
    struct kernel_object *root = vfs_root();
    struct kernel_object *directory = root ?
        vfs_create(root, "page-files", VFS_NODE_DIRECTORY) : 0;
    struct kernel_object *node = directory ?
        vfs_create(directory, "blob", VFS_NODE_REGULAR) : 0;
    struct kernel_object *opened = node ? vfs_open(node) : 0;
    u32 transferred = 0;
    u32 appended_position = 0;
    u32 span = sizeof(payload);
    for (u32 index = 0; index < span; index++)
        payload[index] = (u8)(index * 7 + 3);
    struct vfs_node_info info;
    int valid = root && directory && node && opened &&
        !vfs_write(opened, 0, payload, span, &transferred) &&
        transferred == span &&
        !vfs_stat(node, &info) && info.size == span;
    for (u32 index = 0; index < span; index++) received[index] = 0;
    valid = valid && !vfs_read(opened, 0, received, span, &transferred) &&
        transferred == span;
    for (u32 index = 0; index < span; index++)
        if (received[index] != payload[index]) valid = 0;
    valid = valid && !vfs_read(opened, 4090, received, 12, &transferred) &&
        transferred == 12;
    for (u32 index = 0; index < 12; index++)
        if (received[index] != payload[4090 + index]) valid = 0;
    valid = valid && !vfs_append(opened, payload, 5, &transferred,
                                 &appended_position) &&
        transferred == 5 && appended_position == span + 5;
    for (u32 index = 0; index < 7000; index++) received[index] = 0xA5;
    valid = valid && !vfs_write(opened, 20000, payload, 5, &transferred) &&
        transferred == 5 &&
        !vfs_stat(node, &info) && info.size == 20005 &&
        !vfs_read(opened, span + 5, received, 20000 - span - 5,
                  &transferred) &&
        transferred == 20000 - span - 5;
    for (u32 index = span + 5; index < 20000; index++)
        if (received[index - span - 5] != 0) valid = 0;
    valid = valid && !vfs_read(opened, 20000, received, 5, &transferred) &&
        transferred == 5;
    for (u32 index = 0; index < 5; index++)
        if (received[index] != payload[index]) valid = 0;
    valid = valid && !vfs_truncate(opened, 5000) &&
        !vfs_stat(node, &info) && info.size == 5000 &&
        !vfs_truncate(opened, 8000) &&
        !vfs_read(opened, 0, received, 8000, &transferred) &&
        transferred == 8000;
    for (u32 index = 0; index < 5000; index++)
        if (received[index] != payload[index]) valid = 0;
    for (u32 index = 5000; index < 8000; index++)
        if (received[index] != 0) valid = 0;
    valid = valid && !vfs_write(opened, 4990, payload, 20, &transferred) &&
        transferred == 20 &&
        !vfs_read(opened, 4990, received, 20, &transferred) &&
        transferred == 20;
    for (u32 index = 0; index < 20; index++)
        if (received[index] != payload[index]) valid = 0;
    valid = valid && !vfs_truncate(opened, 0) &&
        !vfs_stat(node, &info) && info.size == 0 &&
        !vfs_write(opened, 4096, payload, 4096, &transferred) &&
        transferred == 4096 &&
        !vfs_read(opened, 0, received, 8192, &transferred) &&
        transferred == 8192;
    for (u32 index = 0; index < 4096; index++)
        if (received[index] != 0) valid = 0;
    for (u32 index = 4096; index < 8192; index++)
        if (received[index] != payload[index - 4096]) valid = 0;
    valid = valid &&
        vfs_write(opened, VFS_FILE_SIZE_MAX, payload, 1, &transferred) < 0 &&
        vfs_write(opened, VFS_FILE_SIZE_MAX - 4, payload, 8,
                  &transferred) < 0 &&
        vfs_truncate(opened, VFS_FILE_SIZE_MAX + 1) < 0;
    if (opened) object_release(opened);
    valid = valid && !vfs_unlink(directory, "blob");
    if (node) object_release(node);
    if (directory) object_release(directory);
    valid = valid && !vfs_unlink(root, "page-files");
    if (root) object_release(root);
    valid = valid && object_active_count() == objects &&
        vfs_node_active_count() == nodes &&
        vfs_file_active_count() == files &&
        pmm_free_pages() == free_pages;
    return valid ? 0 : -1;
}
