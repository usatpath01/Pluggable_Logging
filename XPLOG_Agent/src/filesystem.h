#ifndef __FILESYSTEM_H
#define __FILESYSTEM_H

#include "vmlinux.h"
#include "xlp.h"
#include "buffer.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

static __always_inline struct file *get_struct_file_from_fd(u64 fd_num)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    struct file **fd = BPF_CORE_READ(task, files, fdt, fd);
    struct file *f;
    bpf_core_read(&f, sizeof(f), &fd[fd_num]);
    return f;
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_name);
}

static __always_inline void *get_file_str(struct file *file)
{
    char slash = '/';
    int zero = 0;
    
    struct path f_path = BPF_CORE_READ(file, f_path);
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;

    // struct mount *mnt_p = real_mount(vfsmnt);
    // bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1); // starts at the last index of the string, ends at the first index
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(0);
    if (string_p == NULL)
        return NULL;

    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        // mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        d_parent = BPF_CORE_READ(dentry, d_parent);
        if (dentry == mnt_root || dentry == d_parent) {
            // if (dentry != mnt_root) {
            //     // We reached root, but not mount root - escaped?
            //     break;
            // }
            // if (mnt_p != mnt_parent_p) {
            //     // We reached root, but not global root - continue with mount point path
            //     bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
            //     bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
            //     bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
            //     vfsmnt = &mnt_p->mnt;
            //     continue;
            // }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = get_d_name_from_dentry(dentry);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;

        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_core_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *) d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_core_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        d_name = get_d_name_from_dentry(dentry);
        bpf_core_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_core_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_core_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }

    return &string_p->buf[buf_off];
}

#endif // __FILESYSTEM_H