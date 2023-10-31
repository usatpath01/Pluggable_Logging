#ifndef __UTIL_H
#define __UTIL_H

#include "vmlinux.h"
#include "xlp.h"
#include "syscall.h"
#include "filesystem.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define FILTER_SELF if(mypid == (bpf_get_current_pid_tgid() >> 32)) {return 0;}
#define FILTER_CONTAINER if((bpf_get_current_pid_tgid() >> 32) == get_task_ns_tgid((struct task_struct *)bpf_get_current_task())) {return 0;}

typedef struct
{
    long unsigned int args[6];
} args_t;

typedef struct
{
    char exe_name[MAX_FILEPATH_SIZE];
} copy_str;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
    __type(value, copy_str);
    __uint(max_entries, 10240);
} pid_exec_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
    __type(value, args_t);
    __uint(max_entries, 1024);
} pid_args_map SEC(".maps");

static void *reserve_in_event_queue(void *ringbuf, u64 payload_size, u64 flags)
{
    void *data = bpf_ringbuf_reserve(ringbuf, payload_size + sizeof(u32), flags);
    if (!data) /* Null-check the pointer to the address in the ringbuf, must-do */
        return NULL;
    return data;
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, mnt_ns, ns.inum);
}

static __always_inline u32 get_pid_ns_for_children_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, pid_ns_for_children, ns.inum);
}

static __always_inline u32 get_uts_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, uts_ns, ns.inum);
}

static __always_inline u32 get_ipc_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, ipc_ns, ns.inum);
}

static __always_inline u32 get_net_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, net_ns, ns.inum);
}

static __always_inline u32 get_cgroup_ns_id(struct nsproxy *ns)
{
    return BPF_CORE_READ(ns, cgroup_ns, ns.inum);
}

static __always_inline u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

    pid = BPF_CORE_READ(task, thread_pid);
    level = BPF_CORE_READ(task, thread_pid, level);
    struct upid *numbers = NULL;

    return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    return get_task_pid_vnr(group_leader);
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    return get_task_pid_vnr(real_parent);
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(BPF_CORE_READ(task, nsproxy));
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

    pid = BPF_CORE_READ(task, thread_pid);
    level = BPF_CORE_READ(task, thread_pid, level);
    struct upid *numbers = NULL;

    return BPF_CORE_READ(pid, numbers[level].ns, ns.inum);
}

static void init_event(event_context_t *event_ctx, struct task_struct *task, u32 syscall_id)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 host_pid = (id >> 32);
    event_ctx->ts = bpf_ktime_get_boot_ns();
    event_ctx->syscall_id = syscall_id;
    event_ctx->task.host_tid = id;
    event_ctx->task.host_pid = (id >> 32);
    event_ctx->task.host_ppid = get_task_ppid(task);
    event_ctx->task.tid = get_task_ns_pid(task);
    event_ctx->task.pid = get_task_ns_tgid(task);
    event_ctx->task.ppid = get_task_ns_ppid(task);
    event_ctx->task.cgroup_id = bpf_get_current_cgroup_id();
    event_ctx->task.mntns_id = get_task_mnt_ns_id(task);
    event_ctx->task.pidns_id = get_task_pid_ns_id(task);
    bpf_get_current_comm(event_ctx->task.comm, sizeof(event_ctx->task.comm));
    copy_str *exe_filepath = (copy_str *)bpf_map_lookup_elem(&pid_exec_map, &host_pid);
    bpf_probe_read_str(event_ctx->task.exe_path, sizeof(event_ctx->task.exe_path), exe_filepath->exe_name);
}

static void *init_event_header(void *data, u32 syscall_id)
{
    *((u32 *)data) = syscall_id;
    data = data + sizeof(u32);
    return data;
}

#endif /* __UTIL_H */