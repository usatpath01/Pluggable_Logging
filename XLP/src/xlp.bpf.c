#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "xlp.h"
#include "util.h"
#include "syscall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int mypid = 0;
int filter_container = 0;
unsigned int syscall_flags = ((1UL << 32) - 1);

/* Compare two strings (whose sizes are known) passed for equality */
static __always_inline int string_cmp(
    const unsigned char *string1,
    const unsigned char *string2,
    unsigned int size1,
    unsigned int size2)
{
    if(size1 != size2) {
        return -1;
    }
    for(int i = 0; i < size1; ++i) {
        if(string1[i] != string2[i]) {
            return -1;
        }
    }
    return 0;
}

static inline void string_cpy(char* string_to, const char* string_from, int len_from)
{
    for(int i = 0;i < len_from; i++)
    {
        string_to[i] = string_from[i];
    }
}

/* Check if the filepath to which the write call is equal to - "/var/log/app/.*" */
static __always_inline int check_log_filepath(unsigned int fd) {
    // struct files_struct *files = NULL;
    // struct fdtable *fdt = NULL;
    struct file **_fdt = NULL;
    struct file *f = NULL;
    struct dentry *de = NULL;
    struct dentry *de_parent = NULL;
    struct task_struct *curr = NULL;
    int nread = 0;
    int buf_cnt = 0;
    int i = 1;
    const unsigned char dirname_var[] = {'v','a','r','\0'};
    const unsigned char dirname_log[] = {'l','o','g','\0'};
    const unsigned char dirname_app[] = {'a','p','p','\0'};
    int var_dirlevel = -1; /* Root directory is the lowest level */
    int log_dirlevel = -1;
    int app_dirlevel = -1;

    curr = (struct task_struct *)bpf_get_current_task();
    // bpf_probe_read_kernel(&files, sizeof(files), &curr->files);
    // bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    // bpf_probe_read_kernel(&_fdt, sizeof(_fdt), &fdt->fd);
    // bpf_probe_read_kernel(&f, sizeof(f), &_fdt[fd]);
    // bpf_probe_read_kernel(&de, sizeof(de), &f->f_path.dentry);
    _fdt = BPF_CORE_READ(curr, files, fdt, fd);
    bpf_core_read(&f, sizeof(f), &_fdt[fd]);
    de = BPF_CORE_READ(f, f_path.dentry);

    /* Iterate up the dentry hierarchy and store the lowest levels at which
    "var/", "log/" and "app/" occur. If the filepath is "/var/log/app/.*" then
    these levels occur as consecutive integers and thus return 1, else return 0 */
    for (i = MAX_DIR_LEVELS_ALLOWED; i >= 1; --i) {
        // bpf_probe_read_kernel(&de_parent, sizeof(de_parent), &de->d_parent);
        de_parent = BPF_CORE_READ(de, d_parent);
        if(de_parent == NULL) {
            break;
        }
        
	    struct qstr d_name = {};
        unsigned char name[MAX_FILEPATH_SIZE];
        unsigned int len = 0;
        
	    // bpf_probe_read_kernel(&len, sizeof(len), &d_name.len);
        len = BPF_CORE_READ(de_parent, d_name.len);

        // bpf_probe_read(&d_name, sizeof(d_name), &de_parent->d_name);
        // bpf_probe_read_str(name, MAX_FILEPATH_SIZE, d_name.name);
        bpf_core_read(&d_name, sizeof(d_name), &de_parent->d_name);
        bpf_core_read_str(name, MAX_FILEPATH_SIZE, d_name.name);
	
	    if(string_cmp(name, dirname_var, len+1, 4) == 0) {
            var_dirlevel = i;
        }
        if(string_cmp(name, dirname_log, len+1, 4) == 0) {
            log_dirlevel = i;
        }
        if(string_cmp(name, dirname_app, len+1, 4) == 0) {
            app_dirlevel = i;
        }
        de = de_parent;
    }
    return (app_dirlevel == log_dirlevel + 1 && log_dirlevel == var_dirlevel + 1);
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : unsigned int fd
    ctx->args[1] : char *buf
    ctx->args[2] : unsigned int count
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> READ_FLAG) & 1)) return 0;
    void *event_data;
    struct read_data_t *read_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct read_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    read_data = (struct read_data_t *)init_event_header(event_data, SYSCALL_READ);
    
    /* Task and event context */
    init_event(&read_data->event, curr, SYSCALL_READ);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    if(ctx_args != NULL && read_data != NULL)
    {
        /* Arguments */
        read_data->fd = (unsigned int)ctx_args->args[0];
        read_data->buf = (char *)ctx_args->args[1];
        read_data->count = (unsigned int)ctx_args->args[2];
        read_data->retval = ctx->ret;

        /* File read from */
        struct file *f = get_struct_file_from_fd(read_data->fd);
        char *filepath = get_file_str(f);
        bpf_probe_read_str(read_data->filepath, sizeof(read_data->filepath), filepath);
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_write")
int handle_write_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : unsigned int fd
    ctx->args[1] : const char *buf
    ctx->args[2] : unsigned int count
    */

    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> WRITE_FLAG) & 1)) return 0;
    
    void *event_data;
    struct write_data_t *write_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    
    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct write_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    write_data = (struct write_data_t *)init_event_header(event_data, SYSCALL_WRITE);
    
    /* Task and event context */
    init_event(&write_data->event, curr, SYSCALL_WRITE);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    if(ctx_args != NULL && write_data != NULL)
    {
        /* Arguments */
        write_data->fd = (unsigned int)ctx_args->args[0];
        write_data->buf = (char *)ctx_args->args[1];
        write_data->count = (unsigned int)ctx_args->args[2];
        write_data->retval = ctx->ret;

        /* File written to */
        struct file *f = get_struct_file_from_fd(write_data->fd);
        char *filepath = get_file_str(f);
        bpf_probe_read_str(write_data->filepath, sizeof(write_data->filepath), filepath);
    }

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);

    if(ctx_args == NULL)
        return 0;
    
    unsigned int fd = (unsigned int)ctx_args->args[0];

    /* Generate write augmented application log */
    /* Write to a log file */
    if(fd == 1 || fd == 2 || check_log_filepath(fd)) {
        int i = 0;
        int c = 5;
        int cnt = (int)ctx_args->args[2];
        char *buf = (char *)ctx_args->args[1];
        while(c--) {
            /* Reserve sizeof(struct applog_data_t) + sizeof(u32) storage in the ringbuffer */
            void *event_data;
            struct applog_data_t *applog_data;

            event_data = reserve_in_event_queue(&rb, sizeof(struct applog_data_t), 0);
            if(!event_data)
                return 0;
            applog_data = (struct applog_data_t *)init_event_header(event_data, APP);

            /* Task and event context */
            init_event(&applog_data->event, curr, APP);

            /* Other data */
            applog_data->fd = fd; // File descriptor
            u32 num_bytes = MAX_MSG_LEN;
            if(cnt < MAX_MSG_LEN && cnt > 0)
            {
                num_bytes = cnt;
            }
            applog_data->count = num_bytes;
            bpf_core_read_user(applog_data->msg, MAX_MSG_LEN, (void *)buf); // Log message string

            /* Successfully submit it to user-space for post-processing */
            bpf_ringbuf_submit(event_data, 0);

            cnt -= MAX_MSG_LEN;
            if(cnt < 0){
                break;
            }
            buf = buf + MAX_MSG_LEN - 1;
        }
    }
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);
	return 0;
}

SEC("tp/syscalls/sys_exit_open")
int handle_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : const char *filename
    ctx->args[1] : int flags
    ctx->args[2] : umode_t mode
    */

    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> OPEN_FLAG) & 1)) return 0;
    
    void *event_data;
    struct open_data_t *open_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct open_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    open_data = (struct open_data_t *)init_event_header(event_data, SYSCALL_OPEN);
    
    /* Task and event context */
    init_event(&open_data->event, curr, SYSCALL_OPEN);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && open_data != NULL)
    {
        bpf_probe_read_str(open_data->filename, sizeof(open_data->filename), (char *)ctx_args->args[0]);
        open_data->flags = (int)ctx_args->args[1];
        open_data->mode = (unsigned short)ctx_args->args[2];
        open_data->retval = ctx->ret;
    }

    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : unsigned int fd
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> CLOSE_FLAG) & 1)) return 0;

    void *event_data;
    struct close_data_t *close_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct close_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    close_data = (struct close_data_t *)init_event_header(event_data, SYSCALL_CLOSE);
    
    /* Task and event context */
    init_event(&close_data->event, curr, SYSCALL_CLOSE);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && close_data != NULL)
    {
        close_data->fd = (unsigned int)ctx_args->args[0];
        close_data->retval = ctx->ret;
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_dup")
int handle_dup_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : unsigned int fildes
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> DUP_FLAG) & 1)) return 0;

    void *event_data;
    struct dup_data_t *dup_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct dup_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    dup_data = (struct dup_data_t *)init_event_header(event_data, SYSCALL_DUP);
    
    /* Task and event context */
    init_event(&dup_data->event, curr, SYSCALL_DUP);

     /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && dup_data != NULL)
    {
        dup_data->fildes = (unsigned int)ctx_args->args[0];
        dup_data->retval = ctx->ret;
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_dup2")
int handle_dup2_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : unsigned int oldfd
    ctx->args[1] : unsigned int newfd
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> DUP2_FLAG) & 1)) return 0;

    void *event_data;
    struct dup2_data_t *dup2_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct dup2_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    dup2_data = (struct dup2_data_t *)init_event_header(event_data, SYSCALL_DUP2);
    
    /* Task and event context */
    init_event(&dup2_data->event, curr, SYSCALL_DUP2);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && dup2_data != NULL)
    {
        dup2_data->oldfd = (unsigned int)ctx_args->args[0];
        dup2_data->newfd = (unsigned int)ctx_args->args[1];
        dup2_data->retval = ctx->ret;
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : int fd
    ctx->args[1] : struct sockaddr *uservaddr
    ctx->args[2] : int addrlen
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> CONNECT_FLAG) & 1)) return 0;

    void *event_data;
    struct connect_data_t *connect_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct connect_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    connect_data = (struct connect_data_t *)init_event_header(event_data, SYSCALL_CONNECT);
    
    /* Task and event context */
    init_event(&connect_data->event, curr, SYSCALL_CONNECT);

    /* Lookup in args map */
    
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && connect_data != NULL)
    {
        connect_data->fd = (int)ctx_args->args[0];
        connect_data->uservaddr = (void *)ctx_args->args[1];
        connect_data->addrlen = (int)ctx_args->args[2];
        connect_data->retval = ctx->ret;
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_accept")
int handle_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : int fd
    ctx->args[1] : struct sockaddr *upeer_sockaddr
    ctx->args[2] : int upeer_addrlen
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> ACCEPT_FLAG) & 1)) return 0;

    void *event_data;
    struct accept_data_t *accept_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct accept_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    accept_data = (struct accept_data_t *)init_event_header(event_data, SYSCALL_ACCEPT);
    
    /* Task and event context */
    init_event(&accept_data->event, curr, SYSCALL_ACCEPT);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && event_data != NULL)
    {
        accept_data->fd = (int)ctx_args->args[0];
        accept_data->upeer_sockaddr = (void *)ctx_args->args[1];
        accept_data->upeer_addrlen = (int *)ctx_args->args[2];
        accept_data->retval = ctx->ret;
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_bind")
int handle_bind_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : int fd
    ctx->args[1] : struct sockaddr *umyaddr
    ctx->args[2] : int addrlen
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> BIND_FLAG) & 1)) return 0;

    void *event_data;
    struct bind_data_t *bind_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct bind_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    bind_data = (struct bind_data_t *)init_event_header(event_data, SYSCALL_BIND);
    
    /* Task and event context */
    init_event(&bind_data->event, curr, SYSCALL_BIND);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && bind_data != NULL)
    {
        bind_data->fd = (int)ctx_args->args[0];
        bind_data->umyaddr = (void *)ctx_args->args[1];
        bind_data->addrlen = (int)ctx_args->args[2];
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER

    int syscall_id = ctx->args[1];
    args_t ctx_args = {};
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    switch(syscall_id)
    {
        case SYSCALL_WRITE:
        case SYSCALL_READ:
		case SYSCALL_OPEN:
		case SYSCALL_CLOSE:
		case SYSCALL_DUP:
		case SYSCALL_DUP2:
		case SYSCALL_CONNECT:
		case SYSCALL_ACCEPT:
		case SYSCALL_BIND:
		case SYSCALL_CLONE:
		case SYSCALL_FORK:
		case SYSCALL_VFORK:
		case SYSCALL_EXECVE:
		case SYSCALL_EXIT:
		case SYSCALL_EXIT_GROUP:
		case SYSCALL_OPENAT:
		case SYSCALL_UNLINKAT:
		case SYSCALL_ACCEPT4:
		case SYSCALL_DUP3:
            /* Copy system call arguments to program stack */
            ctx_args.args[0] = PT_REGS_PARM1_CORE(regs);
            ctx_args.args[1] = PT_REGS_PARM2_CORE(regs);
            ctx_args.args[2] = PT_REGS_PARM3_CORE(regs);
            ctx_args.args[3] = PT_REGS_PARM4_CORE(regs);
            ctx_args.args[4] = PT_REGS_PARM5_CORE(regs);

            u32 host_pid = (bpf_get_current_pid_tgid() >> 32);    
            /*Add arguments to map*/
            bpf_map_update_elem(&pid_args_map, &host_pid, &ctx_args, 0);
            break;
		default:
			return 0;
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_clone")
int handle_clone_exit(struct trace_event_raw_sys_exit *ctx)
{
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> CLONE_FLAG) & 1)) return 0;

    void *event_data;
    struct clone_data_t *clone_data;

    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct clone_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    clone_data = (struct clone_data_t *)init_event_header(event_data, SYSCALL_CLONE);
    
    /* Task and event context */
    init_event(&clone_data->event, curr, SYSCALL_CLONE);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && clone_data != NULL)
    {
        clone_data->flags = (unsigned long)ctx_args->args[0];
        clone_data->newsp = (void *)ctx_args->args[1];
        clone_data->parent_tid = (int *)ctx_args->args[2];
        clone_data->child_tid = (int *)ctx_args->args[3];
        clone_data->tls = (unsigned long)ctx_args->args[4];
        clone_data->retval = ctx->ret;
    }

    if(clone_data != NULL && clone_data->retval == 0 && clone_data->event.task.pid == clone_data->event.task.tid)
    {
        /* Update pid_exec map if child process */
        copy_str ename = {};
        struct file *f = BPF_CORE_READ(curr, mm, exe_file);
        char *exe_filepath = (char *)get_file_str(f);
        bpf_core_read_str(ename.exe_name, sizeof(ename.exe_name), exe_filepath);
        bpf_map_update_elem(&pid_exec_map, &host_pid, &ename, 0);

        /* Update task_context data */
        bpf_core_read_str(clone_data->event.task.exe_path, sizeof(clone_data->event.task.exe_path), exe_filepath);
    }

    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}


SEC("tp/syscalls/sys_exit_fork")
int handle_fork_exit(struct trace_event_raw_sys_exit *ctx)
{
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> FORK_FLAG) & 1)) return 0;

    void *event_data;
    struct fork_data_t *fork_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct fork_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    fork_data = (struct fork_data_t *)init_event_header(event_data, SYSCALL_FORK);
    
    /* Task and event context */
    init_event(&fork_data->event, curr, SYSCALL_FORK);

    /* Lookup in args map */
    
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);
    
    /* Arguments */
    if(ctx_args != NULL && fork_data != NULL)
    {
        fork_data->retval = ctx->ret;
    }

    if(fork_data != NULL && fork_data->retval == 0)
    {
        /* Update pid_exec map if child process */
        copy_str ename = {};
        struct file *f = BPF_CORE_READ(curr, mm, exe_file);
        char *exe_filepath = (char *)get_file_str(f);
        bpf_core_read_str(ename.exe_name, sizeof(ename.exe_name), exe_filepath);
        bpf_map_update_elem(&pid_exec_map, &host_pid, &ename, 0);

        /* Update task_context data */
        bpf_core_read_str(fork_data->event.task.exe_path, sizeof(fork_data->event.task.exe_path), exe_filepath);
    }

    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_vfork")
int handle_vfork_exit(struct trace_event_raw_sys_exit *ctx)
{
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> VFORK_FLAG) & 1)) return 0;

    void *event_data;
    struct vfork_data_t *vfork_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct vfork_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    vfork_data = (struct vfork_data_t *)init_event_header(event_data, SYSCALL_VFORK);
    
    /* Task and event context */
    init_event(&vfork_data->event, curr, SYSCALL_VFORK);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && vfork_data != NULL)
    {
        vfork_data->retval = ctx->ret;
    }

    if(vfork_data != NULL && vfork_data->retval == 0)
    {
        /* Update pid_exec map if child process */
        copy_str ename = {};
        struct file *f = BPF_CORE_READ(curr, mm, exe_file);
        char *exe_filepath = (char *)get_file_str(f);
        bpf_core_read_str(ename.exe_name, sizeof(ename.exe_name), exe_filepath);
        bpf_map_update_elem(&pid_exec_map, &host_pid, &ename, 0);

        /* Update task_context data */
        bpf_core_read_str(vfork_data->event.task.exe_path, sizeof(vfork_data->event.task.exe_path), exe_filepath);
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* TODO: Pass filename string and argv list of strings to the exit tracepoint */
    return 0;
}

SEC("tp/syscalls/sys_exit_execve")
int handle_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : const char *filename
    ctx->args[1] : const char *__argv
    ctx->args[2] : const char *__envp
    */

    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> EXECVE_FLAG) & 1)) return 0;
    
    void *event_data;
    struct execve_data_t *execve_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 host_pid = (tgid_pid >> 32);

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct execve_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    execve_data = (struct execve_data_t *)init_event_header(event_data, SYSCALL_EXECVE);
    
    /* Task and event context */
    init_event(&execve_data->event, curr, SYSCALL_EXECVE);

    /* Lookup in args map */
    args_t *ctx_args = bpf_map_lookup_elem(&pid_args_map, &host_pid);
    
    if(ctx_args != NULL && execve_data != NULL)
    {
        /* Arguments */
        execve_data->filename = (char *)ctx_args->args[0];
        execve_data->argv = (char **)ctx_args->args[1];
        execve_data->retval = ctx->ret;

        /* Update pid_exec map */
        copy_str ename = {};
        struct file *f = BPF_CORE_READ(curr, mm, exe_file);
        char *exe_filepath = (char *)get_file_str(f);
        bpf_core_read_str(ename.exe_name, sizeof(ename.exe_name), exe_filepath);
        bpf_map_update_elem(&pid_exec_map, &host_pid, &ename, 0);

        /* Update task_context data */
        bpf_core_read_str(execve_data->event.task.exe_path, sizeof(execve_data->event.task.exe_path), exe_filepath);
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;

}

SEC("tp/syscalls/sys_exit_exit")
int handle_exit_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    cts->args[0] : int error_code
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> EXIT_FLAG) & 1)) return 0;

    void *event_data;
    struct exit_data_t *exit_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct exit_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    exit_data = (struct exit_data_t *)init_event_header(event_data, SYSCALL_EXIT);
    
    /* Task and event context */
    init_event(&exit_data->event, curr, SYSCALL_EXIT);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && exit_data != NULL)
    {
        exit_data->error_code = (int)ctx_args->args[0];
        exit_data->retval = ctx->ret;
    }

    /* Clear pid_exec_map */
    bpf_map_delete_elem(&pid_exec_map, &host_pid);

    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_exit_group")
int handle_exit_group(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    cts->args[0] : int error_code
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> EXIT_GROUP_FLAG) & 1)) return 0;

    void *event_data;
    struct exit_group_data_t *exit_group_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct exit_group_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    exit_group_data = (struct exit_group_data_t *)init_event_header(event_data, SYSCALL_EXIT_GROUP);
    
    /* Task and event context */
    init_event(&exit_group_data->event, curr, SYSCALL_EXIT_GROUP);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && exit_group_data != NULL)
    {
        exit_group_data->error_code = (int)ctx_args->args[0];
        exit_group_data->retval = ctx->ret;
    }
    
    /* Clear pid_exec_map */
    bpf_map_delete_elem(&pid_exec_map, &host_pid);

    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    cts->args[0] : int dfd
    ctx->args[1] : const char *filename
    ctx->args[2] : int flags
    ctx->args[3] : umode_t mode
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> OPENAT_FLAG) & 1)) return 0;

    void *event_data;
    struct openat_data_t *openat_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct openat_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    openat_data = (struct openat_data_t *)init_event_header(event_data, SYSCALL_OPENAT);
    
    /* Task and event context */
    init_event(&openat_data->event, curr, SYSCALL_OPENAT);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && openat_data != NULL)
    {
        openat_data->dfd = (int)ctx_args->args[0];
        bpf_probe_read_user_str(openat_data->filename, sizeof(openat_data->filename), (char *)ctx_args->args[1]);
        openat_data->flags = (int)ctx_args->args[2];
        openat_data->mode = (unsigned short)ctx_args->args[3];
        openat_data->retval = ctx->ret;

        /* Update (pid, file opened) map */
        // copy_str ename = {};
        // bpf_probe_read_user_str(ename.exe_name, sizeof(ename.exe_name), (char *)ctx_args->args[0]);
        // bpf_map_update_elem(&pid_exec_map, &host_pid, &ename, 0);
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_unlinkat")
int handle_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    cts->args[0] : int dfd
    ctx->args[1] : const char *pathname
    ctx->args[2] : int flag
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> UNLINKAT_FLAG) & 1)) return 0;

    void *event_data;
    struct unlinkat_data_t *unlinkat_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct unlinkat_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    unlinkat_data = (struct unlinkat_data_t *)init_event_header(event_data, SYSCALL_UNLINKAT);
    
    /* Task and event context */
    init_event(&unlinkat_data->event, curr, SYSCALL_UNLINKAT);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && unlinkat_data != NULL)
    {
        unlinkat_data->dfd = (int)ctx_args->args[0];
        bpf_probe_read_user_str(unlinkat_data->pathname, sizeof(unlinkat_data->pathname), (char *)ctx_args->args[1]);
        unlinkat_data->flag = (int)ctx_args->args[2];
        unlinkat_data->retval = ctx->ret;
    }
    
     /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_accept4")
int handle_accept4_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : int fd
    ctx->args[1] : struct sockaddr *upeer_sockaddr
    ctx->args[2] : int upeer_addrlen
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> ACCEPT4_FLAG) & 1)) return 0;

    void *event_data;
    struct accept4_data_t *accept4_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct accept4_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    accept4_data = (struct accept4_data_t *)init_event_header(event_data, SYSCALL_ACCEPT4);
    
    /* Task and event context */
    init_event(&accept4_data->event, curr, SYSCALL_ACCEPT4);

    /* Lookup in args map */
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && accept4_data != NULL)
    {
        accept4_data->fd = (int)ctx_args->args[0];
        accept4_data->upeer_sockaddr = (void *)ctx_args->args[1];
        accept4_data->upeer_addrlen = (int *)ctx_args->args[2];
        accept4_data->flags = (int)ctx_args->args[3];
        accept4_data->retval = ctx->ret;
    }
    
    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);


    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_dup3")
int handle_dup3_exit(struct trace_event_raw_sys_exit *ctx)
{
    /* 
    ctx->args[0] : unsigned int oldfd
    ctx->args[1] : unsigned int newfd
    ctx->args[2] : int flags
    */
    FILTER_SELF
    if(filter_container == 1) FILTER_CONTAINER
    if(!((syscall_flags >> DUP3_FLAG) & 1)) return 0;

    void *event_data;
    struct dup3_data_t *dup3_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct dup3_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    dup3_data = (struct dup3_data_t *)init_event_header(event_data, SYSCALL_DUP3);
    
    /* Task and event context */
    init_event(&dup3_data->event, curr, SYSCALL_DUP3);

    /* Lookup in args map */
    
    u32 host_pid = (bpf_get_current_pid_tgid() >> 32);
    args_t *ctx_args  = bpf_map_lookup_elem(&pid_args_map, &host_pid);

    /* Arguments */
    if(ctx_args != NULL && dup3_data != NULL)
    {
        dup3_data->oldfd = (unsigned int)ctx_args->args[0];
        dup3_data->newfd = (unsigned int)ctx_args->args[1];
        dup3_data->flags = (int)ctx_args->args[2];
        dup3_data->retval = ctx->ret;
    }

    /* Delete from args map */
    bpf_map_delete_elem(&pid_args_map, &host_pid);
    
    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

