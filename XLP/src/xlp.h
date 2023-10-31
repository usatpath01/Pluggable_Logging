#ifndef __WRITESNOOP_H
#define __WRITESNOOP_H

#define TASK_COMM_LEN 16
#define MAX_MSG_LEN 200
#define MAX_FILEPATH_SIZE 200
#define MAX_FILE_AND_DIR_NAME_SIZE 10
#define MAX_DIR_LEVELS_ALLOWED 6
#define MAX_EXECVE_ARGS 20
#define SYSCALL_NAME_MAXLEN 20
#define MAX_PERCPU_BUFSIZE (1 << 15)
#define MAX_BUFFERS 2
#define MAX_PATH_COMPONENTS 16
#define MAX_STRING_SIZE 1024

typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

// Generate macros for system call flags
#define GENERATE_SYSCALL_FLAG(name, index) \
    #name "_FLAG", \
    
#define READ_FLAG 0
#define WRITE_FLAG 1
#define OPENAT_FLAG 2
#define DUP_FLAG 3
#define DUP2_FLAG 4
#define DUP3_FLAG 5
#define CLONE_FLAG 6
#define VFORK_FLAG 7
#define FORK_FLAG 8
#define EXECVE_FLAG 9
#define ACCEPT_FLAG 10
#define CONNECT_FLAG 11
#define BIND_FLAG 12
#define ACCEPT4_FLAG 13
#define EXIT_FLAG 14
#define EXIT_GROUP_FLAG 15
#define UNLINKAT_FLAG 16
#define OPEN_FLAG 17
#define CLOSE_FLAG 18

typedef struct task_context {
    u32 host_pid;               /* PID in host pid namespace */
    u32 host_tid;               /* TID in host pid namespace */
    u32 host_ppid;              /* Parent PID in host pid namespace */
    u32 pid;                    /* PID as in the userspace term */
    u32 tid;                    /* TID as in the userspace term */
    u32 ppid;                   /* Parent PID as in the userspace term */
    u64 cgroup_id;              /* Cgroup ID */
    u32 mntns_id;               /* Mount namespace inode number */
    u32 pidns_id;               /* PID namespace inode number */
    char comm[TASK_COMM_LEN];   /* Command for the task */
    char exe_path[MAX_FILEPATH_SIZE];   /* Executable file path */
} task_context_t;

typedef struct event_context {
    u64 ts;                     /* Time at which ecent occurs in nanosecs since boot */
    u32 syscall_id;             /* Syscall that triggered event, = -1 for application log */
    task_context_t task;        /* Task related context */
} event_context_t;

struct applog_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Data
    unsigned int fd;                            /* File descriptor */
    unsigned int count;                         /* Number of characters in full log message */
    char msg[MAX_MSG_LEN];                      /* Application log message string (lms) */
};

struct read_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    unsigned int fd;                            /* File descriptor of file to be read */
    char *buf;                                  /* Starting address of buffer */
    size_t count;                               /* Number of bytes ro be read */

    char filepath[MAX_FILEPATH_SIZE];           /* Full path of the file read from */
    
    long retval;                                /* Return value */
};

struct write_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    unsigned int fd;                            /* File descriptor of file to be written */
    char *buf;                                  /* Starting address of buffer */
    unsigned int count;                         /* Number of bytes being written */

    char filepath[MAX_FILEPATH_SIZE];           /* Full path of the file written to */
    
    long retval;                                /* Return value */
};

struct open_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    char filename[MAX_FILEPATH_SIZE];           /* File path of the file to be opened */
    int flags;                                  /* Flags */
    unsigned short mode;                        /* Mode */
    
    long retval;                                /* Return value */
};

struct close_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    unsigned int fd;                            /* File descriptor to be closed */

    long retval;                                /* Return value */
};

struct dup_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    unsigned int fildes;                        /* File descriptor */

    long retval;                                /* Return value */
};

struct dup2_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    unsigned int oldfd;                         /* Old file descriptor */
    unsigned int newfd;                         /* New file descriptor */

    long retval;                                /* Return value */
};

struct connect_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    int fd;                                     /* Socket file descriptor */
    void *uservaddr;                            /* Server address info */
    int addrlen;                                /* Server address length */
    // Data

    long retval;                                /* Return value */
};

struct accept_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    int fd;                                     /* Socket file descriptor */
    void *upeer_sockaddr;                       /* Peer address info */
    int *upeer_addrlen;                         /* Peer address length */
    // Data

    long retval;                                /* Return value */
};

struct bind_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    int fd;                                     /* Socket file descriptor */
    void *umyaddr;                              /* My address info */
    int addrlen;                                /* My address length */

    long retval;                                /* Return value */
};

struct clone_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    unsigned long flags;                        /* Flags */
    void *newsp;                                /* New stack pointer */
    int *parent_tid;                            /* Parent's TID (To be populated) */
    int *child_tid;                             /* Child' TID (To be populated) */
    unsigned long tls;                          /* Thread local struct */
    
    long retval;                                /* Return value */
};

struct fork_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    
    long retval;                                /* Return value */
};

struct vfork_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    
    long retval;                                /* Return value */
};

struct execve_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    char *filename;                                 /* File path of the binary that is executed */
    char **argv;                                    /* Arguments that the binary is executed with */

    long retval;                                /* Return value */
};

struct exit_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    int error_code;                             /* Error code with which exited */
    
    long retval;                                /* Return value */
};

struct exit_group_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    int error_code;                             /* Error code with which exited */
    
    long retval;                                /* Return value */
};

struct openat_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    int dfd;                                    /* Directory file descriptor */
    char filename[MAX_FILEPATH_SIZE];           /* File path of the file to be opened */
    int flags;                                  /* Flags */
    unsigned short mode;                        /* Mode */
    
    long retval;                                /* Return value */
};

struct unlinkat_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    int dfd;                                    /* Directory file descriptor */
    char pathname[MAX_FILEPATH_SIZE];           /* File path of the file to be unlinked */
    int flag;                                   /* Flags */

    long retval;                                /* Return value */
};

struct accept4_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    int fd;                                     /* Socket file descriptor */
    void *upeer_sockaddr;                       /* Peer address info (To be populated) */
    int *upeer_addrlen;                         /* Peer address length (To be populated) */
    int flags;                                  /* Flags */      
    // Data
    
    long retval;                                /* Return value */
};

struct dup3_data_t {
    // Metadata
    event_context_t event;                      /* Event context */
    // Args
    unsigned int oldfd;                         /* Old file descriptor */
    unsigned int newfd;                         /* New file descriptor */
    int flags;                                  /* Flags */

    long retval;                                /* Return value */
};


#endif /* __WRITESNOOP_H */
