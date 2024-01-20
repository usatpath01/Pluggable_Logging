// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <argp.h>
#include <strings.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "xlp.h"
#include "syscall.h"
#include "xlp.skel.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define QUOTE(...) #__VA_ARGS__

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

/* Supported system call names */
const char *system_calls[] = {
	"read",
	"write",
	"openat",
	"dup",
	"dup2",
	"dup3",
	"clone",
	"vfork",
	"fork",
	"execve",
	"accept",
	"connect",
	"bind",
	"accept4",
	"exit",
	"exit_group",
	"unlinkat",
	"open",
	"close",
	"send",
	"recv",
	"socket"};

const int num_system_calls = sizeof(system_calls) / sizeof(system_calls[0]);

// Structure to store command line arguments
struct arguments
{
	unsigned int bit_flags;
	int syscall_flag;
	int container_flag;
};

// Function to parse command line arguments
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key)
	{
	case 's':
		arguments->syscall_flag = 1;
		char *token;
		char *rest = arg;
		while ((token = strtok_r(rest, ",", &rest)))
		{
			int i;
			for (i = 0; i < num_system_calls; i++)
			{
				if (strcmp(token, system_calls[i]) == 0)
				{
					arguments->bit_flags |= (1 << i);
					break;
				}
			}

			if (i == num_system_calls)
			{
				argp_failure(state, 1, 0, "Unsupported system call '%s'", token);
			}
		}
		break;
	case 'c':
		arguments->container_flag = 1;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

// Define the argp options
static struct argp_option options[] = {
	{"system_call", 's', "SYSTEM_CALL", 0, "Comma separated list of supported system calls"},
	{"filter_container", 'c', 0, 0, "Enable container filtering mode"},
	{0}};

// Define the argp parser
static struct argp argp = {
	options,
	parse_opt,
	0,
	0};

int clientSocket;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	u32 event_id = *((u32 *)data);
	data = data + sizeof(u32);
	//char log_buffer[4096];
	char log_buffer[8192];
	memset(log_buffer, 0, sizeof(log_buffer));
	switch (event_id)
	{
	case APP:
	{
		const struct applog_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);
		
		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		char escaped_msg[250];

		// Escape all double quotes, newlines and other whitespace special chars
		int j = 0;
		for (int i = 0; i < d->count; i++)
		{
			char ch = d->msg[i];
			if (ch == '\"')
			{
				strcpy(escaped_msg + j, "\\\"");
				j += 2;
			}
			else if (ch == '\f')
			{
				strcpy(escaped_msg + j, "\\f");
				j += 2;
			}
			else if (ch == '\n')
			{
				strcpy(escaped_msg + j, "\\n");
				j += 2;
			}
			else if (ch == '\r')
			{
				strcpy(escaped_msg + j, "\\r");
				j += 2;
			}
			else if (ch == '\t')
			{
				strcpy(escaped_msg + j, "\\t");
				j += 2;
			}
			else if (ch == '\v')
			{
				strcpy(escaped_msg + j, "\\v");
				j += 2;
			}
			else
			{
				escaped_msg[j] = ch;
				j += 1;
			}
		}
		escaped_msg[j] = '\0';
		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"data" : {
							"fd" : % d,
							"lms" : "%s"
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
							// "file_writen"
						}
					}),
				d->event.ts, ts, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fd, escaped_msg, d->event.task.exe_path, epoctime);
		break;
	}
	case SYSCALL_READ:
	{
		const struct read_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "read",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"fd" : % d,
							"buf" : "0x%08x",
							"count" : % u
						},
						"artifacts" : {
							"exe" : "%s",
							"file_read" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fd, (unsigned int)d->buf, d->count,
				d->event.task.exe_path, d->filepath, epoctime);
		break;
	}
	case SYSCALL_WRITE:
	{
		const struct write_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "write",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"fd" : % d,
							"buf" : "0x%08x",
							"count" : % u
						},
						"artifacts" : {
							"exe" : "%s",
							"file_written" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fd, (unsigned int)d->buf, d->count,
				d->event.task.exe_path, d->filepath,epoctime);
		break;
	}
	case SYSCALL_OPEN:
	{
		const struct open_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "open",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"filename" : "%s",
							"flags" : % d,
							"mode" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 

						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->filename, d->flags, d->mode, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_CLOSE:
	{
		const struct close_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "close",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"fd" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fd, d->event.task.exe_path, epoctime);
		break;
	}
	case SYSCALL_DUP:
	{
		const struct dup_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "dup",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"fildes" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fildes, d->event.task.exe_path, epoctime);
		break;
	}
	case SYSCALL_DUP2:
	{
		const struct dup2_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "dup2",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"oldfd" : % d,
							"newfd" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->oldfd, d->newfd, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_CONNECT:
	{
		const struct connect_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		struct in_addr s_addr_in;
		s_addr_in.s_addr = d->s_addr;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "connect",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"fd" : % d,
							"uservaddr" : "0x%08x",
							"addrlen" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"IP" : "%s",
							"port" : "%d",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fd, d->uservaddr, d->addrlen, d->event.task.exe_path, inet_ntoa(s_addr_in), d->sin_port, epoctime);
		break;
	}
	case SYSCALL_ACCEPT:
	{
		const struct accept_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		struct in_addr s_addr_in;
		s_addr_in.s_addr = d->s_addr;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "accept",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"fd" : % d,
							"upeer_sockaddr" : "0x%08x",
							"upeer_addrlen" : "0x%08x"
						},
						"artifacts" : {
							"exe" : "%s",
							"IP" : "%s",
							"port" : "%d",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fd, d->upeer_sockaddr, d->upeer_addrlen, d->event.task.exe_path,inet_ntoa(s_addr_in), d->sin_port, epoctime);
		break;
	}
	case SYSCALL_SOCKET:
	{
		const struct socket_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;
		
		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "socket",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"domain" : % d,
							"type" :  % d,
							"protocol" : %d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->domain, d->type, d->protocol, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_SENDTO:
	{
		const struct send_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "send",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"sockfd" : % d,
							"buff" :  "0x%08x" , 
							"len" : % u, 
							"flags" : % u
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->sockfd, d->buff, d->len, d->flags, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_RECVFROM:
	{
		//fprintf(stderr,"Received Data: %s\n", data);
		const struct recv_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "recv",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"sockfd" : % d,
							"buff" :  "0x%08x" , 
							"len" : % u, 
							"flags" : % u
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->sockfd, d->buff, d->len, d->flags, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_BIND:
	{
		const struct bind_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "bind",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"fd" : % d,
							"umyaddr" : "0x%08x",
							"addrlen" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fd, d->umyaddr, d->addrlen, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_CLONE:
	{
		const struct clone_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "clone",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"flags" : % lu,
							"newsp" : "0x%08x",
							"parent_tid" : "0x%08x",
							"child_tid" : "0x%08x",
							"tls" : % lu
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->flags, d->newsp, d->parent_tid,
				d->child_tid, d->tls, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_FORK:
	{
		const struct fork_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "fork",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->event.task.exe_path, epoctime);
		break;
	}
	case SYSCALL_VFORK:
	{
		const struct vfork_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "vfork",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_EXECVE:
	{
		const struct execve_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "execve",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"filename" : "0x%08x",
							"argv" : "0x%08x"
						}
					}),
				epoctime, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->filename, d->argv);
		break;
	}
	case SYSCALL_EXIT:
	{
		const struct exit_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "exit",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"error_code" : "%d"
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->error_code, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_EXIT_GROUP:
	{
		const struct exit_group_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "exit_group",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"error_code" : "%d"
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->error_code, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_OPENAT:
	{
		const struct openat_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "openat",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"dfd" : % d,
							"filename" : "%s",
							"flags" : % d,
							"mode" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->dfd, d->filename, d->flags, d->mode, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_UNLINKAT:
	{
		const struct unlinkat_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "unlinkat",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"dfd" : % d,
							"pathname" : "%s",
							"flag" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->dfd, d->pathname, d->flag, d->event.task.exe_path,epoctime);
		break;
	}
	case SYSCALL_ACCEPT4:
	{
		const struct accept4_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		struct in_addr s_addr_in;
		s_addr_in.s_addr = d->s_addr;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "accept4",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"fd" : % d,
							"upeer_sockaddr" : "0x%08x",
							"upeer_addrlen" : "0x%08x",
							"flags" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"IP" : "%s",
							"port" : "%d",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->fd, d->upeer_sockaddr, d->upeer_addrlen, d->flags, d->event.task.exe_path,inet_ntoa(s_addr_in), d->sin_port, epoctime);
		break;
	}
	case SYSCALL_DUP3:
	{
		const struct dup3_data_t *d = data;
		char ts[32];
		time_t t;

		time(&t);
		struct tm *tmd = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;

		sprintf(log_buffer,
				QUOTE(
					{
						"event_context" : {
							"ts" : % llu,
							"datetime" : "%s",
							"syscall_id" : % d,
							"syscall_name" : "dup3",
							"retval" : % d,
							"task_context" : {
								"host_pid" : % d,
								"host_tid" : % d,
								"host_ppid" : % d,
								"pid" : % d,
								"tid" : % d,
								"ppid" : % d,
								"cgroup_id" : % llu,
								"mntns_id" : % u,
								"pidns_id" : % u,
								"task_command" : "%s"
							}
						},
						"arguments" : {
							"oldfd" : % d,
							"newfd" : % d,
							"flags" : % d
						},
						"artifacts" : {
							"exe" : "%s",
							"epoc": "%lld" 
						}
					}),
				d->event.ts, ts, d->event.syscall_id, d->retval, d->event.task.host_pid, d->event.task.host_tid,
				d->event.task.host_ppid, d->event.task.pid, d->event.task.tid, d->event.task.ppid, d->event.task.cgroup_id,
				d->event.task.mntns_id, d->event.task.pidns_id, d->event.task.comm, d->oldfd, d->newfd, d->flags, d->event.task.exe_path,epoctime);
		break;
	}
	default:
	{
		break;
	}
	}
	// printf(",\n");
	strcat(log_buffer, ",\n");
	//printf("LOG = : %s\n", log_buffer);
	// printf("LOG = : %s\n", log_buffer);
	send_message(log_buffer);

	return 0;
}

void send_message(char *message)
{
	int totalLen = strlen(message);
	int cursor = 0;
	while (cursor != totalLen)
	{
		int bytes_sent = send(clientSocket, message + cursor, totalLen - cursor, 0);
		if (bytes_sent == -1)
		{
			perror("Error: Could not send data to the server");
			break;
		}
		else
		{
			cursor += bytes_sent;
		}
	}
	fprintf(stderr,"Sent message to the server: %s\n", message);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct xlp_bpf *skel;

	struct arguments arguments = {
		.bit_flags = 0,
		.syscall_flag = 0,
		.container_flag = 0};

	int err;

	// fprintf(stderr, "Trying to send request!\n");
	// send_request();

	/* DNS Resolution Logic */
	/* Setup socket for sending logs */
	
	// const char *serverHostname = "xlp_server"; // Hostname of the server

	// fprintf(stderr, "Creating socket \n");

	// clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	// if (clientSocket == -1)
	// {
	// 	perror("Error: Could not create socket");
	// 	return 1;
	// }
	// struct sockaddr_in serverAddr;
	// serverAddr.sin_family = AF_INET;
	// serverAddr.sin_port = htons(8086);
	// struct hostent *hp;
	// hp = gethostbyname(serverHostname);
	// serverAddr.sin_addr.s_addr = *((unsigned long *)hp->h_addr);

	// fprintf(stderr, "Connecting to server \n");
	// if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
	// {
	// 	perror("Error: Could not connect to the server");
	// 	close(clientSocket);
	// 	return 1;
	// }
	

	// /* Server IP and Port Hard Coded */
	const char *serverIP = "10.5.20.145";
	const int serverPort = 8086;

	fprintf(stderr, "Creating socket \n");

	clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == -1)
	{
		perror("Error: Could not create socket");
		return 1;
	}

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(serverPort);

	// Use inet_pton to convert the IP address from string to binary format
	if (inet_pton(AF_INET, serverIP, &serverAddr.sin_addr) <= 0)
	{
		perror("Error: Invalid IP address");
		close(clientSocket);
		return 1;
	}

	fprintf(stderr, "Connecting to server \n");
	if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
	{
		perror("Error: Could not connect to the server");
		close(clientSocket);
		return 1;
	}


	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, &arguments);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = xlp_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* ensure that BPF program only handles write() syscalls from other processes */
	skel->bss->mypid = getpid();

	if (arguments.syscall_flag == 1)
	{
		skel->data->syscall_flags = arguments.bit_flags;
	}

	if (arguments.container_flag == 1)
	{
		skel->bss->filter_container = 1;
	}

	/* Load & verify BPF programs */
	err = xlp_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = xlp_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, skel, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("{\n\"logs\":[\n");
	while (!exiting)
	{
		time_t current_time;
   	 	time(&current_time);
		char* timeString = ctime(&current_time);
		long long epoctime = (long long)current_time * 1000;
		err = ring_buffer__poll(rb, 500 /* 1out, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		if (err > 0){
			printf("Time : %lld -- Number of events processed   %d\n", epoctime, err);
			printf("Time : %lld -- Size of Record Consumed %d\n", epoctime, sizeof(err));
		}
	}
	printf("]\n}");

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	xlp_bpf__destroy(skel);
	// Close the client socket
	if (clientSocket != -1)
		close(clientSocket);

	return err < 0 ? -err : 0;
}
