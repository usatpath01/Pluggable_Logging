#ifndef __BUFFER_H
#define __BUFFER_H

#include "vmlinux.h"
#include "xlp.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef struct
{
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
    __type(value, buf_t);
    __uint(max_entries, MAX_BUFFERS);
} bufs SEC(".maps");

static __always_inline buf_t *get_buf(int idx)
{
    return (buf_t *)bpf_map_lookup_elem(&bufs, &idx);
}

#endif // __BUFFER_H
