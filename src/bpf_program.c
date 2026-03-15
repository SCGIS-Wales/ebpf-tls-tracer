// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tracer.h"

/* Per-CPU map to stash SSL_read/SSL_write arguments between entry and return */
struct ssl_args_t {
    void *buf;
    int   num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_args_t);
} ssl_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tls_events SEC(".maps");

/* --- SSL_read probes --- */

SEC("uprobe/SSL_read")
int probe_ssl_read_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args_t args = {};

    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);

    bpf_map_update_elem(&ssl_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ssl_read_return(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args_t *args;
    int ret;

    args = bpf_map_lookup_elem(&ssl_args_map, &id);
    if (!args)
        return 0;

    ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    struct tls_event_t event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.tid = (__u32)id;
    event.uid = bpf_get_current_uid_gid();
    event.direction = DIRECTION_READ;
    event.event_type = EVENT_TLS_DATA;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    __u32 read_len = ret;
    if (read_len > MAX_DATA_LEN)
        read_len = MAX_DATA_LEN;
    event.data_len = read_len;

    if (bpf_probe_read_user(event.data, read_len & (MAX_DATA_LEN - 1), args->buf) == 0)
        bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

cleanup:
    bpf_map_delete_elem(&ssl_args_map, &id);
    return 0;
}

/* --- SSL_write probes --- */

SEC("uprobe/SSL_write")
int probe_ssl_write_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args_t args = {};

    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);

    bpf_map_update_elem(&ssl_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int probe_ssl_write_return(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args_t *args;
    int ret;

    args = bpf_map_lookup_elem(&ssl_args_map, &id);
    if (!args)
        return 0;

    ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    struct tls_event_t event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.tid = (__u32)id;
    event.uid = bpf_get_current_uid_gid();
    event.direction = DIRECTION_WRITE;
    event.event_type = EVENT_TLS_DATA;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    __u32 write_len = ret;
    if (write_len > MAX_DATA_LEN)
        write_len = MAX_DATA_LEN;
    event.data_len = write_len;

    if (bpf_probe_read_user(event.data, write_len & (MAX_DATA_LEN - 1), args->buf) == 0)
        bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

cleanup:
    bpf_map_delete_elem(&ssl_args_map, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
