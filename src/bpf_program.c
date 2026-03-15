// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tracer.h"

/* Minimal socket struct definitions for BPF compilation.
 * BPF programs cannot include full kernel/glibc socket headers,
 * so we define only what we need inline. */
#define AF_INET     2
#define AF_INET6    10

struct sockaddr {
    unsigned short sa_family;
    char           sa_data[14];
};

struct in_addr {
    __u32 s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;
    __u16          sin_port;
    struct in_addr sin_addr;
    char           sin_zero[8];
};

struct in6_addr {
    __u8 s6_addr[16];
};

struct sockaddr_in6 {
    unsigned short sin6_family;
    __u16          sin6_port;
    __u32          sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32          sin6_scope_id;
};

/* Per-thread map to stash SSL_read/SSL_write arguments between entry and return */
struct ssl_args_t {
    void *ssl;   /* SSL * (first arg) */
    void *buf;
    int   num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_args_t);
} ssl_args_map SEC(".maps");

/* Connection info map: keyed by pid_tgid, stores remote addr/port.
 * Populated by connect/accept kprobes, read by SSL uprobes. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct conn_info_t);
} conn_info_map SEC(".maps");

/* Temporary map for connect() args between entry and return */
struct connect_args_t {
    struct sockaddr *addr;
    int addrlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct connect_args_t);
} connect_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tls_events SEC(".maps");

/* Per-CPU scratch buffer for tls_event_t (too large for 512-byte BPF stack).
 * Each CPU gets its own copy, so no locking needed. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tls_event_t);
} event_buf SEC(".maps");

/* --- Helper: get zeroed event buffer from per-CPU map --- */

static __always_inline struct tls_event_t *get_event_buf(void)
{
    __u32 zero = 0;
    struct tls_event_t *event = bpf_map_lookup_elem(&event_buf, &zero);
    if (!event)
        return 0;

    /* Zero the metadata fields (not the data buffer — it gets overwritten) */
    event->timestamp_ns = 0;
    event->pid = 0;
    event->tid = 0;
    event->uid = 0;
    event->data_len = 0;
    event->tls_version = 0;
    event->direction = 0;
    event->event_type = 0;
    event->addr_family = 0;
    event->local_port = 0;
    event->remote_port = 0;
    event->remote_addr_v4 = 0;
    event->local_addr_v4 = 0;
    return event;
}

/* --- Helper: populate event with connection info if available --- */

static __always_inline void enrich_event_with_conn_info(struct tls_event_t *event, __u64 pid_tgid)
{
    struct conn_info_t *ci = bpf_map_lookup_elem(&conn_info_map, &pid_tgid);
    if (!ci)
        return;

    event->addr_family = ci->addr_family;
    event->local_port = ci->local_port;
    event->remote_port = ci->remote_port;

    if (ci->addr_family == ADDR_FAMILY_IPV4) {
        event->remote_addr_v4 = ci->remote_addr_v4;
        event->local_addr_v4 = ci->local_addr_v4;
    } else if (ci->addr_family == ADDR_FAMILY_IPV6) {
        __builtin_memcpy(event->remote_addr_v6, ci->remote_addr_v6, 16);
        __builtin_memcpy(event->local_addr_v6, ci->local_addr_v6, 16);
    }
}

/* --- Minimal kernel struct definitions for reading sock addresses ---
 * These offsets are stable across kernel 5.x-6.x (part of the
 * stable __sk_common layout at the start of struct sock). */

struct sock_common {
    union {
        struct {
            __u32 skc_daddr;        /* Foreign IPv4 addr (offset 0) */
            __u32 skc_rcv_saddr;    /* Bound local IPv4 addr (offset 4) */
        };
    };
    union {
        unsigned int skc_hash;
        __u16 skc_u16hashes[2];
    };
    union {
        struct {
            __u16 skc_dport;        /* Destination port (offset 12) */
            __u16 skc_num;          /* Local port (offset 14, host byte order) */
        };
    };
    short skc_family;               /* Address family (offset 16) */
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

/* TCP states from include/net/tcp_states.h */
#define TCP_ESTABLISHED  1

/* --- connect() kprobes: capture outbound remote addresses --- */

SEC("kprobe/__sys_connect")
int probe_connect_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t args = {};

    args.addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    args.addrlen = (int)PT_REGS_PARM3(ctx);

    bpf_map_update_elem(&connect_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/__sys_connect")
int probe_connect_return(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *args;
    int ret;

    args = bpf_map_lookup_elem(&connect_args_map, &id);
    if (!args)
        return 0;

    ret = (int)PT_REGS_RC(ctx);
    /* connect returns 0 on success, or -EINPROGRESS for non-blocking */
    if (ret != 0 && ret != -115)  /* -EINPROGRESS = -115 */
        goto cleanup;

    struct conn_info_t ci = {};
    __u16 sa_family = 0;
    bpf_probe_read_user(&sa_family, sizeof(sa_family), &args->addr->sa_family);

    if (sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), args->addr);
        ci.addr_family = ADDR_FAMILY_IPV4;
        ci.remote_addr_v4 = sin.sin_addr.s_addr;
        ci.remote_port = bpf_ntohs(sin.sin_port);
    } else if (sa_family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), args->addr);
        ci.addr_family = ADDR_FAMILY_IPV6;
        __builtin_memcpy(ci.remote_addr_v6, &sin6.sin6_addr, 16);
        ci.remote_port = bpf_ntohs(sin6.sin6_port);
    } else {
        goto cleanup;
    }

    bpf_map_update_elem(&conn_info_map, &id, &ci, BPF_ANY);

cleanup:
    bpf_map_delete_elem(&connect_args_map, &id);
    return 0;
}

/* --- tcp_set_state kprobe: capture local (source) address when TCP ESTABLISHED ---
 *
 * tcp_set_state(struct sock *sk, int state) is called when a TCP socket
 * transitions state. When state == TCP_ESTABLISHED, both local and remote
 * addresses are populated in struct sock, giving us the source IP:port. */

SEC("kprobe/tcp_set_state")
int probe_tcp_set_state(struct pt_regs *ctx)
{
    int new_state = (int)PT_REGS_PARM2(ctx);
    if (new_state != TCP_ESTABLISHED)
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();

    /* Look up existing conn_info (populated by connect kretprobe) */
    struct conn_info_t *ci = bpf_map_lookup_elem(&conn_info_map, &id);
    if (!ci)
        return 0;

    /* Read local address from struct sock */
    short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family),
                          &sk->__sk_common.skc_family);

    if (family == AF_INET) {
        __u32 saddr = 0;
        __u16 sport = 0;
        bpf_probe_read_kernel(&saddr, sizeof(saddr),
                              &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&sport, sizeof(sport),
                              &sk->__sk_common.skc_num);
        ci->local_addr_v4 = saddr;
        ci->local_port = sport;  /* skc_num is already host byte order */
    }
    /* Note: IPv6 local address requires reading sk->sk_v6_rcv_saddr
     * which is at a variable offset — we skip it for now */

    bpf_map_update_elem(&conn_info_map, &id, ci, BPF_ANY);
    return 0;
}

/* --- SSL_read probes --- */

SEC("uprobe/SSL_read")
int probe_ssl_read_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_args_t args = {};

    args.ssl = (void *)PT_REGS_PARM1(ctx);
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

    struct tls_event_t *event = get_event_buf();
    if (!event)
        goto cleanup;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    event->uid = bpf_get_current_uid_gid();
    event->direction = DIRECTION_READ;
    event->event_type = EVENT_TLS_DATA;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    enrich_event_with_conn_info(event, id);

    __u32 read_len = ret;
    if (read_len > MAX_DATA_LEN)
        read_len = MAX_DATA_LEN;
    event->data_len = read_len;

    if (bpf_probe_read_user(event->data, read_len & (MAX_DATA_LEN - 1), args->buf) == 0)
        bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, sizeof(*event));

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

    args.ssl = (void *)PT_REGS_PARM1(ctx);
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

    struct tls_event_t *event = get_event_buf();
    if (!event)
        goto cleanup;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    event->uid = bpf_get_current_uid_gid();
    event->direction = DIRECTION_WRITE;
    event->event_type = EVENT_TLS_DATA;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    enrich_event_with_conn_info(event, id);

    __u32 write_len = ret;
    if (write_len > MAX_DATA_LEN)
        write_len = MAX_DATA_LEN;
    event->data_len = write_len;

    if (bpf_probe_read_user(event->data, write_len & (MAX_DATA_LEN - 1), args->buf) == 0)
        bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, sizeof(*event));

cleanup:
    bpf_map_delete_elem(&ssl_args_map, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
