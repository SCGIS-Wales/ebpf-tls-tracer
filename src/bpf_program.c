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

/* Map to store TLS version per SSL pointer (populated by SSL_version uprobe).
 * Key: SSL* pointer address, Value: TLS version (0x0303=TLS1.2, 0x0304=TLS1.3) */
struct ssl_version_args_t {
    void *ssl;  /* SSL * (first arg to SSL_version) */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_args_t);
} ssl_args_map SEC(".maps");

/* Temporary map for SSL_version args between entry and return */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_version_args_t);
} ssl_version_args_map SEC(".maps");

/* Persistent map: SSL pointer → TLS version number */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);  /* SSL pointer cast to u64 */
    __type(value, __u16);
} ssl_version_map SEC(".maps");

/* Cipher name storage: SSL pointer → cipher name string.
 * Populated by SSL_get_current_cipher uprobe (reads SSL_CIPHER->name). */
struct cipher_name_t {
    char name[64];  /* MAX_CIPHER_LEN */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);  /* SSL pointer cast to u64 */
    __type(value, struct cipher_name_t);
} cipher_name_map SEC(".maps");

/* Temp map for SSL_get_current_cipher args (SSL * → pid_tgid correlation) */
struct ssl_cipher_args_t {
    void *ssl;  /* SSL * (first arg to SSL_get_current_cipher) */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_cipher_args_t);
} ssl_cipher_args_map SEC(".maps");

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
    event->error_code = 0;
    event->addr_family = 0;
    event->local_port = 0;
    event->remote_port = 0;
    event->remote_addr_v4 = 0;
    event->local_addr_v4 = 0;
    event->cipher[0] = '\0';
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
    if (ret != 0 && ret != -115) {  /* -EINPROGRESS = -115 */
        /* Emit a TCP connection error event */
        struct tls_event_t *event = get_event_buf();
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns();
            event->pid = id >> 32;
            event->tid = (__u32)id;
            event->uid = bpf_get_current_uid_gid();
            event->direction = DIRECTION_WRITE;
            event->event_type = EVENT_CONNECT_ERROR;
            event->error_code = (__s16)(-ret);  /* Store positive errno */
            event->data_len = 0;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));

            /* Try to get destination address from connect args */
            __u16 sa_family = 0;
            bpf_probe_read_user(&sa_family, sizeof(sa_family),
                                &args->addr->sa_family);
            if (sa_family == AF_INET) {
                struct sockaddr_in sin = {};
                bpf_probe_read_user(&sin, sizeof(sin), args->addr);
                event->addr_family = ADDR_FAMILY_IPV4;
                event->remote_addr_v4 = sin.sin_addr.s_addr;
                event->remote_port = bpf_ntohs(sin.sin_port);
            } else if (sa_family == AF_INET6) {
                struct sockaddr_in6 sin6 = {};
                bpf_probe_read_user(&sin6, sizeof(sin6), args->addr);
                event->addr_family = ADDR_FAMILY_IPV6;
                __builtin_memcpy(event->remote_addr_v6, &sin6.sin6_addr, 16);
                event->remote_port = bpf_ntohs(sin6.sin6_port);
            }

            bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU,
                                  event, sizeof(*event));
        }
        goto cleanup;
    }

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

/* --- tcp_set_state kprobe: capture BOTH local and remote addresses when TCP ESTABLISHED ---
 *
 * tcp_set_state(struct sock *sk, int state) is called when a TCP socket
 * transitions state. When state == TCP_ESTABLISHED, struct sock has all
 * addressing info populated. This fires DURING connect() — before the
 * connect kretprobe — so we create/populate conn_info_t directly from
 * struct sock rather than relying on a prior connect_return entry. */

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

    /* Read address family */
    short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family),
                          &sk->__sk_common.skc_family);

    struct conn_info_t ci = {};

    if (family == AF_INET) {
        __u32 daddr = 0, saddr = 0;
        __u16 dport = 0, sport = 0;

        bpf_probe_read_kernel(&daddr, sizeof(daddr),
                              &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&saddr, sizeof(saddr),
                              &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&dport, sizeof(dport),
                              &sk->__sk_common.skc_dport);
        bpf_probe_read_kernel(&sport, sizeof(sport),
                              &sk->__sk_common.skc_num);

        ci.addr_family = ADDR_FAMILY_IPV4;
        ci.remote_addr_v4 = daddr;
        ci.local_addr_v4 = saddr;
        ci.remote_port = bpf_ntohs(dport);
        ci.local_port = sport;  /* skc_num is already host byte order */
    } else {
        /* IPv6: skip for now (sk_v6_rcv_saddr offset varies) */
        return 0;
    }

    bpf_map_update_elem(&conn_info_map, &id, &ci, BPF_ANY);
    return 0;
}

/* --- QUIC detection: detect UDP traffic to port 443 with QUIC Initial header ---
 * QUIC Initial packets have:
 *   Byte 0: Header Form (bit 7) = 1 (Long Header), Fixed Bit (bit 6) = 1,
 *           Packet Type (bits 5-4) = 00 (Initial) → byte & 0xF0 == 0xC0
 *   Bytes 1-4: QUIC Version (big-endian)
 * We probe udp_sendmsg to detect outbound QUIC. */

SEC("kprobe/udp_sendmsg")
int probe_udp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    /* Check destination port - QUIC uses 443 or 8443 */
    __u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = bpf_ntohs(dport);
    if (dport != 443 && dport != 8443)
        return 0;

    /* Read address family - only handle IPv4 for now */
    short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    /* Emit a QUIC detection event */
    struct tls_event_t *event = get_event_buf();
    if (!event)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    event->uid = bpf_get_current_uid_gid();
    event->direction = DIRECTION_WRITE;
    event->event_type = EVENT_QUIC_DETECTED;
    event->data_len = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    __u32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    event->addr_family = ADDR_FAMILY_IPV4;
    event->remote_addr_v4 = daddr;
    event->remote_port = dport;

    __u32 saddr = 0;
    __u16 sport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    event->local_addr_v4 = saddr;
    event->local_port = sport;

    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

/* --- Helper: look up TLS version for an SSL pointer --- */

static __always_inline __u16 get_tls_version(void *ssl)
{
    __u64 key = (__u64)(unsigned long)ssl;
    __u16 *ver = bpf_map_lookup_elem(&ssl_version_map, &key);
    if (ver)
        return *ver;
    return 0;
}

/* --- Helper: look up cipher name for an SSL pointer --- */

static __always_inline void enrich_event_with_cipher(struct tls_event_t *event, void *ssl)
{
    __u64 key = (__u64)(unsigned long)ssl;
    struct cipher_name_t *cn = bpf_map_lookup_elem(&cipher_name_map, &key);
    if (cn)
        __builtin_memcpy(event->cipher, cn->name, 64);
}

/* --- SSL_get_current_cipher probes: capture negotiated cipher suite ---
 * const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl)
 * Returns a pointer to the SSL_CIPHER struct. We read the cipher name
 * from SSL_CIPHER->name (offset 8 on 64-bit, after uint32_t valid + padding). */

SEC("uprobe/SSL_get_current_cipher")
int probe_ssl_get_cipher_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_cipher_args_t args = {};
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&ssl_cipher_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_get_current_cipher")
int probe_ssl_get_cipher_return(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_cipher_args_t *args;

    args = bpf_map_lookup_elem(&ssl_cipher_args_map, &id);
    if (!args)
        return 0;

    void *ssl_cipher = (void *)PT_REGS_RC(ctx);
    if (!ssl_cipher)
        goto cleanup_cipher;

    /* Read the cipher name pointer from SSL_CIPHER struct.
     * In OpenSSL 3.x, SSL_CIPHER layout:
     *   offset 0: uint32_t valid (4 bytes)
     *   offset 4: 4 bytes padding (on 64-bit)
     *   offset 8: const char *name (8 bytes pointer)
     */
    const char *name_ptr = NULL;
    if (bpf_probe_read_user(&name_ptr, sizeof(name_ptr),
                            (void *)ssl_cipher + 8) != 0 || !name_ptr)
        goto cleanup_cipher;

    struct cipher_name_t cn = {};
    if (bpf_probe_read_user(cn.name, sizeof(cn.name) - 1, name_ptr) == 0) {
        cn.name[63] = '\0';
        __u64 ssl_key = (__u64)(unsigned long)args->ssl;
        bpf_map_update_elem(&cipher_name_map, &ssl_key, &cn, BPF_ANY);
    }

cleanup_cipher:
    bpf_map_delete_elem(&ssl_cipher_args_map, &id);
    return 0;
}

/* --- SSL_version probes: capture TLS version per SSL connection ---
 * int SSL_version(const SSL *s) returns TLS1_2_VERSION(0x0303) or
 * TLS1_3_VERSION(0x0304). Called by applications or internally. */

SEC("uprobe/SSL_version")
int probe_ssl_version_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_version_args_t args = {};
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&ssl_version_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_version")
int probe_ssl_version_return(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_version_args_t *args;

    args = bpf_map_lookup_elem(&ssl_version_args_map, &id);
    if (!args)
        return 0;

    int version = (int)PT_REGS_RC(ctx);
    if (version > 0) {
        __u64 key = (__u64)(unsigned long)args->ssl;
        __u16 ver = (__u16)version;
        bpf_map_update_elem(&ssl_version_map, &key, &ver, BPF_ANY);
    }

    bpf_map_delete_elem(&ssl_version_args_map, &id);
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
    if (ret <= 0) {
        /* SSL_read error: ret 0 = connection closed, ret < 0 = error.
         * Emit a TLS error event so userspace can log the failure. */
        if (ret < 0) {
            struct tls_event_t *err_event = get_event_buf();
            if (err_event) {
                err_event->timestamp_ns = bpf_ktime_get_ns();
                err_event->pid = id >> 32;
                err_event->tid = (__u32)id;
                err_event->uid = bpf_get_current_uid_gid();
                err_event->direction = DIRECTION_READ;
                err_event->event_type = EVENT_TLS_ERROR;
                err_event->error_code = (__s16)ret;
                err_event->tls_version = get_tls_version(args->ssl);
                err_event->data_len = 0;
                bpf_get_current_comm(&err_event->comm, sizeof(err_event->comm));
                enrich_event_with_conn_info(err_event, id);
                bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU,
                                      err_event, sizeof(*err_event));
            }
        }
        goto cleanup;
    }

    struct tls_event_t *event = get_event_buf();
    if (!event)
        goto cleanup;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    event->uid = bpf_get_current_uid_gid();
    event->direction = DIRECTION_READ;
    event->event_type = EVENT_TLS_DATA;
    event->tls_version = get_tls_version(args->ssl);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    enrich_event_with_conn_info(event, id);
    enrich_event_with_cipher(event, args->ssl);

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
    if (ret <= 0) {
        /* SSL_write error: emit TLS error event */
        if (ret < 0) {
            struct tls_event_t *err_event = get_event_buf();
            if (err_event) {
                err_event->timestamp_ns = bpf_ktime_get_ns();
                err_event->pid = id >> 32;
                err_event->tid = (__u32)id;
                err_event->uid = bpf_get_current_uid_gid();
                err_event->direction = DIRECTION_WRITE;
                err_event->event_type = EVENT_TLS_ERROR;
                err_event->error_code = (__s16)ret;
                err_event->tls_version = get_tls_version(args->ssl);
                err_event->data_len = 0;
                bpf_get_current_comm(&err_event->comm, sizeof(err_event->comm));
                enrich_event_with_conn_info(err_event, id);
                bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU,
                                      err_event, sizeof(*err_event));
            }
        }
        goto cleanup;
    }

    struct tls_event_t *event = get_event_buf();
    if (!event)
        goto cleanup;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    event->uid = bpf_get_current_uid_gid();
    event->direction = DIRECTION_WRITE;
    event->event_type = EVENT_TLS_DATA;
    event->tls_version = get_tls_version(args->ssl);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    enrich_event_with_conn_info(event, id);
    enrich_event_with_cipher(event, args->ssl);

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
