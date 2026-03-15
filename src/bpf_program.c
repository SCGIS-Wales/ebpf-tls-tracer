// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <stddef.h>  /* offsetof() for variable-length perf output */
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

/* Persistent map: SSL pointer → TLS version number.
 * Uses LRU hash to auto-evict oldest entries and prevent memory leaks
 * when SSL objects are freed without cleanup notification. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);  /* SSL pointer cast to u64 */
    __type(value, struct cipher_name_t);
} cipher_name_map SEC(".maps");

/* mTLS detection map: SSL pointer → whether client cert is present.
 * Populated by SSL_get_certificate uprobe (non-NULL return = mTLS). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);  /* SSL pointer cast to u64 */
    __type(value, __u8);  /* 1 = mTLS (client cert present), 0 = one-way */
} mtls_map SEC(".maps");

/* Temp map for SSL_get_certificate args */
struct ssl_cert_args_t {
    void *ssl;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_cert_args_t);
} ssl_cert_args_map SEC(".maps");

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
 * Populated by connect/accept kprobes, read by SSL uprobes.
 * Uses LRU hash to auto-evict stale entries from exited processes. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
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
    event->fd = 0;
    event->tls_version = 0;
    event->direction = 0;
    event->event_type = 0;
    event->is_mtls = 0;
    event->error_code = 0;
    event->addr_family = 0;
    event->local_port = 0;
    event->remote_port = 0;
    event->remote_addr_v4 = 0;
    event->local_addr_v4 = 0;
    /* Zero full IPv6 union fields to prevent stale data leaking from
     * a previous IPv6 event into a subsequent IPv4 event (R4 fix). */
    __builtin_memset(event->remote_addr_v6, 0, 16);
    __builtin_memset(event->local_addr_v6, 0, 16);
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
 * Uses __attribute__((preserve_access_index)) for CO-RE (Compile Once,
 * Run Everywhere) support. The BPF loader rewrites field accesses at
 * load time using BTF, so offsets are correct on any kernel version.
 * This fixes S1: hardcoded IPv6 struct offsets. */

struct in6_addr_kernel {
    __u8 in6_u[16];
} __attribute__((preserve_access_index));

struct sock_common {
    union {
        struct {
            __u32 skc_daddr;        /* Foreign IPv4 addr */
            __u32 skc_rcv_saddr;    /* Bound local IPv4 addr */
        };
    };
    union {
        unsigned int skc_hash;
        __u16 skc_u16hashes[2];
    };
    union {
        struct {
            __u16 skc_dport;        /* Destination port */
            __u16 skc_num;          /* Local port (host byte order) */
        };
    };
    short skc_family;               /* Address family */
    struct in6_addr_kernel skc_v6_daddr;    /* IPv6 destination address (CO-RE, S1 fix) */
    struct in6_addr_kernel skc_v6_rcv_saddr; /* IPv6 source address (CO-RE, S1 fix) */
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
        /* Only emit error events for IP sockets (AF_INET/AF_INET6).
         * Skip AF_UNIX, AF_NETLINK, etc. — they produce noise (e.g.
         * ENOENT from DNS resolution via nscd sockets). */
        __u16 sa_family = 0;
        bpf_probe_read_user(&sa_family, sizeof(sa_family),
                            &args->addr->sa_family);
        if (sa_family != AF_INET && sa_family != AF_INET6)
            goto cleanup;

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

            if (sa_family == AF_INET) {
                struct sockaddr_in sin = {};
                bpf_probe_read_user(&sin, sizeof(sin), args->addr);
                event->addr_family = ADDR_FAMILY_IPV4;
                event->remote_addr_v4 = sin.sin_addr.s_addr;
                event->remote_port = bpf_ntohs(sin.sin_port);
            } else {
                struct sockaddr_in6 sin6 = {};
                bpf_probe_read_user(&sin6, sizeof(sin6), args->addr);
                event->addr_family = ADDR_FAMILY_IPV6;
                __builtin_memcpy(event->remote_addr_v6, &sin6.sin6_addr, 16);
                event->remote_port = bpf_ntohs(sin6.sin6_port);
            }

            __u64 out_size = offsetof(struct tls_event_t, data);
            bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, out_size);
        }
        goto cleanup;
    }

    /* Check if tcp_set_state already populated a complete entry with local
     * address.  If so, don't overwrite — the tcp_set_state entry is more
     * complete (has both local + remote).  This fixes the src_ip race. */
    struct conn_info_t *existing = bpf_map_lookup_elem(&conn_info_map, &id);
    if (existing && existing->local_port != 0)
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
    } else if (family == AF_INET6) {
        /* IPv6: read addresses from struct sock using CO-RE (S1 fix).
         * BPF_CORE_READ via preserve_access_index ensures correct offsets
         * across kernel versions — no hardcoded byte offsets needed. */
        __u16 dport = 0, sport = 0;

        bpf_probe_read_kernel(&dport, sizeof(dport),
                              &sk->__sk_common.skc_dport);
        bpf_probe_read_kernel(&sport, sizeof(sport),
                              &sk->__sk_common.skc_num);

        ci.addr_family = ADDR_FAMILY_IPV6;
        ci.remote_port = bpf_ntohs(dport);
        ci.local_port = sport;

        /* CO-RE: read IPv6 addresses via BTF-relocated field access (S1 fix) */
        bpf_probe_read_kernel(ci.remote_addr_v6, 16,
                              &sk->__sk_common.skc_v6_daddr);
        bpf_probe_read_kernel(ci.local_addr_v6, 16,
                              &sk->__sk_common.skc_v6_rcv_saddr);
    } else {
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

    /* Handle IPv4 and IPv6 (R9 fix: previously only IPv4 was handled) */
    short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
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

    event->remote_port = dport;

    if (family == AF_INET) {
        __u32 daddr = 0, saddr = 0;
        __u16 sport = 0;
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        event->addr_family = ADDR_FAMILY_IPV4;
        event->remote_addr_v4 = daddr;
        event->local_addr_v4 = saddr;
        event->local_port = sport;
    } else {
        __u16 sport = 0;
        bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        event->addr_family = ADDR_FAMILY_IPV6;
        event->local_port = sport;
        /* CO-RE: read IPv6 addresses via BTF-relocated field access (S1 fix) */
        bpf_probe_read_kernel(event->remote_addr_v6, 16,
                              &sk->__sk_common.skc_v6_daddr);
        bpf_probe_read_kernel(event->local_addr_v6, 16,
                              &sk->__sk_common.skc_v6_rcv_saddr);
    }

    {
        __u64 out_size = offsetof(struct tls_event_t, data);
        bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, out_size);
    }
    return 0;
}

/* --- Helper: extract socket fd from SSL struct (S2 documented) ---
 *
 * WARNING: These offsets are OpenSSL internal ABI, NOT public API.
 * They are derived from specific OpenSSL builds and may change with
 * distro patches or minor version updates.
 *
 * SSL->rbio: offset 16 on 64-bit for both OpenSSL 1.1.x and 3.x
 *   Verified: OpenSSL 3.0.x (AL2023), 3.1.x, 3.2.x, 1.1.1 (Ubuntu 20.04)
 *   Source: SSL struct layout — rbio is the 3rd pointer field after method+session
 *
 * BIO->num (socket fd):
 *   OpenSSL 3.x: offset 40 (method_ptr(8) + callback(8) + cb_arg(8) + init(4) + shutdown(4) + num(4))
 *   OpenSSL 1.1.x: offset 32 (different struct packing)
 *   Verified: AL2023 OpenSSL 3.0.8, Ubuntu 22.04 OpenSSL 3.0.2
 *
 * If these offsets break on a new OpenSSL version, fd extraction fails
 * silently (returns -1), and connection correlation degrades gracefully
 * (conn_id and dst_dns caching stop working, but data capture continues).
 *
 * This technique is used by Pixie/New Relic and eCapture:
 * https://blog.px.dev/ebpf-tls-tracing-past-present-future/
 *
 * TODO: Consider using BTF-based OpenSSL struct introspection or
 *       offset auto-detection at startup for future-proofing. */

static __always_inline int get_ssl_fd(void *ssl)
{
    if (!ssl)
        return -1;

    void *rbio = NULL;
    if (bpf_probe_read_user(&rbio, sizeof(rbio), (void *)ssl + 16) != 0 || !rbio)
        return -1;

    /* Try OpenSSL 3.x offset first (more common on modern distros) */
    int fd = -1;
    bpf_probe_read_user(&fd, sizeof(fd), (void *)rbio + 40);
    if (fd >= 0 && fd < 1048576)  /* sanity: fd should be < 1M */
        return fd;

    /* Fallback: try OpenSSL 1.1.x offset */
    fd = -1;
    bpf_probe_read_user(&fd, sizeof(fd), (void *)rbio + 32);
    if (fd >= 0 && fd < 1048576)
        return fd;

    return -1;
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

    /* Read the cipher name pointer from SSL_CIPHER struct (S3 documented).
     *
     * WARNING: SSL_CIPHER is an internal OpenSSL struct, NOT public ABI.
     * Layout on OpenSSL 3.x (64-bit):
     *   offset 0: uint32_t valid       (4 bytes)
     *   offset 4: padding              (4 bytes, alignment)
     *   offset 8: const char *name     (8 bytes pointer)
     * Verified: AL2023 OpenSSL 3.0.8, Ubuntu 22.04 OpenSSL 3.0.2
     *
     * On OpenSSL 1.1.x (64-bit), the layout is the same (valid + name).
     * If this offset breaks, cipher name reads garbage and the cipher
     * field shows junk — data capture itself is unaffected.
     *
     * TODO: Consider using SSL_CIPHER_get_name() via a separate uprobe
     *       for a public-API-only approach. */
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

/* --- SSL_get_certificate probes: detect mTLS (client certificate presence) ---
 * X509 *SSL_get_certificate(const SSL *ssl) returns the local certificate.
 * If non-NULL on a client connection, the client is presenting a cert → mTLS. */

SEC("uprobe/SSL_get_certificate")
int probe_ssl_get_cert_enter(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_cert_args_t args = {};
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&ssl_cert_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_get_certificate")
int probe_ssl_get_cert_return(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct ssl_cert_args_t *args;

    args = bpf_map_lookup_elem(&ssl_cert_args_map, &id);
    if (!args)
        return 0;

    void *cert = (void *)PT_REGS_RC(ctx);
    __u64 ssl_key = (__u64)(unsigned long)args->ssl;
    __u8 is_mtls = cert ? 1 : 0;
    bpf_map_update_elem(&mtls_map, &ssl_key, &is_mtls, BPF_ANY);

    bpf_map_delete_elem(&ssl_cert_args_map, &id);
    return 0;
}

/* --- Helper: check if connection is mTLS --- */

static __always_inline __u8 get_mtls_status(void *ssl)
{
    __u64 key = (__u64)(unsigned long)ssl;
    __u8 *val = bpf_map_lookup_elem(&mtls_map, &key);
    if (val)
        return *val;
    return 0;  /* Default: unknown/one-way */
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

    /* Extract socket fd from SSL struct for connection correlation */
    int ssl_fd = get_ssl_fd(args->ssl);

    if (ret <= 0) {
        /* SSL_read returns: 0 = peer closed connection, <0 = error.
         * Emit EVENT_TLS_CLOSE for ret==0, EVENT_TLS_ERROR for ret<0 (#3 fix). */
        struct tls_event_t *err_event = get_event_buf();
        if (err_event) {
            err_event->timestamp_ns = bpf_ktime_get_ns();
            err_event->pid = id >> 32;
            err_event->tid = (__u32)id;
            err_event->uid = bpf_get_current_uid_gid();
            err_event->fd = ssl_fd >= 0 ? (__u32)ssl_fd : 0;
            err_event->direction = DIRECTION_READ;
            err_event->event_type = (ret == 0) ? EVENT_TLS_CLOSE : EVENT_TLS_ERROR;
            err_event->error_code = (__s16)ret;
            err_event->tls_version = get_tls_version(args->ssl);
            err_event->data_len = 0;
            bpf_get_current_comm(&err_event->comm, sizeof(err_event->comm));
            enrich_event_with_conn_info(err_event, id);
            enrich_event_with_cipher(err_event, args->ssl);
            err_event->is_mtls = get_mtls_status(args->ssl);
            __u64 out_size = offsetof(struct tls_event_t, data);
            bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, err_event, out_size);
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
    event->fd = ssl_fd >= 0 ? (__u32)ssl_fd : 0;
    event->direction = DIRECTION_READ;
    event->event_type = EVENT_TLS_DATA;
    event->tls_version = get_tls_version(args->ssl);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    enrich_event_with_conn_info(event, id);
    enrich_event_with_cipher(event, args->ssl);
    event->is_mtls = get_mtls_status(args->ssl);

    __u32 read_len = ret;
    if (read_len > MAX_DATA_LEN)
        read_len = MAX_DATA_LEN;
    event->data_len = read_len;

    if (bpf_probe_read_user(event->data, read_len & (MAX_DATA_LEN - 1), args->buf) == 0) {
        __u64 out_size = offsetof(struct tls_event_t, data) + read_len;
        bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, out_size);
    }

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

    /* Extract socket fd from SSL struct for connection correlation */
    int ssl_fd = get_ssl_fd(args->ssl);

    if (ret <= 0) {
        /* SSL_write returns: 0 = connection closed, <0 = error (#3 fix) */
        struct tls_event_t *err_event = get_event_buf();
        if (err_event) {
            err_event->timestamp_ns = bpf_ktime_get_ns();
            err_event->pid = id >> 32;
            err_event->tid = (__u32)id;
            err_event->uid = bpf_get_current_uid_gid();
            err_event->fd = ssl_fd >= 0 ? (__u32)ssl_fd : 0;
            err_event->direction = DIRECTION_WRITE;
            err_event->event_type = (ret == 0) ? EVENT_TLS_CLOSE : EVENT_TLS_ERROR;
            err_event->error_code = (__s16)ret;
            err_event->tls_version = get_tls_version(args->ssl);
            err_event->data_len = 0;
            bpf_get_current_comm(&err_event->comm, sizeof(err_event->comm));
            enrich_event_with_conn_info(err_event, id);
            enrich_event_with_cipher(err_event, args->ssl);
            err_event->is_mtls = get_mtls_status(args->ssl);
            __u64 out_size = offsetof(struct tls_event_t, data);
            bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, err_event, out_size);
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
    event->fd = ssl_fd >= 0 ? (__u32)ssl_fd : 0;
    event->direction = DIRECTION_WRITE;
    event->event_type = EVENT_TLS_DATA;
    event->tls_version = get_tls_version(args->ssl);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    enrich_event_with_conn_info(event, id);
    enrich_event_with_cipher(event, args->ssl);
    event->is_mtls = get_mtls_status(args->ssl);

    __u32 write_len = ret;
    if (write_len > MAX_DATA_LEN)
        write_len = MAX_DATA_LEN;
    event->data_len = write_len;

    if (bpf_probe_read_user(event->data, write_len & (MAX_DATA_LEN - 1), args->buf) == 0) {
        __u64 out_size = offsetof(struct tls_event_t, data) + write_len;
        bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, out_size);
    }

cleanup:
    bpf_map_delete_elem(&ssl_args_map, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
