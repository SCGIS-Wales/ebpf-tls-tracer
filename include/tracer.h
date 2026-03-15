#ifndef TRACER_H
#define TRACER_H

/* BPF programs and libbpf user-space both use linux/types.h.
 * Only fall back to stdint.h typedefs if linux/types.h is unavailable. */
#if defined(__KERNEL__) || defined(__bpf__) || defined(__linux__)
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t  __u8;
typedef int16_t  __s16;
typedef int32_t  __s32;
#endif

#define MAX_URL_LEN     256
#define MAX_METHOD_LEN  16
#define MAX_COMM_LEN    16
#define MAX_CIPHER_LEN  64
#define MAX_IP_LEN      46  /* INET6_ADDRSTRLEN */
#define MAX_DATA_LEN    4096

/* Direction of TLS operation */
#define DIRECTION_READ  0
#define DIRECTION_WRITE 1

/* Event types */
#define EVENT_TLS_DATA      1
#define EVENT_TLS_HANDSHAKE 2
#define EVENT_CONNECT       3
#define EVENT_CONNECT_ERROR 4
#define EVENT_TLS_ERROR     5
#define EVENT_QUIC_DETECTED 6

/* Address family constants (match AF_INET/AF_INET6) */
#define ADDR_FAMILY_IPV4    2
#define ADDR_FAMILY_IPV6    10

/* Connection info stored per pid+fd for IP correlation */
struct conn_info_t {
    __u8  addr_family;       /* ADDR_FAMILY_IPV4 or ADDR_FAMILY_IPV6 */
    __u8  _pad[3];
    __u16 local_port;
    __u16 remote_port;
    union {
        __u32 remote_addr_v4;
        __u8  remote_addr_v6[16];
    };
    union {
        __u32 local_addr_v4;
        __u8  local_addr_v6[16];
    };
};

/* Key for connection map: identifies a socket per thread */
struct conn_key_t {
    __u32 pid;
    __u32 fd;
};

struct tls_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 data_len;
    __u16 tls_version;
    __u8  direction;         /* DIRECTION_READ or DIRECTION_WRITE */
    __u8  event_type;
    __u8  addr_family;       /* ADDR_FAMILY_IPV4 or ADDR_FAMILY_IPV6 */
    __u8  is_mtls;           /* 1 = mutual TLS (client cert present), 0 = one-way */
    __s16 error_code;        /* errno for connect errors, SSL ret for TLS errors */
    __u16 local_port;
    __u16 remote_port;
    union {
        __u32 remote_addr_v4;
        __u8  remote_addr_v6[16];
    };
    union {
        __u32 local_addr_v4;
        __u8  local_addr_v6[16];
    };
    char  comm[MAX_COMM_LEN];
    char  cipher[MAX_CIPHER_LEN]; /* TLS cipher suite name (e.g. "TLS_AES_256_GCM_SHA384") */
    char  data[MAX_DATA_LEN];
};

#endif /* TRACER_H */
