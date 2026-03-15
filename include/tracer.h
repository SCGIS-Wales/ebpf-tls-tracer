#ifndef TRACER_H
#define TRACER_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
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
#define EVENT_TLS_DATA  1
#define EVENT_TLS_HANDSHAKE 2

struct tls_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 data_len;
    __u16 tls_version;
    __u8  direction;    /* DIRECTION_READ or DIRECTION_WRITE */
    __u8  event_type;
    char  comm[MAX_COMM_LEN];
    char  data[MAX_DATA_LEN];
};

#endif /* TRACER_H */
