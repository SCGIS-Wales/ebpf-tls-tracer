#ifndef SESSION_H
#define SESSION_H

#include "tracer.h"
#include <time.h>

/* Forward declaration */
struct config;
struct http_info;

#define SESSION_TABLE_SIZE 4096

/* Session close reasons */
#define SESSION_CLOSE_TIMEOUT 0
#define SESSION_CLOSE_NORMAL  1
#define SESSION_CLOSE_ERROR   2

/* Session tracking entry */
struct session_entry {
    struct conn_key_t key;
    __u64  start_ns;
    __u64  last_seen_ns;
    __u64  bytes_sent;
    __u64  bytes_received;
    __u32  event_count;
    __u16  tls_version;
    __u8   is_mtls;
    __u8   addr_family;
    __u16  local_port;
    __u16  remote_port;
    union {
        __u32 v4;
        __u8  v6[16];
    } local_addr;
    union {
        __u32 v4;
        __u8  v6[16];
    } remote_addr;
    char   cipher[64];
    char   protocol[16];
    char   dns_hostname[256];
    char   comm[16];
    int    close_reason;
    __u8   occupied;  /* 0 = empty, 1 = in use */
};

/* Callback for emitting session summaries */
typedef void (*session_emit_fn)(const struct session_entry *entry,
                                const struct config *cfg);

/* Update or create a session from an event */
void session_update(const struct tls_event_t *event,
                    const struct http_info *http,
                    const struct config *cfg);

/* Sweep sessions: emit summaries for idle sessions, remove them */
void session_sweep(time_t now, int timeout_secs,
                   session_emit_fn emit_fn, const struct config *cfg);

/* Emit a session summary as JSON */
void session_emit_json(const struct session_entry *entry,
                       const struct config *cfg);

/* Mark a session for immediate emission (on close/error) */
void session_close(const struct tls_event_t *event, int reason,
                   session_emit_fn emit_fn, const struct config *cfg);

#endif /* SESSION_H */
