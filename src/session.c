// SPDX-License-Identifier: MIT
//
// Session aggregation: tracks per-connection statistics and emits
// summary events on connection close or idle timeout.

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "session.h"
#include "config.h"
#include "output.h"
#include "protocol.h"

static struct session_entry session_table[SESSION_TABLE_SIZE];

static inline __u32 session_hash(__u32 pid, __u32 fd)
{
    return mix_hash_pid_fd(pid, fd, SESSION_TABLE_SIZE - 1);
}

static struct session_entry *session_find_or_create(__u32 pid, __u32 fd)
{
    __u32 idx = session_hash(pid, fd);
    __u32 first_empty = UINT32_MAX;

    for (__u32 i = 0; i < SESSION_TABLE_SIZE; i++) {
        __u32 slot = (idx + i) & (SESSION_TABLE_SIZE - 1);
        if (!session_table[slot].occupied) {
            if (first_empty == UINT32_MAX)
                first_empty = slot;
            /* If table has gaps, stop probing */
            if (i > 64)
                break;
            continue;
        }
        if (session_table[slot].key.pid == pid &&
            session_table[slot].key.fd == fd) {
            return &session_table[slot];
        }
    }

    /* Create new entry */
    __u32 slot = (first_empty != UINT32_MAX) ? first_empty : idx;
    memset(&session_table[slot], 0, sizeof(session_table[slot]));
    session_table[slot].key.pid = pid;
    session_table[slot].key.fd = fd;
    session_table[slot].occupied = 1;
    return &session_table[slot];
}

void session_update(const struct tls_event_t *event,
                    const struct http_info *http,
                    const struct config *cfg)
{
    (void)cfg;

    if (event->event_type != EVENT_TLS_DATA)
        return;

    struct session_entry *s = session_find_or_create(event->pid, event->fd);
    if (!s)
        return;

    /* First event: populate metadata */
    if (s->start_ns == 0) {
        s->start_ns = event->timestamp_ns;
        s->tls_version = event->tls_version;
        s->is_mtls = event->is_mtls;
        s->addr_family = event->addr_family;
        s->local_port = event->local_port;
        s->remote_port = event->remote_port;
        if (event->addr_family == ADDR_FAMILY_IPV4) {
            s->local_addr.v4 = event->local_addr_v4;
            s->remote_addr.v4 = event->remote_addr_v4;
        } else if (event->addr_family == ADDR_FAMILY_IPV6) {
            memcpy(s->local_addr.v6, event->local_addr_v6, 16);
            memcpy(s->remote_addr.v6, event->remote_addr_v6, 16);
        }
        memcpy(s->comm, event->comm, MAX_COMM_LEN);
        if (event->cipher[0])
            snprintf(s->cipher, sizeof(s->cipher), "%.*s",
                     MAX_CIPHER_LEN, event->cipher);
    }

    s->last_seen_ns = event->timestamp_ns;
    s->event_count++;

    if (event->direction == DIRECTION_WRITE)
        s->bytes_sent += event->data_len;
    else
        s->bytes_received += event->data_len;

    /* Update protocol from HTTP info if available */
    if (http && http->method[0] && !s->protocol[0])
        snprintf(s->protocol, sizeof(s->protocol), "https");

    /* Update DNS hostname from HTTP Host header */
    if (http && http->host[0] && !s->dns_hostname[0])
        snprintf(s->dns_hostname, sizeof(s->dns_hostname), "%s", http->host);
}

void session_emit_json(const struct session_entry *entry,
                       const struct config *cfg)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char iso_time[64];
    struct tm tm_buf;
    gmtime_r(&ts.tv_sec, &tm_buf);
    strftime(iso_time, sizeof(iso_time), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    __u64 duration_ms = 0;
    if (entry->last_seen_ns > entry->start_ns)
        duration_ms = (entry->last_seen_ns - entry->start_ns) / 1000000;

    char remote_ip[INET6_ADDRSTRLEN] = "-";
    char local_ip[INET6_ADDRSTRLEN] = "-";
    if (entry->addr_family == ADDR_FAMILY_IPV4) {
        if (entry->remote_addr.v4) {
            struct in_addr raddr = { .s_addr = entry->remote_addr.v4 };
            inet_ntop(AF_INET, &raddr, remote_ip, sizeof(remote_ip));
        }
        if (entry->local_addr.v4) {
            struct in_addr laddr = { .s_addr = entry->local_addr.v4 };
            inet_ntop(AF_INET, &laddr, local_ip, sizeof(local_ip));
        }
    } else if (entry->addr_family == ADDR_FAMILY_IPV6) {
        inet_ntop(AF_INET6, entry->remote_addr.v6, remote_ip, sizeof(remote_ip));
        inet_ntop(AF_INET6, entry->local_addr.v6, local_ip, sizeof(local_ip));
    }

    const char *close_str = "timeout";
    if (entry->close_reason == SESSION_CLOSE_NORMAL)
        close_str = "normal";
    else if (entry->close_reason == SESSION_CLOSE_ERROR)
        close_str = "error";

    const char *tls_ver = NULL;
    switch (entry->tls_version) {
    case 0x0301: tls_ver = "1.0"; break;
    case 0x0302: tls_ver = "1.1"; break;
    case 0x0303: tls_ver = "1.2"; break;
    case 0x0304: tls_ver = "1.3"; break;
    }

    printf("{\"event_type\":\"session_summary\","
           "\"timestamp\":\"%s.%06ldZ\","
           "\"conn_id\":\"%u:%u\","
           "\"pid\":%u,\"comm\":",
           iso_time, ts.tv_nsec / 1000,
           entry->key.pid, entry->key.fd,
           entry->key.pid);
    print_json_string_n(entry->comm, MAX_COMM_LEN);

    if (cfg->host_ip[0]) {
        printf(",\"host_ip\":");
        print_json_string(cfg->host_ip);
    }

    printf(",\"duration_ms\":%llu,"
           "\"bytes_sent\":%llu,\"bytes_received\":%llu,"
           "\"events_count\":%u",
           (unsigned long long)duration_ms,
           (unsigned long long)entry->bytes_sent,
           (unsigned long long)entry->bytes_received,
           entry->event_count);

    if (tls_ver)
        printf(",\"tls_version\":\"%s\"", tls_ver);
    if (entry->cipher[0]) {
        printf(",\"tls_cipher\":");
        print_json_string(entry->cipher);
    }
    printf(",\"tls_auth\":\"%s\"", entry->is_mtls ? "mtls" : "one-way");

    if (entry->protocol[0])
        printf(",\"protocol\":\"%s\"", entry->protocol);

    printf(",\"src_ip\":\"%s\",\"src_port\":%u,"
           "\"dst_ip\":\"%s\",\"dst_port\":%u",
           local_ip, entry->local_port,
           remote_ip, entry->remote_port);

    if (entry->dns_hostname[0]) {
        printf(",\"dst_dns\":");
        print_json_string(entry->dns_hostname);
    }

    printf(",\"close_reason\":\"%s\"}\n", close_str);
}

void session_sweep(time_t now, int timeout_secs,
                   session_emit_fn emit_fn, const struct config *cfg)
{
    __u64 timeout_ns = (__u64)timeout_secs * 1000000000ULL;
    __u64 now_ns = (__u64)now * 1000000000ULL;

    for (__u32 i = 0; i < SESSION_TABLE_SIZE; i++) {
        if (!session_table[i].occupied)
            continue;
        if (session_table[i].last_seen_ns == 0)
            continue;
        if (now_ns - session_table[i].last_seen_ns > timeout_ns) {
            session_table[i].close_reason = SESSION_CLOSE_TIMEOUT;
            if (emit_fn)
                emit_fn(&session_table[i], cfg);
            session_table[i].occupied = 0;
        }
    }
}

void session_close(const struct tls_event_t *event, int reason,
                   session_emit_fn emit_fn, const struct config *cfg)
{
    __u32 idx = session_hash(event->pid, event->fd);

    for (__u32 i = 0; i < SESSION_TABLE_SIZE && i < 64; i++) {
        __u32 slot = (idx + i) & (SESSION_TABLE_SIZE - 1);
        if (!session_table[slot].occupied)
            return;
        if (session_table[slot].key.pid == event->pid &&
            session_table[slot].key.fd == event->fd) {
            session_table[slot].close_reason = reason;
            if (emit_fn)
                emit_fn(&session_table[slot], cfg);
            session_table[slot].occupied = 0;
            return;
        }
    }
}
