// SPDX-License-Identifier: MIT
//
// Output formatting and event handling: JSON/text output, hex dump,
// address formatting, and the ring buffer event callback.

#define _GNU_SOURCE  /* for memmem() */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include "output.h"
#include "config.h"
#include "filter.h"
#include "protocol.h"
#include "k8s.h"
#include "session.h"
#include "pcap.h"
#include "metrics.h"

/* Event statistics (defined in tls_tracer.c, accessed here) */
extern __u64 stat_events_captured;
extern __u64 stat_events_filtered;

const char *direction_str(int dir)
{
    return dir == DIRECTION_READ ? "RESPONSE" : "REQUEST";
}

/* DRY helper: TLS version code to string */
static const char *tls_version_str(__u16 ver)
{
    switch (ver) {
    case 0x0301: return "1.0";
    case 0x0302: return "1.1";
    case 0x0303: return "1.2";
    case 0x0304: return "1.3";
    default:     return NULL;
    }
}

void format_addr(const struct tls_event_t *event, char *buf, size_t buflen)
{
    if (event->addr_family == ADDR_FAMILY_IPV4 && event->remote_addr_v4 != 0) {
        struct in_addr addr = { .s_addr = event->remote_addr_v4 };
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        snprintf(buf, buflen, "%s:%u", ip, event->remote_port);
    } else if (event->addr_family == ADDR_FAMILY_IPV6) {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, event->remote_addr_v6, ip, sizeof(ip));
        snprintf(buf, buflen, "[%s]:%u", ip, event->remote_port);
    } else {
        snprintf(buf, buflen, "-");
    }
}

void print_hex_dump(const char *data, __u32 len)
{
    for (__u32 i = 0; i < len; i += 16) {
        printf("  %04x: ", i);
        __u32 remaining = (len - i < 16) ? len - i : 16;
        for (__u32 j = 0; j < remaining; j++)
            printf("%02x ", (unsigned char)data[i + j]);
        for (__u32 j = remaining; j < 16; j++)
            printf("   ");
        printf(" ");
        for (__u32 j = 0; j < remaining; j++) {
            char c = data[i + j];
            printf("%c", isprint((unsigned char)c) ? c : '.');
        }
        printf("\n");
    }
}

void print_printable(const char *data, __u32 len)
{
    for (__u32 i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        if (isprint(c) || c == '\n' || c == '\r' || c == '\t')
            putchar(c);
    }
}

/* Print a JSON string value, escaping special characters.
 * For length-bounded strings (e.g. comm from kernel), use maxlen > 0
 * to avoid reading past the buffer. If maxlen == 0, reads until NUL. */
void print_json_string_n(const char *s, size_t maxlen)
{
    putchar('"');
    for (size_t i = 0; (maxlen == 0 ? *s : i < maxlen) && *s; s++, i++) {
        switch (*s) {
        case '"':  printf("\\\""); break;
        case '\\': printf("\\\\"); break;
        case '\n': printf("\\n"); break;
        case '\r': printf("\\r"); break;
        case '\t': printf("\\t"); break;
        default:
            if (isprint((unsigned char)*s))
                putchar(*s);
            else
                printf("\\u%04x", (unsigned char)*s);
        }
    }
    putchar('"');
}

/* Print a NUL-terminated JSON string value, escaping special characters */
void print_json_string(const char *s)
{
    print_json_string_n(s, 0);
}

int handle_event(void *ctx, void *data, size_t size)
{
    struct tls_event_t *event = data;
    struct config *c = ctx;

    if (size < sizeof(*event) - MAX_DATA_LEN)
        return 0;

    /* Apply filters */
    if (c->filter_pid && event->pid != c->filter_pid) {
        stat_events_filtered++;
        return 0;
    }
    if (c->filter_uid && event->uid != c->filter_uid) {
        stat_events_filtered++;
        return 0;
    }

    __u32 data_len = event->data_len;
    if (data_len > MAX_DATA_LEN)
        data_len = MAX_DATA_LEN;

    /* Early HTTP parse for traffic filter (method filter needs HTTP info) */
    struct http_info http_early;
    memset(&http_early, 0, sizeof(http_early));
    if (data_len > 0)
        parse_http_info(event->data, data_len, &http_early);

    /* Apply traffic filters (CIDR, protocol, method, direction) */
    if (filter_event(&c->filter, event, &http_early) == 0) {
        stat_events_filtered++;
        return 0;
    }

    /* Headers-only mode: truncate data at HTTP body boundary (\r\n\r\n) */
    if (c->headers_only && data_len > 0) {
        const void *body_sep = memmem(event->data, data_len, "\r\n\r\n", 4);
        if (body_sep)
            data_len = (__u32)((const char *)body_sep - event->data) + 4;
    }

    stat_events_captured++;

    /* Update Prometheus metrics counters */
    if (c->metrics_port > 0)
        metrics_update_event(event);

    /* Write to PCAP file (data events only) */
    if (c->pcap_path[0] && event->event_type == EVENT_TLS_DATA)
        pcap_write_event_from_tls(c->pcap_path, event);

    /* Session aggregation: update session tracking */
    if (c->aggregate) {
        session_update(event, &http_early, c);

        /* Emit summary immediately on close/error */
        if (event->event_type == EVENT_TLS_CLOSE)
            session_close(event, SESSION_CLOSE_NORMAL, session_emit_json, c);
        else if (event->event_type == EVENT_TLS_ERROR)
            session_close(event, SESSION_CLOSE_ERROR, session_emit_json, c);

        /* Suppress per-event output if aggregate-only mode */
        if (c->aggregate_only)
            return 0;
    }

    char addr_buf[128];
    format_addr(event, addr_buf, sizeof(addr_buf));

    /* Format remote and local IPs separately for JSON */
    char remote_ip[INET6_ADDRSTRLEN] = "-";
    char local_ip[INET6_ADDRSTRLEN] = "-";
    if (event->addr_family == ADDR_FAMILY_IPV4) {
        if (event->remote_addr_v4 != 0) {
            struct in_addr raddr = { .s_addr = event->remote_addr_v4 };
            inet_ntop(AF_INET, &raddr, remote_ip, sizeof(remote_ip));
        }
        if (event->local_addr_v4 != 0) {
            struct in_addr laddr = { .s_addr = event->local_addr_v4 };
            inet_ntop(AF_INET, &laddr, local_ip, sizeof(local_ip));
        }
    } else if (event->addr_family == ADDR_FAMILY_IPV6) {
        inet_ntop(AF_INET6, event->remote_addr_v6, remote_ip, sizeof(remote_ip));
        inet_ntop(AF_INET6, event->local_addr_v6, local_ip, sizeof(local_ip));
    }

    if (c->format == FMT_JSON) {
        /* Get wall-clock timestamp (use gmtime_r for thread-safety) */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        char iso_time[64];
        struct tm tm_buf;
        gmtime_r(&ts.tv_sec, &tm_buf);
        strftime(iso_time, sizeof(iso_time), "%Y-%m-%dT%H:%M:%S", &tm_buf);

        /* Handle TCP connect error events */
        if (event->event_type == EVENT_CONNECT_ERROR) {
            const char *err_desc = "unknown";
            int ecode = (int)event->error_code;
            switch (ecode) {
            case 2:   err_desc = "no_such_file"; break;       /* ENOENT */
            case 13:  err_desc = "permission_denied"; break;  /* EACCES */
            case 22:  err_desc = "invalid_argument"; break;   /* EINVAL */
            case 97:  err_desc = "address_family_not_supported"; break; /* EAFNOSUPPORT */
            case 98:  err_desc = "address_already_in_use"; break; /* EADDRINUSE */
            case 99:  err_desc = "address_not_available"; break;  /* EADDRNOTAVAIL */
            case 100: err_desc = "network_down"; break;       /* ENETDOWN */
            case 101: err_desc = "network_unreachable"; break;/* ENETUNREACH */
            case 104: err_desc = "connection_reset"; break;   /* ECONNRESET */
            case 106: err_desc = "already_connected"; break;  /* EISCONN */
            case 110: err_desc = "connection_timed_out"; break;/* ETIMEDOUT */
            case 111: err_desc = "connection_refused"; break; /* ECONNREFUSED */
            case 112: err_desc = "host_down"; break;          /* EHOSTDOWN */
            case 113: err_desc = "no_route_to_host"; break;   /* EHOSTUNREACH */
            case 114: err_desc = "already_in_progress"; break;/* EALREADY */
            case 115: err_desc = "in_progress"; break;        /* EINPROGRESS */
            default: break;
            }

            printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
                   "\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
                   iso_time, ts.tv_nsec / 1000,
                   (unsigned long long)event->timestamp_ns,
                   event->pid, event->tid, event->uid);
            print_json_string_n(event->comm, MAX_COMM_LEN);
            if (c->host_ip[0]) {
                printf(",\"host_ip\":");
                print_json_string(c->host_ip);
            }
            printf(",\"event_type\":\"tcp_error\","
                   "\"dst_ip\":\"%s\",\"dst_port\":%u,"
                   "\"error_code\":%d,\"error\":\"%s\"}\n",
                   remote_ip, event->remote_port,
                   ecode, err_desc);
            return 0;
        }

        /* Handle TLS close events (#3 fix) */
        if (event->event_type == EVENT_TLS_CLOSE) {
            const char *tls_ver_str = tls_version_str(event->tls_version);

            printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
                   "\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
                   iso_time, ts.tv_nsec / 1000,
                   (unsigned long long)event->timestamp_ns,
                   event->pid, event->tid, event->uid);
            print_json_string_n(event->comm, MAX_COMM_LEN);
            if (c->host_ip[0]) {
                printf(",\"host_ip\":");
                print_json_string(c->host_ip);
            }
            printf(",\"event_type\":\"tls_close\","
                   "\"direction\":\"%s\","
                   "\"src_ip\":\"%s\",\"src_port\":%u,"
                   "\"dst_ip\":\"%s\",\"dst_port\":%u",
                   direction_str(event->direction),
                   local_ip, event->local_port,
                   remote_ip, event->remote_port);

            if (event->fd > 0)
                printf(",\"conn_id\":\"%u:%u\"", event->pid, event->fd);
            if (tls_ver_str)
                printf(",\"tls_version\":\"%s\"", tls_ver_str);
            if (event->cipher[0]) {
                printf(",\"tls_cipher\":");
                char cipher_safe[MAX_CIPHER_LEN + 1];
                memcpy(cipher_safe, event->cipher, MAX_CIPHER_LEN);
                cipher_safe[MAX_CIPHER_LEN] = '\0';
                print_json_string(cipher_safe);
            }
            printf(",\"tls_auth\":\"%s\"", event->is_mtls ? "mtls" : "one-way");
            printf("}\n");
            return 0;
        }

        /* Handle TLS error events */
        if (event->event_type == EVENT_TLS_ERROR) {
            const char *tls_ver_str = tls_version_str(event->tls_version);

            printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
                   "\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
                   iso_time, ts.tv_nsec / 1000,
                   (unsigned long long)event->timestamp_ns,
                   event->pid, event->tid, event->uid);
            print_json_string_n(event->comm, MAX_COMM_LEN);
            if (c->host_ip[0]) {
                printf(",\"host_ip\":");
                print_json_string(c->host_ip);
            }
            printf(",\"event_type\":\"tls_error\","
                   "\"direction\":\"%s\","
                   "\"src_ip\":\"%s\",\"src_port\":%u,"
                   "\"dst_ip\":\"%s\",\"dst_port\":%u,"
                   "\"ssl_return_code\":%d",
                   direction_str(event->direction),
                   local_ip, event->local_port,
                   remote_ip, event->remote_port,
                   (int)event->error_code);

            if (event->fd > 0)
                printf(",\"conn_id\":\"%u:%u\"", event->pid, event->fd);

            if (tls_ver_str)
                printf(",\"tls_version\":\"%s\"", tls_ver_str);

            printf("}\n");
            return 0;
        }

        /* Handle QUIC detection events */
        if (event->event_type == EVENT_QUIC_DETECTED) {
            printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
                   "\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
                   iso_time, ts.tv_nsec / 1000,
                   (unsigned long long)event->timestamp_ns,
                   event->pid, event->tid, event->uid);
            print_json_string_n(event->comm, MAX_COMM_LEN);
            if (c->host_ip[0]) {
                printf(",\"host_ip\":");
                print_json_string(c->host_ip);
            }
            printf(",\"event_type\":\"quic_detected\","
                   "\"src_ip\":\"%s\",\"src_port\":%u,"
                   "\"dst_ip\":\"%s\",\"dst_port\":%u,"
                   "\"transport\":\"udp\",\"protocol\":\"quic\"}\n",
                   local_ip, event->local_port,
                   remote_ip, event->remote_port);
            return 0;
        }

        /* K8s metadata enrichment (R-3 fix: cached per PID to avoid /proc I/O storm) */
        struct k8s_meta meta;
        if (!k8s_cache_lookup((pid_t)event->pid, &meta)) {
            get_k8s_meta_ratelimited((pid_t)event->pid, &meta);
            k8s_cache_store((pid_t)event->pid, &meta);
        }

        /* HTTP Layer 7 parsing (both directions — WRITE for requests, READ for responses) */
        /* Reuse early HTTP parse from filter stage */
        struct http_info http = http_early;

        /* Apply sanitization patterns to HTTP fields */
        if (http.path[0])
            sanitize_string(http.path, sizeof(http.path), c);
        if (http.host[0])
            sanitize_string(http.host, sizeof(http.host), c);

        /* Emit one self-contained JSON event */
        printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
               "\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
               iso_time, ts.tv_nsec / 1000,
               (unsigned long long)event->timestamp_ns,
               event->pid, event->tid, event->uid);
        print_json_string_n(event->comm, MAX_COMM_LEN);
        if (c->host_ip[0]) {
            printf(",\"host_ip\":");
            print_json_string(c->host_ip);
        }
        if (c->ecs_detected)
            printf(",\"runtime\":\"ecs\"");
        printf(",\"direction\":\"%s\","
               "\"src_ip\":\"%s\",\"src_port\":%u,"
               "\"dst_ip\":\"%s\",\"dst_port\":%u,"
               "\"data_len\":%u",
               direction_str(event->direction),
               local_ip, event->local_port,
               remote_ip, event->remote_port,
               data_len);

        /* Connection ID for correlating events on the same TCP connection.
         * Combines PID and socket fd into a unique identifier. */
        if (event->fd > 0)
            printf(",\"conn_id\":\"%u:%u\"", event->pid, event->fd);

        /* DNS / hostname from HTTP Host header (best-effort).
         * Cache the hostname per {pid, fd} so subsequent events on the same
         * connection inherit it even without a Host header. */
        const char *dns_hostname = NULL;
        if (http.host[0]) {
            dns_hostname = http.host;
            dns_cache_store(event->pid, event->fd, http.host);
        } else if (event->fd > 0) {
            dns_hostname = dns_cache_lookup(event->pid, event->fd);
        }
        if (dns_hostname) {
            printf(",\"dst_dns\":");
            print_json_string(dns_hostname);
        }

        /* K8s fields (only if populated) */
        if (meta.pod_name[0]) {
            printf(",\"k8s_pod\":");
            print_json_string(meta.pod_name);
        }
        if (meta.pod_namespace[0]) {
            printf(",\"k8s_namespace\":");
            print_json_string(meta.pod_namespace);
        }
        if (meta.container_id[0]) {
            printf(",\"container_id\":");
            print_json_string(meta.container_id);
        }

        /* Protocol detection: data signatures first, then well-known ports */
        const char *l7_proto = "unknown";
        int is_http2 = 0;

        /* 1. Detect HTTP/2 connection preface (client->server first write)
         * RFC 7540 §3.5: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" */
        if (data_len >= 24 && strncmp(event->data, "PRI * HTTP/2.0", 14) == 0)
            is_http2 = 1;

        /* 2. Detect HTTP/2 frames by validating the 9-byte frame header.
         * Format: length(3) + type(1) + flags(1) + stream_id(4)
         * Valid frame types: 0x00(DATA) - 0x09(CONTINUATION) per RFC 7540 §6.
         * To avoid false positives, we require:
         *   - Frame length consistent with captured data (frame_len + 9 <= data_len * 2)
         *   - SETTINGS(0x04) or HEADERS(0x01) frame types (most common first frames)
         *   - Reserved bit in stream ID must be 0 */
        if (!is_http2 && data_len >= 18) {  /* Need enough data to reduce false positives */
            __u8 frame_type = (unsigned char)event->data[3];
            /* Stream ID: top bit is reserved (must be 0) */
            __u8 stream_id_top = (unsigned char)event->data[5];
            __u32 frame_len = ((unsigned char)event->data[0] << 16) |
                              ((unsigned char)event->data[1] << 8) |
                              (unsigned char)event->data[2];
            /* Only match SETTINGS(4), HEADERS(1), WINDOW_UPDATE(8) as first frames */
            if ((frame_type == 0x04 || frame_type == 0x01 || frame_type == 0x08) &&
                (stream_id_top & 0x80) == 0 &&
                frame_len > 0 && frame_len <= 16384)
                is_http2 = 1;
        }

        /* 3. Classify HTTP/2 traffic: gRPC vs plain HTTPS.
         * gRPC uses HTTP/2 exclusively, typically on ports 443, 8443, or
         * 50051-50055 (default grpc ports). Also check for gRPC message
         * framing in DATA frames: compressed_flag(1) + msg_length(4). */
        if (is_http2) {
            /* gRPC detection heuristics:
             * a) Well-known gRPC ports (50051-50055)
             * b) HTTP/2 DATA frame (type=0x0) with gRPC length-prefixed message
             * c) Check for gRPC content-type in HEADERS via HPACK
             *    (te: trailers is gRPC-specific) */
            __u16 port = event->remote_port;
            if (port >= 50051 && port <= 50055) {
                l7_proto = "grpc";
            } else if (data_len >= 14 && (unsigned char)event->data[3] == 0x00) {
                /* DATA frame: check if payload starts with gRPC message framing
                 * (compressed_flag byte 0x00 or 0x01 + 4-byte big-endian length) */
                __u8 grpc_compress = (unsigned char)event->data[9];
                if (grpc_compress <= 1) {
                    __u32 grpc_msg_len = ((unsigned char)event->data[10] << 24) |
                                         ((unsigned char)event->data[11] << 16) |
                                         ((unsigned char)event->data[12] << 8) |
                                         (unsigned char)event->data[13];
                    __u32 frame_len = ((unsigned char)event->data[0] << 16) |
                                      ((unsigned char)event->data[1] << 8) |
                                      (unsigned char)event->data[2];
                    /* gRPC message length should be <= frame payload length - 5 */
                    if (grpc_msg_len > 0 && grpc_msg_len <= frame_len)
                        l7_proto = "grpc";
                }
            }
            if (strcmp(l7_proto, "unknown") == 0)
                l7_proto = "https";  /* HTTP/2 but not gRPC -> HTTPS */
        }

        /* 4. Detect WebSocket upgrade (RFC 6455 over TLS = wss://)
         * Request:  "Upgrade: websocket" header
         * Response: "HTTP/1.1 101 Switching Protocols" */
        if (strcmp(l7_proto, "unknown") == 0 || strcmp(l7_proto, "https") == 0) {
            if (http.websocket)
                l7_proto = "wss";
            else if (data_len >= 12 && strncmp(event->data, "HTTP/1.1 101", 12) == 0)
                l7_proto = "wss";
        }

        /* 5. Detect by HTTP/1.x data content */
        if (strcmp(l7_proto, "unknown") == 0) {
            if (http.method[0])
                l7_proto = "https";
            else if (data_len >= 5 && strncmp(event->data, "HTTP/", 5) == 0)
                l7_proto = "https";
        }

        /* 6. Detect SMTP over TLS */
        if (strcmp(l7_proto, "unknown") == 0 && data_len >= 4 && (
            strncmp(event->data, "EHLO", 4) == 0 ||
            strncmp(event->data, "MAIL", 4) == 0 ||
            strncmp(event->data, "RCPT", 4) == 0 ||
            strncmp(event->data, "220 ", 4) == 0 ||
            strncmp(event->data, "250 ", 4) == 0))
            l7_proto = "smtps";

        /* 7. Detect IMAP over TLS (use memmem for bounded search — R7 fix) */
        if (strcmp(l7_proto, "unknown") == 0 && data_len >= 4 && (
            strncmp(event->data, "* OK", 4) == 0 ||
            (event->data[0] >= 'A' && event->data[0] <= 'Z' &&
             data_len >= 6 && memmem(event->data, data_len, "LOGIN", 5) != NULL)))
            l7_proto = "imaps";

        /* 8. Detect Kafka wire protocol (binary header structure).
         *
         * Issue 3 fix: HTTP/2 binary frames can match the Kafka wire format
         * heuristic (both use big-endian length-prefixed framing). Guard
         * against false positives by:
         *   a) Skipping Kafka detection if protocol is already identified
         *      (HTTPS/gRPC/WSS detected above via HTTP/2 frame checks)
         *   b) Skipping if destination port is 443 or 8443 (Kafka over TLS
         *      uses 9092/9093/9094, never standard HTTPS ports)
         *   c) Requiring correlation_id > 0 (HTTP/2 frames often have 0) */
        int kafka_api_key = -1;
        int is_kafka_response = 0;
        __u16 dst_port = event->remote_port;
        int kafka_port_ok = (dst_port != 443 && dst_port != 8443);

        if (strcmp(l7_proto, "unknown") == 0 && kafka_port_ok &&
            detect_kafka_protocol(event->data, data_len, &kafka_api_key))
            l7_proto = "kafka";

        /* J-4 fix: Kafka response detection must happen BEFORE protocol is printed.
         * Previously this was dead code because l7_proto was already emitted. */
        if (kafka_api_key < 0 && strcmp(l7_proto, "unknown") == 0 &&
            kafka_port_ok &&
            detect_kafka_response(event->data, data_len)) {
            l7_proto = "kafka";
            is_kafka_response = 1;
        }

        /* 9. Fall back to well-known TLS port numbers (RFC/IANA assignments) */
        if (strcmp(l7_proto, "unknown") == 0) {
            __u16 port = event->remote_port;
            switch (port) {
            case 443:  l7_proto = "https";  break;  /* RFC 2818 */
            case 8443: l7_proto = "https";  break;  /* Alt HTTPS */
            case 465:  l7_proto = "smtps";  break;  /* RFC 8314 */
            case 587:  l7_proto = "smtps";  break;  /* SMTP submission + STARTTLS */
            case 993:  l7_proto = "imaps";  break;  /* RFC 8314 */
            case 995:  l7_proto = "pop3s";  break;  /* RFC 8314 */
            case 636:  l7_proto = "ldaps";  break;  /* RFC 4513 */
            case 989:
            case 990:  l7_proto = "ftps";   break;  /* RFC 4217 */
            case 5223: l7_proto = "xmpps";  break;  /* XMPP over TLS */
            case 6697: l7_proto = "ircs";   break;  /* IRC over TLS */
            case 5671: l7_proto = "amqps";  break;  /* AMQP over TLS */
            case 8883: l7_proto = "mqtts";  break;  /* MQTT over TLS */
            case 9200:
            case 9243: l7_proto = "https";  break;  /* Elasticsearch */
            case 27017: l7_proto = "mongodb+srv"; break; /* MongoDB TLS */
            /* Kafka TLS ports (Confluent Cloud / self-hosted) */
            case 9092:
            case 9093:
            case 9094: l7_proto = "kafka";  break;
            /* gRPC default ports (no IANA assignment, de facto standard) */
            case 50051:
            case 50052:
            case 50053:
            case 50054:
            case 50055: l7_proto = "grpc"; break;
            default: break;
            }
        }
        /* TLS version: 0x0303=TLS1.2, 0x0304=TLS1.3 */
        const char *tls_ver_str = tls_version_str(event->tls_version);
        if (tls_ver_str)
            printf(",\"tls_version\":\"%s\"", tls_ver_str);

        /* TLS cipher suite name (from SSL_get_current_cipher uprobe) */
        if (event->cipher[0]) {
            printf(",\"tls_cipher\":");
            /* Ensure null-terminated for safety */
            char cipher_safe[MAX_CIPHER_LEN + 1];
            memcpy(cipher_safe, event->cipher, MAX_CIPHER_LEN);
            cipher_safe[MAX_CIPHER_LEN] = '\0';
            print_json_string(cipher_safe);
        }

        /* TLS authentication mode: one-way or mutual (mTLS) */
        printf(",\"tls_auth\":\"%s\"", event->is_mtls ? "mtls" : "one-way");

        /* TLS library (omit for OpenSSL for backward compat) */
        if (event->tls_library == TLS_LIB_GNUTLS)
            printf(",\"tls_library\":\"gnutls\"");
        else if (event->tls_library == TLS_LIB_WOLFSSL)
            printf(",\"tls_library\":\"wolfssl\"");

        printf(",\"transport\":\"tls\",\"protocol\":\"%s\"", l7_proto);

        /* HTTP version: from request line or inferred from HTTP/2 detection */
        if (is_http2)
            printf(",\"http_version\":\"2\"");
        else if (http.version[0]) {
            printf(",\"http_version\":");
            print_json_string(http.version);
        }

        /* #6 fix: HTTP response status code */
        if (http.status_code > 0)
            printf(",\"http_status\":%d", http.status_code);

        if (http.method[0]) {
            printf(",\"http_method\":\"%s\"", http.method);
            if (http.path[0]) {
                printf(",\"http_path\":");
                print_json_string(http.path);
            }
            if (http.host[0]) {
                printf(",\"http_host\":");
                print_json_string(http.host);
            }
        }

        /* User-Agent header */
        if (http.user_agent[0]) {
            printf(",\"user_agent\":");
            print_json_string(http.user_agent);
        }

        /* #7 fix: HTTP/2 RST_STREAM / GOAWAY error codes */
        if (is_http2 && data_len >= 13) {
            int h2_frame_type = 0;
            int h2_err = parse_h2_error_code(event->data, data_len, &h2_frame_type);
            if (h2_err >= 0) {
                printf(",\"h2_error_code\":%d,\"h2_error_name\":\"%s\"",
                       h2_err, h2_error_code_name(h2_err));
                if (h2_frame_type == 0x03)
                    printf(",\"h2_frame_type\":\"RST_STREAM\"");
                else if (h2_frame_type == 0x07)
                    printf(",\"h2_frame_type\":\"GOAWAY\"");
            }
        }

        /* #8 fix: Try enhanced grpc-status detection from H2 frame payload */
        if (is_http2 && http.grpc_status < 0 && data_len > 0) {
            int h2_grpc = parse_grpc_status_from_h2(event->data, data_len);
            if (h2_grpc >= 0)
                http.grpc_status = h2_grpc;
        }

        /* gRPC status code from grpc-status header (0-16) */
        if (http.grpc_status >= 0) {
            const char *grpc_desc = "unknown";
            switch (http.grpc_status) {
            case 0:  grpc_desc = "OK"; break;
            case 1:  grpc_desc = "CANCELLED"; break;
            case 2:  grpc_desc = "UNKNOWN"; break;
            case 3:  grpc_desc = "INVALID_ARGUMENT"; break;
            case 4:  grpc_desc = "DEADLINE_EXCEEDED"; break;
            case 5:  grpc_desc = "NOT_FOUND"; break;
            case 6:  grpc_desc = "ALREADY_EXISTS"; break;
            case 7:  grpc_desc = "PERMISSION_DENIED"; break;
            case 8:  grpc_desc = "RESOURCE_EXHAUSTED"; break;
            case 9:  grpc_desc = "FAILED_PRECONDITION"; break;
            case 10: grpc_desc = "ABORTED"; break;
            case 11: grpc_desc = "OUT_OF_RANGE"; break;
            case 12: grpc_desc = "UNIMPLEMENTED"; break;
            case 13: grpc_desc = "INTERNAL"; break;
            case 14: grpc_desc = "UNAVAILABLE"; break;
            case 15: grpc_desc = "DATA_LOSS"; break;
            case 16: grpc_desc = "UNAUTHENTICATED"; break;
            default: break;
            }
            printf(",\"grpc_status\":%d,\"grpc_status_name\":\"%s\"",
                   http.grpc_status, grpc_desc);
        }

        /* Kafka API key detection (request frames) */
        if (kafka_api_key >= 0) {
            const char *api_name = kafka_api_key_name(kafka_api_key);
            printf(",\"kafka_api_key\":%d", kafka_api_key);
            if (api_name)
                printf(",\"kafka_api_name\":\"%s\"", api_name);
            printf(",\"kafka_frame_type\":\"request\"");
        }

        /* Kafka response frame details (J-4 fix: detection moved before protocol print) */
        if (is_kafka_response) {
            printf(",\"kafka_frame_type\":\"response\"");
            if (data_len >= 10) {
                int k_err = (int)(short)(((unsigned char)event->data[8] << 8) |
                                          (unsigned char)event->data[9]);
                if (k_err != 0)
                    printf(",\"kafka_error_code\":%d", k_err);
            }
        }

        /* WebSocket close code detection */
        if (strcmp(l7_proto, "wss") == 0 || strcmp(l7_proto, "unknown") == 0) {
            int ws_close = parse_websocket_close_code(event->data, data_len);
            if (ws_close >= 0) {
                const char *ws_desc = "unknown";
                switch (ws_close) {
                case 1000: ws_desc = "NORMAL_CLOSURE"; break;
                case 1001: ws_desc = "GOING_AWAY"; break;
                case 1002: ws_desc = "PROTOCOL_ERROR"; break;
                case 1003: ws_desc = "UNSUPPORTED_DATA"; break;
                case 1005: ws_desc = "NO_STATUS_RECEIVED"; break;
                case 1006: ws_desc = "ABNORMAL_CLOSURE"; break;
                case 1007: ws_desc = "INVALID_FRAME_PAYLOAD_DATA"; break;
                case 1008: ws_desc = "POLICY_VIOLATION"; break;
                case 1009: ws_desc = "MESSAGE_TOO_BIG"; break;
                case 1010: ws_desc = "MANDATORY_EXTENSION"; break;
                case 1011: ws_desc = "INTERNAL_ERROR"; break;
                case 1012: ws_desc = "SERVICE_RESTART"; break;
                case 1013: ws_desc = "TRY_AGAIN_LATER"; break;
                case 1014: ws_desc = "BAD_GATEWAY"; break;
                case 1015: ws_desc = "TLS_HANDSHAKE"; break;
                default:
                    if (ws_close >= 3000 && ws_close <= 3999)
                        ws_desc = "REGISTERED";
                    else if (ws_close >= 4000 && ws_close <= 4999)
                        ws_desc = "PRIVATE";
                    break;
                }
                printf(",\"ws_close_code\":%d,\"ws_close_reason\":\"%s\"",
                       ws_close, ws_desc);
            }
        }

        printf("}\n");
    } else {
        if (!c->data_only) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            struct tm tm_buf;
            localtime_r(&ts.tv_sec, &tm_buf);
            char timebuf[64];
            strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm_buf);

            printf("%-12s %-6s PID=%-6u TID=%-6u UID=%-4u COMM=%-15.*s ADDR=%-21s LEN=%u\n",
                   timebuf,
                   direction_str(event->direction),
                   event->pid, event->tid, event->uid,
                   MAX_COMM_LEN, event->comm,
                   addr_buf,
                   data_len);
        }

        if (data_len > 0) {
            if (c->hex_dump)
                print_hex_dump(event->data, data_len);
            else
                print_printable(event->data, data_len);

            if (!c->hex_dump)
                printf("\n");
        }
    }

    return 0;
}
