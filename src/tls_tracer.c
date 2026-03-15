// SPDX-License-Identifier: MIT
//
// tls_tracer - eBPF-based TLS traffic interceptor
//
// Attaches uprobes to OpenSSL's SSL_read/SSL_write to capture
// plaintext data flowing through TLS connections, along with
// the remote IP address and port of each connection.

#define _GNU_SOURCE  /* for memmem() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <regex.h>
#include <arpa/inet.h>
#include <limits.h>  /* for ULONG_MAX */
#include <sys/stat.h>  /* for mkdir() */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tracer.h"

#define PERF_BUFFER_PAGES  64
#define PERF_POLL_TIMEOUT  100
#define MAX_PROBES         16
#define MAX_SANITIZE_PATTERNS 32
#define DNS_CACHE_SIZE     4096  /* max cached hostname entries */
#define DNS_CACHE_TTL      300   /* seconds before expiry */

static volatile sig_atomic_t exiting = 0;
static volatile sig_atomic_t exit_signal = 0;  /* stores signal number for 128+signum (#2 fix) */

/* --- Userspace DNS cache: remembers hostname per {pid, fd} connection ---
 * When a Host: header is parsed, the hostname is stored here.
 * Subsequent events on the same connection inherit the cached hostname
 * even if they don't contain an HTTP Host header. */
struct dns_cache_entry {
    __u32 pid;
    __u32 fd;
    time_t last_seen;
    char   hostname[256];
};

static struct dns_cache_entry dns_cache[DNS_CACHE_SIZE];
static int dns_cache_count = 0;

static const char *dns_cache_lookup(__u32 pid, __u32 fd)
{
    time_t now = time(NULL);
    for (int i = 0; i < dns_cache_count; i++) {
        if (dns_cache[i].pid == pid && dns_cache[i].fd == fd) {
            if (now - dns_cache[i].last_seen > DNS_CACHE_TTL) {
                /* Expired — evict by swapping with last entry */
                dns_cache[i] = dns_cache[--dns_cache_count];
                return NULL;
            }
            dns_cache[i].last_seen = now;
            return dns_cache[i].hostname;
        }
    }
    return NULL;
}

static void dns_cache_store(__u32 pid, __u32 fd, const char *hostname)
{
    if (!hostname || !hostname[0] || fd == 0)
        return;

    time_t now = time(NULL);

    /* Update existing entry */
    for (int i = 0; i < dns_cache_count; i++) {
        if (dns_cache[i].pid == pid && dns_cache[i].fd == fd) {
            snprintf(dns_cache[i].hostname, sizeof(dns_cache[i].hostname), "%s", hostname);
            dns_cache[i].last_seen = now;
            return;
        }
    }

    /* Evict expired entries first */
    for (int i = 0; i < dns_cache_count; ) {
        if (now - dns_cache[i].last_seen > DNS_CACHE_TTL) {
            dns_cache[i] = dns_cache[--dns_cache_count];
        } else {
            i++;
        }
    }

    /* Add new entry (evict oldest if full) */
    int slot;
    if (dns_cache_count < DNS_CACHE_SIZE) {
        slot = dns_cache_count++;
    } else {
        /* Find and evict the oldest entry */
        slot = 0;
        for (int i = 1; i < DNS_CACHE_SIZE; i++) {
            if (dns_cache[i].last_seen < dns_cache[slot].last_seen)
                slot = i;
        }
    }
    dns_cache[slot].pid = pid;
    dns_cache[slot].fd = fd;
    dns_cache[slot].last_seen = now;
    snprintf(dns_cache[slot].hostname, sizeof(dns_cache[slot].hostname), "%s", hostname);
}

/* Output format */
enum output_fmt {
    FMT_TEXT,
    FMT_JSON,
};

/* Compiled sanitization regex patterns */
struct sanitize_pattern {
    regex_t regex;
    char    original[256];  /* original pattern string for debugging */
};

/* Runtime configuration */
struct config {
    enum output_fmt format;
    char            ssl_lib[256];
    __u32           filter_pid;
    __u32           filter_uid;
    int             hex_dump;
    int             data_only;
    int             verbose;
    struct sanitize_pattern sanitize[MAX_SANITIZE_PATTERNS];
    int             sanitize_count;
};

static struct config cfg = {
    .format          = FMT_TEXT,
    .ssl_lib         = "",
    .filter_pid      = 0,
    .filter_uid      = 0,
    .hex_dump        = 0,
    .data_only       = 0,
    .verbose         = 0,
    .sanitize_count  = 0,
};

static void sig_handler(int signo)
{
    exit_signal = signo;
    exiting = 1;
}

/* Add a sanitization regex pattern (case-insensitive) */
static int add_sanitize_pattern(const char *pattern)
{
    if (cfg.sanitize_count >= MAX_SANITIZE_PATTERNS) {
        fprintf(stderr, "Error: Too many sanitize patterns (max %d)\n",
                MAX_SANITIZE_PATTERNS);
        return -1;
    }
    struct sanitize_pattern *sp = &cfg.sanitize[cfg.sanitize_count];
    int ret = regcomp(&sp->regex, pattern, REG_EXTENDED | REG_ICASE);
    if (ret != 0) {
        char errbuf[128];
        regerror(ret, &sp->regex, errbuf, sizeof(errbuf));
        fprintf(stderr, "Error: Invalid sanitize pattern '%s': %s\n",
                pattern, errbuf);
        return -1;
    }
    snprintf(sp->original, sizeof(sp->original), "%s", pattern);
    cfg.sanitize_count++;
    return 0;
}

/* Apply sanitization patterns to a string, replacing matches with [REDACTED] */
static void sanitize_string(char *str, size_t len)
{
    if (cfg.sanitize_count == 0 || !str || !str[0])
        return;

    for (int i = 0; i < cfg.sanitize_count; i++) {
        regmatch_t match;
        char *p = str;
        while (regexec(&cfg.sanitize[i].regex, p, 1, &match, 0) == 0) {
            size_t match_start = (size_t)(p - str) + (size_t)match.rm_so;
            size_t match_len = (size_t)(match.rm_eo - match.rm_so);
            const char *redacted = "[REDACTED]";
            size_t redacted_len = 10;

            if (match_len == 0)
                break;

            /* Calculate new length */
            size_t current_len = strlen(str);
            if (current_len - match_len + redacted_len >= len)
                break;  /* Not enough space */

            /* Shift remainder and insert [REDACTED] */
            memmove(str + match_start + redacted_len,
                    str + match_start + match_len,
                    current_len - match_start - match_len + 1);
            memcpy(str + match_start, redacted, redacted_len);

            p = str + match_start + redacted_len;
        }
    }
}

static const char *direction_str(int dir)
{
    return dir == DIRECTION_READ ? "RESPONSE" : "REQUEST";
}

static void format_addr(const struct tls_event_t *event, char *buf, size_t buflen)
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

static void print_hex_dump(const char *data, __u32 len)
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

static void print_printable(const char *data, __u32 len)
{
    for (__u32 i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        if (isprint(c) || c == '\n' || c == '\r' || c == '\t')
            putchar(c);
    }
}

/* --- K8s metadata enrichment --- */

struct k8s_meta {
    char pod_name[256];
    char pod_namespace[256];
    char container_id[80];
};

/* Read an environment variable from /proc/<pid>/environ */
static int read_proc_env(pid_t pid, const char *var_name, char *buf, size_t buflen)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    size_t var_len = strlen(var_name);
    char *block = NULL;
    size_t block_len = 0;
    ssize_t n = getdelim(&block, &block_len, '\0', f);

    while (n > 0) {
        if ((size_t)n > var_len && block[var_len] == '=' &&
            strncmp(block, var_name, var_len) == 0) {
            snprintf(buf, buflen, "%s", block + var_len + 1);
            /* Remove trailing newline/null artifacts */
            size_t len = strlen(buf);
            while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
                buf[--len] = '\0';
            free(block);
            fclose(f);
            return 0;
        }
        n = getdelim(&block, &block_len, '\0', f);
    }
    free(block);
    fclose(f);
    return -1;
}

/* Extract container ID from /proc/<pid>/cgroup */
static int read_container_id(pid_t pid, char *buf, size_t buflen)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Look for containerd/docker cgroup paths:
         * .../docker-<id>.scope  or  .../cri-containerd-<id>.scope
         * or  .../pod<uid>/<container_id> */
        char *p;

        /* Pattern: cri-containerd- or docker- followed by hex ID */
        p = strstr(line, "cri-containerd-");
        if (!p)
            p = strstr(line, "docker-");
        if (p) {
            /* Skip prefix to get to the ID */
            char *id_start = strchr(p, '-');
            if (id_start) {
                id_start++;  /* skip second '-' for cri-containerd- */
                if (strncmp(p, "cri-containerd-", 15) == 0) {
                    id_start = p + 15;
                } else {
                    id_start = strchr(p, '-') + 1;
                }
                /* Copy up to .scope or end of line */
                char *end = strstr(id_start, ".scope");
                if (!end)
                    end = strchr(id_start, '\n');
                if (end) {
                    size_t id_len = (size_t)(end - id_start);
                    if (id_len >= buflen)
                        id_len = buflen - 1;
                    strncpy(buf, id_start, id_len);
                    buf[id_len] = '\0';
                    /* Truncate to first 12 chars (short container ID) */
                    if (strlen(buf) > 12)
                        buf[12] = '\0';
                    fclose(f);
                    return 0;
                }
            }
        }

        /* Pattern: last path component is a hex container ID (64 chars) */
        p = strrchr(line, '/');
        if (p && strlen(p + 1) >= 64) {
            char *id = p + 1;
            /* Verify it looks like hex */
            int is_hex = 1;
            for (int i = 0; i < 12 && id[i]; i++) {
                if (!isxdigit((unsigned char)id[i])) {
                    is_hex = 0;
                    break;
                }
            }
            if (is_hex) {
                strncpy(buf, id, 12);
                buf[12] = '\0';
                fclose(f);
                return 0;
            }
        }
    }

    fclose(f);
    return -1;
}

static void get_k8s_meta(pid_t pid, struct k8s_meta *meta)
{
    memset(meta, 0, sizeof(*meta));

    /* Pod name and namespace are typically set by K8s downward API:
     * POD_NAME, POD_NAMESPACE, or HOSTNAME for pod name */
    if (read_proc_env(pid, "POD_NAME", meta->pod_name, sizeof(meta->pod_name)) != 0)
        read_proc_env(pid, "HOSTNAME", meta->pod_name, sizeof(meta->pod_name));

    read_proc_env(pid, "POD_NAMESPACE", meta->pod_namespace, sizeof(meta->pod_namespace));
    read_container_id(pid, meta->container_id, sizeof(meta->container_id));
}

/* --- HTTP Layer 7 parsing --- */

struct http_info {
    char method[16];
    char path[512];
    char host[256];
    char user_agent[256]; /* User-Agent header value */
    char version[16];   /* "1.0", "1.1", or "2" */
    int  status_code;   /* HTTP response status code (0 = not a response) (#6 fix) */
    int  websocket;     /* 1 if Upgrade: websocket detected */
    int  grpc_status;   /* gRPC status code (-1 = not present, 0-16 = code) */
};

/* Kafka wire protocol detection: check if data matches Kafka request header.
 * Kafka request header: message_size(4) + api_key(2) + api_version(2) + correlation_id(4) + client_id_len(2)
 * Minimum 14 bytes. */
static int detect_kafka_protocol(const char *data, __u32 len, int *api_key)
{
    if (len < 14)
        return 0;

    /* Read message_size (4 bytes, big-endian) */
    __u32 msg_size = ((unsigned char)data[0] << 24) |
                     ((unsigned char)data[1] << 16) |
                     ((unsigned char)data[2] << 8) |
                     (unsigned char)data[3];

    /* Sanity: 4 < msg_size < 100MB, and msg_size + 4 should be close to data len */
    if (msg_size <= 4 || msg_size > 104857600)
        return 0;

    /* Read api_key (2 bytes, big-endian, signed) */
    int ak = (int)(short)(((unsigned char)data[4] << 8) |
                          (unsigned char)data[5]);
    if (ak < 0 || ak > 74)
        return 0;

    /* Read api_version (2 bytes) */
    int av = (int)(short)(((unsigned char)data[6] << 8) |
                          (unsigned char)data[7]);
    if (av < 0 || av > 20)
        return 0;

    /* Read correlation_id (4 bytes) — must be >= 0 */
    int corr_id = (int)(((unsigned char)data[8] << 24) |
                        ((unsigned char)data[9] << 16) |
                        ((unsigned char)data[10] << 8) |
                        (unsigned char)data[11]);
    if (corr_id < 0)
        return 0;

    /* Read client_id_length (2 bytes, -1 for null) */
    int cid_len = (int)(short)(((unsigned char)data[12] << 8) |
                               (unsigned char)data[13]);
    if (cid_len < -1 || cid_len > 1024)
        return 0;

    /* If client_id_length > 0, verify there's enough data */
    if (cid_len > 0 && len < (unsigned)(14 + cid_len))
        return 0;

    *api_key = (int)ak;
    return 1;
}

/* #9 fix: Kafka response frame detection.
 * Response header: message_size(4) + correlation_id(4).
 * No api_key in responses — they're matched by correlation_id client-side. */
static int detect_kafka_response(const char *data, __u32 len)
{
    if (len < 12)
        return 0;

    __u32 msg_size = ((unsigned char)data[0] << 24) |
                     ((unsigned char)data[1] << 16) |
                     ((unsigned char)data[2] << 8) |
                     (unsigned char)data[3];

    if (msg_size <= 4 || msg_size > 104857600)
        return 0;

    int corr_id = (int)(((unsigned char)data[4] << 24) |
                        ((unsigned char)data[5] << 16) |
                        ((unsigned char)data[6] << 8) |
                        (unsigned char)data[7]);
    if (corr_id < 0)
        return 0;

    /* Error code (2 bytes, valid range -1 to 120) */
    int error_code = (int)(short)(((unsigned char)data[8] << 8) |
                                   (unsigned char)data[9]);
    if (error_code < -1 || error_code > 120)
        return 0;

    if (msg_size + 4 < 8)
        return 0;

    return 1;
}

/* #10 fix: Extended Kafka API key names (covers all commonly used API keys) */
static const char *kafka_api_key_name(int api_key)
{
    switch (api_key) {
    case 0:  return "Produce";
    case 1:  return "Fetch";
    case 2:  return "ListOffsets";
    case 3:  return "Metadata";
    case 4:  return "LeaderAndIsr";
    case 5:  return "StopReplica";
    case 6:  return "UpdateMetadata";
    case 7:  return "ControlledShutdown";
    case 8:  return "OffsetCommit";
    case 9:  return "OffsetFetch";
    case 10: return "FindCoordinator";
    case 11: return "JoinGroup";
    case 12: return "Heartbeat";
    case 13: return "LeaveGroup";
    case 14: return "SyncGroup";
    case 15: return "DescribeGroups";
    case 16: return "ListGroups";
    case 17: return "SaslHandshake";
    case 18: return "ApiVersions";
    case 19: return "CreateTopics";
    case 20: return "DeleteTopics";
    case 21: return "DeleteRecords";
    case 22: return "InitProducerId";
    case 23: return "OffsetForLeaderEpoch";
    case 24: return "AddPartitionsToTxn";
    case 25: return "AddOffsetsToTxn";
    case 26: return "EndTxn";
    case 27: return "WriteTxnMarkers";
    case 28: return "TxnOffsetCommit";
    case 29: return "DescribeAcls";
    case 30: return "CreateAcls";
    case 31: return "DeleteAcls";
    case 32: return "DescribeConfigs";
    case 33: return "AlterConfigs";
    case 34: return "AlterReplicaLogDirs";
    case 35: return "DescribeLogDirs";
    case 36: return "SaslAuthenticate";
    case 37: return "CreatePartitions";
    case 38: return "CreateDelegationToken";
    case 39: return "RenewDelegationToken";
    case 40: return "ExpireDelegationToken";
    case 41: return "DescribeDelegationToken";
    case 42: return "DeleteGroups";
    case 43: return "ElectLeaders";
    case 44: return "IncrementalAlterConfigs";
    case 45: return "AlterPartitionReassignments";
    case 46: return "ListPartitionReassignments";
    case 47: return "OffsetDelete";
    case 48: return "DescribeClientQuotas";
    case 49: return "AlterClientQuotas";
    case 50: return "DescribeUserScramCredentials";
    case 51: return "AlterUserScramCredentials";
    case 56: return "AlterPartition";
    case 57: return "UpdateFeatures";
    case 60: return "DescribeCluster";
    case 61: return "DescribeProducers";
    case 65: return "DescribeTransactions";
    case 66: return "ListTransactions";
    case 67: return "AllocateProducerIds";
    default: return NULL;
    }
}

/* #7 fix: HTTP/2 RST_STREAM and GOAWAY error code parsing.
 * RST_STREAM (type 0x03): 9-byte header + 4-byte error code
 * GOAWAY (type 0x07): 9-byte header + 4-byte last_stream_id + 4-byte error code */
static int parse_h2_error_code(const char *data, __u32 len, int *frame_type_out)
{
    if (len < 13)
        return -1;

    __u8 frame_type = (unsigned char)data[3];
    __u32 frame_len = ((unsigned char)data[0] << 16) |
                      ((unsigned char)data[1] << 8) |
                      (unsigned char)data[2];

    *frame_type_out = frame_type;

    if (frame_type == 0x03 && frame_len == 4 && len >= 13) {
        /* RST_STREAM: error code at offset 9 */
        __u32 error_code = ((unsigned char)data[9] << 24) |
                           ((unsigned char)data[10] << 16) |
                           ((unsigned char)data[11] << 8) |
                           (unsigned char)data[12];
        return (int)error_code;
    }

    if (frame_type == 0x07 && frame_len >= 8 && len >= 17) {
        /* GOAWAY: last_stream_id at 9-12, error code at 13-16 */
        __u32 error_code = ((unsigned char)data[13] << 24) |
                           ((unsigned char)data[14] << 16) |
                           ((unsigned char)data[15] << 8) |
                           (unsigned char)data[16];
        return (int)error_code;
    }

    return -1;
}

static const char *h2_error_code_name(int code)
{
    switch (code) {
    case 0x0: return "NO_ERROR";
    case 0x1: return "PROTOCOL_ERROR";
    case 0x2: return "INTERNAL_ERROR";
    case 0x3: return "FLOW_CONTROL_ERROR";
    case 0x4: return "SETTINGS_TIMEOUT";
    case 0x5: return "STREAM_CLOSED";
    case 0x6: return "FRAME_SIZE_ERROR";
    case 0x7: return "REFUSED_STREAM";
    case 0x8: return "CANCEL";
    case 0x9: return "COMPRESSION_ERROR";
    case 0xa: return "CONNECT_ERROR";
    case 0xb: return "ENHANCE_YOUR_CALM";
    case 0xc: return "INADEQUATE_SECURITY";
    case 0xd: return "HTTP_1_1_REQUIRED";
    default:  return "UNKNOWN";
    }
}

/* #8 fix: Search for grpc-status in HTTP/2 frame payload.
 * grpc-status is not in the HPACK static table, so it's typically sent
 * as a literal. We scan for the raw bytes as a best-effort heuristic. */
static int parse_grpc_status_from_h2(const char *data, __u32 len)
{
    if (len < 18)
        return -1;

    const char *needle = "grpc-status";
    size_t needle_len = 11;
    const void *found = memmem(data, len, needle, needle_len);
    if (!found)
        return -1;

    const char *pos = (const char *)found + needle_len;
    const char *data_end = data + len;

    /* Skip HPACK encoding bytes or whitespace between name and value */
    while (pos < data_end && (*pos < '0' || *pos > '9') &&
           (size_t)(pos - (const char *)found) < needle_len + 4)
        pos++;

    if (pos < data_end && *pos >= '0' && *pos <= '9') {
        int code = *pos - '0';
        if (pos + 1 < data_end && *(pos + 1) >= '0' && *(pos + 1) <= '9')
            code = code * 10 + (*(pos + 1) - '0');
        if (code <= 16)
            return code;
    }

    return -1;
}

/* WebSocket frame parsing: extract close code from close frame (opcode 0x8) */
static int parse_websocket_close_code(const char *data, __u32 len)
{
    if (len < 2)
        return -1;

    __u8 opcode = (unsigned char)data[0] & 0x0F;
    if (opcode != 0x08)  /* Close frame */
        return -1;

    __u8 mask_bit = ((unsigned char)data[1] & 0x80) ? 1 : 0;
    __u8 payload_len = (unsigned char)data[1] & 0x7F;

    if (payload_len < 2)
        return -1;  /* No close code in payload */

    int offset = 2;
    __u8 masking_key[4] = {0};
    if (mask_bit) {
        if (len < (unsigned)(offset + 4))
            return -1;
        for (int i = 0; i < 4; i++)
            masking_key[i] = (unsigned char)data[offset + i];
        offset += 4;
    }

    if (len < (unsigned)(offset + 2))
        return -1;

    __u16 code;
    if (mask_bit) {
        __u8 b0 = (unsigned char)data[offset] ^ masking_key[0];
        __u8 b1 = (unsigned char)data[offset + 1] ^ masking_key[1];
        code = (b0 << 8) | b1;
    } else {
        code = ((unsigned char)data[offset] << 8) |
               (unsigned char)data[offset + 1];
    }

    return (int)code;
}

static void parse_http_info(const char *data, __u32 len, struct http_info *info)
{
    memset(info, 0, sizeof(*info));
    info->grpc_status = -1;  /* -1 = not present */
    if (len < 4)
        return;

    /* Check for HTTP response line: "HTTP/1.1 200 OK\r\n" (#6 fix: parse status code) */
    if (len >= 8 && strncmp(data, "HTTP/", 5) == 0) {
        const char *ver_start = data + 5;
        const char *ver_end = ver_start;
        const char *data_end = data + len;
        while (ver_end < data_end && *ver_end != ' ' && *ver_end != '\r')
            ver_end++;
        size_t ver_len = (size_t)(ver_end - ver_start);
        if (ver_len > 0 && ver_len < sizeof(info->version)) {
            strncpy(info->version, ver_start, ver_len);
            info->version[ver_len] = '\0';
        }
        /* Parse status code: "HTTP/1.1 200 OK" → 200 */
        if (ver_end < data_end && *ver_end == ' ') {
            const char *status_start = ver_end + 1;
            if (status_start + 3 <= data_end &&
                status_start[0] >= '1' && status_start[0] <= '5' &&
                status_start[1] >= '0' && status_start[1] <= '9' &&
                status_start[2] >= '0' && status_start[2] <= '9') {
                info->status_code = (status_start[0] - '0') * 100 +
                                    (status_start[1] - '0') * 10 +
                                    (status_start[2] - '0');
            }
        }
    }

    /* Check if data starts with an HTTP method */
    const char *methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "PATCH ",
                             "HEAD ", "OPTIONS ", "CONNECT ", NULL};
    int found = 0;
    for (int i = 0; methods[i]; i++) {
        size_t mlen = strlen(methods[i]);
        if (len >= mlen && strncmp(data, methods[i], mlen) == 0) {
            /* Copy method (without trailing space) */
            strncpy(info->method, methods[i], mlen - 1);
            info->method[mlen - 1] = '\0';

            /* Extract path: from after method to next space or \r\n */
            const char *path_start = data + mlen;
            const char *path_end = path_start;
            const char *data_end = data + len;
            while (path_end < data_end && *path_end != ' ' &&
                   *path_end != '\r' && *path_end != '\n')
                path_end++;
            size_t path_len = (size_t)(path_end - path_start);
            if (path_len >= sizeof(info->path))
                path_len = sizeof(info->path) - 1;
            strncpy(info->path, path_start, path_len);
            info->path[path_len] = '\0';
            found = 1;
            break;
        }
    }

    /* Extract HTTP version from request line if we found a method */
    if (found) {
        const char *http_ver = NULL;
        const char *s = data;
        const char *s_end = data + len;
        /* Scan for "HTTP/" in the request line (before first \r\n) */
        for (; s < s_end - 8; s++) {
            if (*s == '\r' || *s == '\n')
                break;
            if (strncmp(s, "HTTP/", 5) == 0) {
                http_ver = s + 5;
                break;
            }
        }
        if (http_ver) {
            const char *ver_end = http_ver;
            while (ver_end < s_end && *ver_end != '\r' && *ver_end != '\n' && *ver_end != ' ')
                ver_end++;
            size_t ver_len = (size_t)(ver_end - http_ver);
            if (ver_len >= sizeof(info->version))
                ver_len = sizeof(info->version) - 1;
            strncpy(info->version, http_ver, ver_len);
            info->version[ver_len] = '\0';
        }
    }

    /* For responses (HTTP/x.x status line), we still parse headers below */
    if (!found && !info->version[0])
        return;

    /* Scan headers for Host and Upgrade: websocket */
    const char *p = data;
    const char *end = data + len;
    const char *host_hdr = NULL;
    while (p < end - 6) {
        if (*p == '\n' || p == data) {
            const char *hdr = p + (p == data ? 0 : 1);
            size_t remaining = (size_t)(end - hdr);

            if (remaining >= 5 && strncasecmp(hdr, "Host:", 5) == 0) {
                host_hdr = hdr + 5;
                while (host_hdr < end && (*host_hdr == ' ' || *host_hdr == '\t'))
                    host_hdr++;
            } else if (remaining >= 11 && strncasecmp(hdr, "User-Agent:", 11) == 0) {
                const char *val = hdr + 11;
                while (val < end && (*val == ' ' || *val == '\t'))
                    val++;
                const char *val_end = val;
                while (val_end < end && *val_end != '\r' && *val_end != '\n')
                    val_end++;
                size_t ua_len = (size_t)(val_end - val);
                if (ua_len >= sizeof(info->user_agent))
                    ua_len = sizeof(info->user_agent) - 1;
                strncpy(info->user_agent, val, ua_len);
                info->user_agent[ua_len] = '\0';
            } else if (remaining >= 8 && strncasecmp(hdr, "Upgrade:", 8) == 0) {
                const char *val = hdr + 8;
                while (val < end && (*val == ' ' || *val == '\t'))
                    val++;
                if ((size_t)(end - val) >= 9 && strncasecmp(val, "websocket", 9) == 0)
                    info->websocket = 1;
            } else if (remaining >= 12 && strncasecmp(hdr, "grpc-status:", 12) == 0) {
                const char *val = hdr + 12;
                while (val < end && (*val == ' ' || *val == '\t'))
                    val++;
                if (val < end && *val >= '0' && *val <= '9') {
                    int code = *val - '0';
                    if (val + 1 < end && *(val + 1) >= '0' && *(val + 1) <= '9')
                        code = code * 10 + (*(val + 1) - '0');
                    info->grpc_status = code;
                }
            }
        }
        p++;
    }

    if (host_hdr) {
        const char *host_end = host_hdr;
        while (host_end < end && *host_end != '\r' && *host_end != '\n')
            host_end++;
        size_t host_len = (size_t)(host_end - host_hdr);
        if (host_len >= sizeof(info->host))
            host_len = sizeof(info->host) - 1;
        strncpy(info->host, host_hdr, host_len);
        info->host[host_len] = '\0';
    }
}

/* Print a JSON string value, escaping special characters.
 * For length-bounded strings (e.g. comm from kernel), use maxlen > 0
 * to avoid reading past the buffer. If maxlen == 0, reads until NUL. */
static void print_json_string_n(const char *s, size_t maxlen)
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
                printf("\\x%02x", (unsigned char)*s);
        }
    }
    putchar('"');
}

/* Print a NUL-terminated JSON string value, escaping special characters */
static void print_json_string(const char *s)
{
    print_json_string_n(s, 0);
}

static void handle_event(void *ctx, int cpu __attribute__((unused)),
                         void *data, __u32 size)
{
    struct tls_event_t *event = data;
    struct config *c = ctx;

    if (size < sizeof(*event) - MAX_DATA_LEN)
        return;

    /* Apply filters */
    if (c->filter_pid && event->pid != c->filter_pid)
        return;
    if (c->filter_uid && event->uid != c->filter_uid)
        return;

    __u32 data_len = event->data_len;
    if (data_len > MAX_DATA_LEN)
        data_len = MAX_DATA_LEN;

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
                   "\"pid\":%u,\"tid\":%u,\"comm\":",
                   iso_time, ts.tv_nsec / 1000,
                   (unsigned long long)event->timestamp_ns,
                   event->pid, event->tid);
            print_json_string_n(event->comm, MAX_COMM_LEN);
            printf(",\"event_type\":\"tcp_error\","
                   "\"dst_ip\":\"%s\",\"dst_port\":%u,"
                   "\"error_code\":%d,\"error\":\"%s\"}\n",
                   remote_ip, event->remote_port,
                   ecode, err_desc);
            fflush(stdout);
            return;
        }

        /* Handle TLS close events (#3 fix) */
        if (event->event_type == EVENT_TLS_CLOSE) {
            const char *tls_ver_str = NULL;
            switch (event->tls_version) {
            case 0x0301: tls_ver_str = "1.0"; break;
            case 0x0302: tls_ver_str = "1.1"; break;
            case 0x0303: tls_ver_str = "1.2"; break;
            case 0x0304: tls_ver_str = "1.3"; break;
            default: break;
            }

            printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
                   "\"pid\":%u,\"tid\":%u,\"comm\":",
                   iso_time, ts.tv_nsec / 1000,
                   (unsigned long long)event->timestamp_ns,
                   event->pid, event->tid);
            print_json_string_n(event->comm, MAX_COMM_LEN);
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
            fflush(stdout);
            return;
        }

        /* Handle TLS error events */
        if (event->event_type == EVENT_TLS_ERROR) {
            const char *tls_ver_str = NULL;
            switch (event->tls_version) {
            case 0x0301: tls_ver_str = "1.0"; break;
            case 0x0302: tls_ver_str = "1.1"; break;
            case 0x0303: tls_ver_str = "1.2"; break;
            case 0x0304: tls_ver_str = "1.3"; break;
            default: break;
            }

            printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
                   "\"pid\":%u,\"tid\":%u,\"comm\":",
                   iso_time, ts.tv_nsec / 1000,
                   (unsigned long long)event->timestamp_ns,
                   event->pid, event->tid);
            print_json_string_n(event->comm, MAX_COMM_LEN);
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
            fflush(stdout);
            return;
        }

        /* Handle QUIC detection events */
        if (event->event_type == EVENT_QUIC_DETECTED) {
            printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
                   "\"pid\":%u,\"tid\":%u,\"comm\":",
                   iso_time, ts.tv_nsec / 1000,
                   (unsigned long long)event->timestamp_ns,
                   event->pid, event->tid);
            print_json_string_n(event->comm, MAX_COMM_LEN);
            printf(",\"event_type\":\"quic_detected\","
                   "\"src_ip\":\"%s\",\"src_port\":%u,"
                   "\"dst_ip\":\"%s\",\"dst_port\":%u,"
                   "\"transport\":\"udp\",\"protocol\":\"quic\"}\n",
                   local_ip, event->local_port,
                   remote_ip, event->remote_port);
            fflush(stdout);
            return;
        }

        /* K8s metadata enrichment */
        struct k8s_meta meta;
        get_k8s_meta((pid_t)event->pid, &meta);

        /* HTTP Layer 7 parsing (both directions — WRITE for requests, READ for responses) */
        struct http_info http;
        memset(&http, 0, sizeof(http));
        if (data_len > 0)
            parse_http_info(event->data, data_len, &http);

        /* Apply sanitization patterns to HTTP fields */
        if (http.path[0])
            sanitize_string(http.path, sizeof(http.path));
        if (http.host[0])
            sanitize_string(http.host, sizeof(http.host));

        /* Emit one self-contained JSON event */
        printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
               "\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
               iso_time, ts.tv_nsec / 1000,
               (unsigned long long)event->timestamp_ns,
               event->pid, event->tid, event->uid);
        print_json_string_n(event->comm, MAX_COMM_LEN);
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

        /* 1. Detect HTTP/2 connection preface (client→server first write)
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
                l7_proto = "https";  /* HTTP/2 but not gRPC → HTTPS */
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

        /* 8. Detect Kafka wire protocol (binary header structure) */
        int kafka_api_key = -1;
        if (strcmp(l7_proto, "unknown") == 0 &&
            detect_kafka_protocol(event->data, data_len, &kafka_api_key))
            l7_proto = "kafka";

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
        const char *tls_ver_str = NULL;
        switch (event->tls_version) {
        case 0x0301: tls_ver_str = "1.0"; break;
        case 0x0302: tls_ver_str = "1.1"; break;
        case 0x0303: tls_ver_str = "1.2"; break;
        case 0x0304: tls_ver_str = "1.3"; break;
        default: break;
        }
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

        printf(",\"transport\":\"tls\",\"protocol\":\"%s\"", l7_proto);

        /* HTTP version: from request line or inferred from HTTP/2 detection */
        if (is_http2)
            printf(",\"http_version\":\"2\"");
        else if (http.version[0])
            printf(",\"http_version\":\"%s\"", http.version);

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

        /* #9 fix: Kafka response frame detection */
        if (kafka_api_key < 0 && strcmp(l7_proto, "unknown") == 0 &&
            detect_kafka_response(event->data, data_len)) {
            l7_proto = "kafka";
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

    fflush(stdout);
}

static void handle_lost_events(void *ctx, int cpu, unsigned long long cnt)
{
    (void)ctx;
    fprintf(stderr, "WARNING: Lost %llu events on CPU %d\n", cnt, cpu);
}

static int find_ssl_library(char *path, size_t path_len)
{
    const char *candidates[] = {
        /* Debian/Ubuntu */
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        /* RHEL/AL2023/Fedora */
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        /* Generic */
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib64/libssl.so.3",
        NULL,
    };

    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], R_OK) == 0) {
            snprintf(path, path_len, "%s", candidates[i]);
            return 0;
        }
    }
    return -1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "eBPF-based TLS traffic interceptor. Captures plaintext data\n"
        "from SSL_read/SSL_write calls in OpenSSL, along with the\n"
        "remote IP address and port of each connection.\n"
        "\n"
        "Options:\n"
        "  -p, --pid PID          Filter by process ID\n"
        "  -u, --uid UID          Filter by user ID\n"
        "  -l, --lib PATH         Path to libssl.so (auto-detected by default)\n"
        "  -f, --format FMT       Output format: text (default) or json\n"
        "  -x, --hex              Show hex dump of captured data\n"
        "  -d, --data-only        Print only captured data (no headers)\n"
        "  -s, --sanitize REGEX   Sanitize URLs matching REGEX (case-insensitive, repeatable)\n"
        "  -v, --verbose          Verbose output\n"
        "  -h, --help             Show this help message\n"
        "\n"
        "Examples:\n"
        "  %s                     Trace all TLS traffic\n"
        "  %s -p 1234             Trace TLS traffic for PID 1234\n"
        "  %s -f json             Output in JSON format\n"
        "  %s -x -p 1234          Hex dump of TLS data for PID 1234\n"
        "  %s -s 'apikey=[^&]*'   Redact API keys from logged URLs\n"
        "\n"
        "Requires root privileges (or CAP_BPF + CAP_PERFMON).\n",
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *links[MAX_PROBES] = {0};
    struct perf_buffer *pb = NULL;
    int err = 0;
    int link_count = 0;

    static const struct option long_opts[] = {
        {"pid",       required_argument, NULL, 'p'},
        {"uid",       required_argument, NULL, 'u'},
        {"lib",       required_argument, NULL, 'l'},
        {"format",    required_argument, NULL, 'f'},
        {"hex",       no_argument,       NULL, 'x'},
        {"data-only", no_argument,       NULL, 'd'},
        {"sanitize",  required_argument, NULL, 's'},
        {"verbose",   no_argument,       NULL, 'v'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:u:l:f:xds:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': {
            char *endp;
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val == 0 || val > UINT_MAX) {
                fprintf(stderr, "Error: Invalid PID '%s'\n", optarg);
                return 1;
            }
            cfg.filter_pid = (__u32)val;
            break;
        }
        case 'u': {
            char *endp;
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val > UINT_MAX) {
                fprintf(stderr, "Error: Invalid UID '%s'\n", optarg);
                return 1;
            }
            cfg.filter_uid = (__u32)val;
            break;
        }
        case 'l':
            snprintf(cfg.ssl_lib, sizeof(cfg.ssl_lib), "%s", optarg);
            break;
        case 'f':
            if (strcmp(optarg, "json") == 0)
                cfg.format = FMT_JSON;
            else if (strcmp(optarg, "text") == 0)
                cfg.format = FMT_TEXT;
            else {
                fprintf(stderr, "Error: Unknown format '%s' (use 'text' or 'json')\n", optarg);
                return 1;
            }
            break;
        case 'x':
            cfg.hex_dump = 1;
            break;
        case 'd':
            cfg.data_only = 1;
            break;
        case 's':
            if (add_sanitize_pattern(optarg) != 0)
                return 1;
            break;
        case 'v':
            cfg.verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Check for root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This tool requires root privileges.\n");
        fprintf(stderr, "Run with: sudo %s\n", argv[0]);
        return 1;
    }

    /* Find SSL library */
    if (cfg.ssl_lib[0] == '\0') {
        if (find_ssl_library(cfg.ssl_lib, sizeof(cfg.ssl_lib)) != 0) {
            fprintf(stderr, "Error: Could not find libssl.so. Specify with --lib PATH.\n");
            return 1;
        }
    } else {
        if (access(cfg.ssl_lib, R_OK) != 0) {
            fprintf(stderr, "Error: Cannot access SSL library at '%s': %s\n",
                    cfg.ssl_lib, strerror(errno));
            return 1;
        }
    }

    if (cfg.verbose)
        fprintf(stderr, "Using SSL library: %s\n", cfg.ssl_lib);

    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open and load BPF object.
     * Search order: installed path first, then CWD fallback for development.
     * Using an absolute path prevents loading a malicious .o from CWD (S5 fix). */
    const char *bpf_obj_paths[] = {
        "/usr/local/lib/tls_tracer/bpf_program.o",
        "/opt/tls_tracer/bpf_program.o",
        "bpf_program.o",
        NULL,
    };
    const char *bpf_obj_path = NULL;
    for (int i = 0; bpf_obj_paths[i]; i++) {
        if (access(bpf_obj_paths[i], R_OK) == 0) {
            bpf_obj_path = bpf_obj_paths[i];
            break;
        }
    }
    if (!bpf_obj_path) {
        fprintf(stderr, "Error: Cannot find bpf_program.o in any search path\n");
        return 1;
    }
    if (cfg.verbose)
        fprintf(stderr, "Loading BPF object: %s\n", bpf_obj_path);

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "Error: Failed to open BPF object file '%s': %s\n",
                bpf_obj_path, strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF object: %s\n",
                strerror(-err));
        goto cleanup;
    }

    if (cfg.verbose)
        fprintf(stderr, "BPF object loaded successfully.\n");

    /* Attach kprobes for connection tracking (connect syscall + tcp_set_state) */
    const char *kprobe_names[] = {
        "probe_connect_enter",
        "probe_connect_return",
        "probe_tcp_set_state",
        "probe_udp_sendmsg",
    };

    for (int i = 0; i < 4; i++) {
        prog = bpf_object__find_program_by_name(obj, kprobe_names[i]);
        if (!prog) {
            if (cfg.verbose)
                fprintf(stderr, "Note: kprobe '%s' not found, IP tracking may be limited.\n",
                        kprobe_names[i]);
            continue;
        }

        links[link_count] = bpf_program__attach(prog);
        if (!links[link_count] || libbpf_get_error(links[link_count])) {
            links[link_count] = NULL;
            if (cfg.verbose)
                fprintf(stderr, "Warning: Could not attach kprobe '%s': IP tracking may be limited.\n",
                        kprobe_names[i]);
            continue;
        }
        link_count++;
        if (cfg.verbose)
            fprintf(stderr, "Attached kprobe: %s\n", kprobe_names[i]);
    }

    /* Attach uprobes to SSL functions */
    const char *uprobe_names[] = {
        "probe_ssl_read_enter",
        "probe_ssl_read_return",
        "probe_ssl_write_enter",
        "probe_ssl_write_return",
        "probe_ssl_version_enter",
        "probe_ssl_version_return",
        "probe_ssl_get_cipher_enter",
        "probe_ssl_get_cipher_return",
        "probe_ssl_get_cert_enter",
        "probe_ssl_get_cert_return",
    };
    int is_retprobe[] = {0, 1, 0, 1, 0, 1, 0, 1, 0, 1};
    const char *func_names[] = {
        "SSL_read",
        "SSL_read",
        "SSL_write",
        "SSL_write",
        "SSL_version",
        "SSL_version",
        "SSL_get_current_cipher",
        "SSL_get_current_cipher",
        "SSL_get_certificate",
        "SSL_get_certificate",
    };

    int uprobe_count = 0;
    for (int i = 0; i < 10; i++) {
        prog = bpf_object__find_program_by_name(obj, uprobe_names[i]);
        if (!prog) {
            fprintf(stderr, "Error: BPF program '%s' not found in object.\n",
                    uprobe_names[i]);
            err = 1;
            goto cleanup;
        }

        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
            .retprobe = is_retprobe[i],
            .func_name = func_names[i],
        );

        links[link_count] = bpf_program__attach_uprobe_opts(
            prog, -1, cfg.ssl_lib, 0, &uprobe_opts);

        if (!links[link_count] || libbpf_get_error(links[link_count])) {
            links[link_count] = NULL;
            fprintf(stderr, "Warning: Could not attach uprobe for %s (%s). "
                    "Ensure libssl has debug symbols or is not stripped.\n",
                    func_names[i], is_retprobe[i] ? "return" : "entry");
            continue;
        }
        link_count++;
        uprobe_count++;
    }

    if (uprobe_count == 0) {
        fprintf(stderr, "Error: Could not attach any SSL probes. "
                "Check that the SSL library path is correct and has symbols.\n");
        err = 1;
        goto cleanup;
    }

    if (cfg.verbose)
        fprintf(stderr, "Attached %d/%d SSL probes.\n", uprobe_count, 10);

    /* Set up perf buffer */
    int map_fd = bpf_object__find_map_fd_by_name(obj, "tls_events");
    if (map_fd < 0) {
        fprintf(stderr, "Error: Could not find 'tls_events' map in BPF object.\n");
        err = 1;
        goto cleanup;
    }

    pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGES, handle_event,
                          handle_lost_events, &cfg, NULL);
    if (!pb) {
        fprintf(stderr, "Error: Failed to create perf buffer: %s\n",
                strerror(errno));
        err = 1;
        goto cleanup;
    }

    /* Print startup banner */
    if (!cfg.data_only && cfg.format == FMT_TEXT) {
        fprintf(stderr, "Tracing TLS traffic");
        if (cfg.filter_pid)
            fprintf(stderr, " for PID %u", cfg.filter_pid);
        if (cfg.filter_uid)
            fprintf(stderr, " for UID %u", cfg.filter_uid);
        fprintf(stderr, "... Press Ctrl+C to stop.\n");
    }

    /* Touch health file to signal readiness */
    /* Use a dedicated path for health file to prevent spoofing via /tmp (S4 fix).
     * Falls back to /tmp if the directory doesn't exist (e.g., local dev). */
    const char *health_file = "/var/run/tls-tracer/healthy";
    if (access("/var/run/tls-tracer", F_OK) != 0) {
        if (mkdir("/var/run/tls-tracer", 0755) != 0)
            health_file = "/tmp/tls_tracer_healthy";  /* fallback */
    }
    FILE *hf = fopen(health_file, "w");
    if (hf) {
        fprintf(hf, "ready\n");
        fclose(hf);
    }

    /* Main event loop (#1 fix: don't mask poll errors) */
    int poll_count = 0;
    while (!exiting) {
        int poll_err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT);
        if (poll_err < 0 && poll_err != -EINTR) {
            fprintf(stderr, "Error: Polling perf buffer failed: %s\n",
                    strerror(-poll_err));
            err = poll_err;
            break;
        }

        /* Update health file every ~10 seconds (100ms poll * 100) */
        if (++poll_count >= 100) {
            poll_count = 0;
            hf = fopen(health_file, "w");
            if (hf) {
                fprintf(hf, "%ld\n", (long)time(NULL));
                fclose(hf);
            }
        }
    }

    /* Remove health file on shutdown */
    unlink(health_file);

    if (cfg.verbose)
        fprintf(stderr, "\nExiting...\n");

cleanup:
    if (pb)
        perf_buffer__free(pb);
    for (int i = 0; i < link_count; i++) {
        if (links[i])
            bpf_link__destroy(links[i]);
    }
    if (obj)
        bpf_object__close(obj);

    /* #2 fix: POSIX convention — exit with 128+signum on signal termination */
    if (exit_signal)
        return 128 + (int)exit_signal;
    return err != 0 ? 1 : 0;
}
