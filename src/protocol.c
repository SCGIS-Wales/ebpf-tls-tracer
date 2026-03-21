// SPDX-License-Identifier: MIT
//
// Protocol detection and parsing: HTTP/1.x, HTTP/2, Kafka, gRPC, WebSocket.
// All functions are pure (no global state, no side effects).

#define _GNU_SOURCE  /* for memmem() */
#include <stdio.h>    /* snprintf */
#include <string.h>
#include <strings.h>  /* strncasecmp */
#include <ctype.h>
#include "protocol.h"

/* Kafka wire protocol detection: check if data matches Kafka request header.
 * Kafka request header: message_size(4) + api_key(2) + api_version(2) + correlation_id(4) + client_id_len(2)
 * Minimum 14 bytes. */
int detect_kafka_protocol(const char *data, __u32 len, int *api_key)
{
    if (len < 14)
        return 0;

    /* Read message_size (4 bytes, big-endian) */
    __u32 msg_size = ((unsigned int)(unsigned char)data[0] << 24) |
                     ((unsigned int)(unsigned char)data[1] << 16) |
                     ((unsigned int)(unsigned char)data[2] << 8) |
                     (unsigned char)data[3];

    /* Sanity: 4 < msg_size < 100MB, and msg_size + 4 should be close to data len */
    if (msg_size <= 4 || msg_size > MAX_KAFKA_MESSAGE_SIZE)
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

    /* Read correlation_id (4 bytes) — must be > 0.
     * Issue 3 fix: Require correlation_id > 0 (not just >= 0) to reduce
     * false positives from HTTP/2 binary frames where the bytes at this
     * offset are often 0. Real Kafka clients use correlation_id starting
     * from 1, incrementing per request. */
    int corr_id = (int)(((unsigned int)(unsigned char)data[8] << 24) |
                        ((unsigned int)(unsigned char)data[9] << 16) |
                        ((unsigned int)(unsigned char)data[10] << 8) |
                        (unsigned char)data[11]);
    if (corr_id <= 0)
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
int detect_kafka_response(const char *data, __u32 len)
{
    if (len < 12)
        return 0;

    __u32 msg_size = ((unsigned int)(unsigned char)data[0] << 24) |
                     ((unsigned int)(unsigned char)data[1] << 16) |
                     ((unsigned int)(unsigned char)data[2] << 8) |
                     (unsigned char)data[3];

    if (msg_size <= 4 || msg_size > MAX_KAFKA_MESSAGE_SIZE)
        return 0;

    int corr_id = (int)(((unsigned int)(unsigned char)data[4] << 24) |
                        ((unsigned int)(unsigned char)data[5] << 16) |
                        ((unsigned int)(unsigned char)data[6] << 8) |
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
const char *kafka_api_key_name(int api_key)
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
int parse_h2_error_code(const char *data, __u32 len, int *frame_type_out)
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
        __u32 error_code = ((unsigned int)(unsigned char)data[9] << 24) |
                           ((unsigned int)(unsigned char)data[10] << 16) |
                           ((unsigned int)(unsigned char)data[11] << 8) |
                           (unsigned char)data[12];
        return (int)error_code;
    }

    if (frame_type == 0x07 && frame_len >= 8 && len >= 17) {
        /* GOAWAY: last_stream_id at 9-12, error code at 13-16 */
        __u32 error_code = ((unsigned int)(unsigned char)data[13] << 24) |
                           ((unsigned int)(unsigned char)data[14] << 16) |
                           ((unsigned int)(unsigned char)data[15] << 8) |
                           (unsigned char)data[16];
        return (int)error_code;
    }

    return -1;
}

const char *h2_error_code_name(int code)
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
int parse_grpc_status_from_h2(const char *data, __u32 len)
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
int parse_websocket_close_code(const char *data, __u32 len)
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

void parse_http_info(const char *data, __u32 len, struct http_info *info)
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
        if (ver_len > 0 && ver_len < sizeof(info->version))
            snprintf(info->version, sizeof(info->version), "%.*s", (int)ver_len, ver_start);
        /* Parse status code: "HTTP/1.1 200 OK" -> 200 */
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
            /* M-1 fix: use snprintf instead of strncpy for guaranteed NUL-termination */
            snprintf(info->method, sizeof(info->method), "%.*s", (int)(mlen - 1), methods[i]);

            /* Extract path: from after method to next space or \r\n */
            const char *path_start = data + mlen;
            const char *path_end = path_start;
            const char *data_end = data + len;
            while (path_end < data_end && *path_end != ' ' &&
                   *path_end != '\r' && *path_end != '\n')
                path_end++;
            size_t path_len = (size_t)(path_end - path_start);
            snprintf(info->path, sizeof(info->path), "%.*s", (int)path_len, path_start);
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
            snprintf(info->version, sizeof(info->version), "%.*s", (int)ver_len, http_ver);
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
                snprintf(info->user_agent, sizeof(info->user_agent), "%.*s", (int)ua_len, val);
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
        snprintf(info->host, sizeof(info->host), "%.*s", (int)host_len, host_hdr);
    }
}
