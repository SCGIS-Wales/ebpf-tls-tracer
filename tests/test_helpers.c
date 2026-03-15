// SPDX-License-Identifier: MIT
//
// Unit tests for TLS Tracer helper functions:
//   - JSON output correctness (print_json_string_n)
//   - HTTP parsing (parse_http_info)
//   - Kafka protocol detection
//   - Sanitization regex
//   - IPv6/IPv4 address formatting
//   - Edge cases (zero-length data, max-length strings)
//
// These functions are static in tls_tracer.c, so we copy their
// implementations here for isolated unit testing without libbpf deps.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <arpa/inet.h>
#include <assert.h>
#include "tracer.h"

/* ===== Test framework ===== */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { tests_run++; printf("  TEST  %-55s", #name); } while (0)
#define PASS() do { tests_passed++; printf(" PASS\n"); } while (0)
#define FAIL(msg) do { printf(" FAIL: %s\n", msg); return; } while (0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); } } while (0)
#define ASSERT_STR_EQ(a, b, msg) do { if (strcmp((a), (b)) != 0) { FAIL(msg); } } while (0)
#define ASSERT_STR_CONTAINS(haystack, needle, msg) \
    do { if (strstr((haystack), (needle)) == NULL) { FAIL(msg); } } while (0)
#define ASSERT_TRUE(expr, msg) do { if (!(expr)) { FAIL(msg); } } while (0)

/* ===== Copied function implementations from tls_tracer.c ===== */

/* --- JSON string escaping --- */
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
                printf("\\u%04x", (unsigned char)*s);
        }
    }
    putchar('"');
}

static void print_json_string(const char *s)
{
    print_json_string_n(s, 0);
}

/* --- HTTP parsing --- */
struct http_info {
    char method[16];
    char path[512];
    char host[256];
    char user_agent[256];
    char version[16];
    int  status_code;
    int  websocket;
    int  grpc_status;
};

static void parse_http_info(const char *data, __u32 len, struct http_info *info)
{
    memset(info, 0, sizeof(*info));
    info->grpc_status = -1;
    if (len < 4)
        return;

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

    const char *methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "PATCH ",
                             "HEAD ", "OPTIONS ", "CONNECT ", NULL};
    int found = 0;
    for (int i = 0; methods[i]; i++) {
        size_t mlen = strlen(methods[i]);
        if (len >= mlen && strncmp(data, methods[i], mlen) == 0) {
            strncpy(info->method, methods[i], mlen - 1);
            info->method[mlen - 1] = '\0';

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

    if (found) {
        const char *http_ver = NULL;
        const char *s = data;
        const char *s_end = data + len;
        for (; s < s_end - 8; s++) {
            if (*s == '\r' || *s == '\n') break;
            if (strncmp(s, "HTTP/", 5) == 0) { http_ver = s + 5; break; }
        }
        if (http_ver) {
            const char *ver_end = http_ver;
            while (ver_end < s_end && *ver_end != '\r' && *ver_end != '\n' && *ver_end != ' ')
                ver_end++;
            size_t ver_len = (size_t)(ver_end - http_ver);
            if (ver_len >= sizeof(info->version)) ver_len = sizeof(info->version) - 1;
            strncpy(info->version, http_ver, ver_len);
            info->version[ver_len] = '\0';
        }
    }

    if (!found && !info->version[0])
        return;

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
                while (val < end && (*val == ' ' || *val == '\t')) val++;
                const char *val_end = val;
                while (val_end < end && *val_end != '\r' && *val_end != '\n') val_end++;
                size_t ua_len = (size_t)(val_end - val);
                if (ua_len >= sizeof(info->user_agent)) ua_len = sizeof(info->user_agent) - 1;
                strncpy(info->user_agent, val, ua_len);
                info->user_agent[ua_len] = '\0';
            } else if (remaining >= 8 && strncasecmp(hdr, "Upgrade:", 8) == 0) {
                const char *val = hdr + 8;
                while (val < end && (*val == ' ' || *val == '\t')) val++;
                if ((size_t)(end - val) >= 9 && strncasecmp(val, "websocket", 9) == 0)
                    info->websocket = 1;
            } else if (remaining >= 12 && strncasecmp(hdr, "grpc-status:", 12) == 0) {
                const char *val = hdr + 12;
                while (val < end && (*val == ' ' || *val == '\t')) val++;
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
        while (host_end < end && *host_end != '\r' && *host_end != '\n') host_end++;
        size_t host_len = (size_t)(host_end - host_hdr);
        if (host_len >= sizeof(info->host)) host_len = sizeof(info->host) - 1;
        strncpy(info->host, host_hdr, host_len);
        info->host[host_len] = '\0';
    }
}

/* --- Kafka detection --- */
static int detect_kafka_protocol(const char *data, __u32 len, int *api_key)
{
    if (len < 14) return 0;
    __u32 msg_size = ((unsigned char)data[0] << 24) | ((unsigned char)data[1] << 16) |
                     ((unsigned char)data[2] << 8) | (unsigned char)data[3];
    if (msg_size <= 4 || msg_size > 104857600) return 0;
    int ak = (int)(short)(((unsigned char)data[4] << 8) | (unsigned char)data[5]);
    if (ak < 0 || ak > 74) return 0;
    int av = (int)(short)(((unsigned char)data[6] << 8) | (unsigned char)data[7]);
    if (av < 0 || av > 20) return 0;
    /* H-3 fix: corr_id must be > 0 (not just >= 0) to match tls_tracer.c.
     * Issue 3 fix: correlation_id == 0 causes false positives from HTTP/2 frames. */
    int corr_id = (int)(((unsigned char)data[8] << 24) | ((unsigned char)data[9] << 16) |
                        ((unsigned char)data[10] << 8) | (unsigned char)data[11]);
    if (corr_id <= 0) return 0;
    int cid_len = (int)(short)(((unsigned char)data[12] << 8) | (unsigned char)data[13]);
    if (cid_len < -1 || cid_len > 1024) return 0;
    if (cid_len > 0 && len < (unsigned)(14 + cid_len)) return 0;
    *api_key = (int)ak;
    return 1;
}

static int detect_kafka_response(const char *data, __u32 len)
{
    if (len < 12) return 0;
    __u32 msg_size = ((unsigned char)data[0] << 24) | ((unsigned char)data[1] << 16) |
                     ((unsigned char)data[2] << 8) | (unsigned char)data[3];
    if (msg_size <= 4 || msg_size > 104857600) return 0;
    int corr_id = (int)(((unsigned char)data[4] << 24) | ((unsigned char)data[5] << 16) |
                        ((unsigned char)data[6] << 8) | (unsigned char)data[7]);
    if (corr_id < 0) return 0;
    int error_code = (int)(short)(((unsigned char)data[8] << 8) | (unsigned char)data[9]);
    if (error_code < -1 || error_code > 120) return 0;
    if (msg_size + 4 < 8) return 0;
    return 1;
}

/* --- Sanitize --- */
#define MAX_SANITIZE_PATTERNS 32
struct sanitize_pattern {
    regex_t regex;
    char original[256];
};

struct test_config {
    struct sanitize_pattern sanitize[MAX_SANITIZE_PATTERNS];
    int sanitize_count;
};

static struct test_config test_cfg = { .sanitize_count = 0 };

static int add_test_sanitize_pattern(const char *pattern)
{
    if (test_cfg.sanitize_count >= MAX_SANITIZE_PATTERNS) return -1;
    struct sanitize_pattern *sp = &test_cfg.sanitize[test_cfg.sanitize_count];
    int ret = regcomp(&sp->regex, pattern, REG_EXTENDED | REG_ICASE);
    if (ret != 0) return -1;
    snprintf(sp->original, sizeof(sp->original), "%s", pattern);
    test_cfg.sanitize_count++;
    return 0;
}

static void sanitize_string(char *str, size_t len)
{
    if (test_cfg.sanitize_count == 0 || !str || !str[0])
        return;
    for (int i = 0; i < test_cfg.sanitize_count; i++) {
        regmatch_t match;
        char *p = str;
        while (regexec(&test_cfg.sanitize[i].regex, p, 1, &match, 0) == 0) {
            size_t match_start = (size_t)(p - str) + (size_t)match.rm_so;
            size_t match_len = (size_t)(match.rm_eo - match.rm_so);
            const char *redacted = "[REDACTED]";
            size_t redacted_len = 10;
            if (match_len == 0) break;
            size_t current_len = strlen(str);
            if (current_len - match_len + redacted_len >= len) break;
            memmove(str + match_start + redacted_len,
                    str + match_start + match_len,
                    current_len - match_start - match_len + 1);
            memcpy(str + match_start, redacted, redacted_len);
            p = str + match_start + redacted_len;
        }
    }
}

/* --- Address formatting --- */
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

/* ===== Helper: capture stdout output from a function ===== */
static char *capture_stdout(void (*fn)(const char *, size_t), const char *arg, size_t maxlen)
{
    char *buf = NULL;
    size_t buf_size = 0;
    FILE *stream = open_memstream(&buf, &buf_size);
    if (!stream) return NULL;

    /* Redirect stdout to our memory stream */
    FILE *old_stdout = stdout;
    stdout = stream;
    fn(arg, maxlen);
    stdout = old_stdout;

    fflush(stream);
    fclose(stream);
    return buf;
}

/* ===== JSON output tests ===== */

static void test_json_simple_string(void)
{
    TEST(json_simple_string);
    char *out = capture_stdout(print_json_string_n, "hello", 0);
    ASSERT_STR_EQ(out, "\"hello\"", "simple string");
    free(out);
    PASS();
}

static void test_json_escape_quotes(void)
{
    TEST(json_escape_quotes);
    char *out = capture_stdout(print_json_string_n, "say \"hello\"", 0);
    ASSERT_STR_EQ(out, "\"say \\\"hello\\\"\"", "escaped quotes");
    free(out);
    PASS();
}

static void test_json_escape_backslash(void)
{
    TEST(json_escape_backslash);
    char *out = capture_stdout(print_json_string_n, "path\\to\\file", 0);
    ASSERT_STR_EQ(out, "\"path\\\\to\\\\file\"", "escaped backslashes");
    free(out);
    PASS();
}

static void test_json_escape_newline_tab(void)
{
    TEST(json_escape_newline_tab);
    char *out = capture_stdout(print_json_string_n, "line1\nline2\ttab", 0);
    ASSERT_STR_EQ(out, "\"line1\\nline2\\ttab\"", "escaped control chars");
    free(out);
    PASS();
}

static void test_json_escape_carriage_return(void)
{
    TEST(json_escape_carriage_return);
    char *out = capture_stdout(print_json_string_n, "line1\r\nline2", 0);
    ASSERT_STR_EQ(out, "\"line1\\r\\nline2\"", "escaped CR+LF");
    free(out);
    PASS();
}

static void test_json_escape_nonprintable_uses_unicode(void)
{
    TEST(json_escape_nonprintable_unicode);
    /* J-1/S-3 fix: non-printable must use \uXXXX, not \xNN */
    char input[] = {'\x01', '\x7f', '\0'};
    char *out = capture_stdout(print_json_string_n, input, 0);
    /* Should produce \u0001 and \u007f, NOT \x01 and \x7f */
    ASSERT_STR_CONTAINS(out, "\\u0001", "byte 0x01 escaped as \\u0001");
    ASSERT_STR_CONTAINS(out, "\\u007f", "byte 0x7f escaped as \\u007f");
    /* Verify NO \x sequences */
    ASSERT_TRUE(strstr(out, "\\x") == NULL, "no \\x in output");
    free(out);
    PASS();
}

static void test_json_escape_null_byte_handling(void)
{
    TEST(json_null_byte_bounded);
    /* With maxlen, should stop at maxlen even with embedded nulls */
    char input[] = {'a', '\0', 'b'};  /* 'a' then null then 'b' */
    char *out = capture_stdout(print_json_string_n, input, 3);
    /* Should stop at null byte since *s is checked */
    ASSERT_STR_EQ(out, "\"a\"", "stops at null byte");
    free(out);
    PASS();
}

static void test_json_empty_string(void)
{
    TEST(json_empty_string);
    char *out = capture_stdout(print_json_string_n, "", 0);
    ASSERT_STR_EQ(out, "\"\"", "empty string produces empty JSON string");
    free(out);
    PASS();
}

static void test_json_maxlen_truncation(void)
{
    TEST(json_maxlen_truncation);
    char *out = capture_stdout(print_json_string_n, "hello world", 5);
    ASSERT_STR_EQ(out, "\"hello\"", "truncated at maxlen");
    free(out);
    PASS();
}

static void test_json_high_byte_unicode_escape(void)
{
    TEST(json_high_byte_unicode_escape);
    char input[] = {(char)0x80, (char)0xff, '\0'};
    char *out = capture_stdout(print_json_string_n, input, 0);
    ASSERT_STR_CONTAINS(out, "\\u0080", "0x80 escaped as \\u0080");
    ASSERT_STR_CONTAINS(out, "\\u00ff", "0xff escaped as \\u00ff");
    free(out);
    PASS();
}

/* ===== HTTP parsing tests ===== */

static void test_http_get_request(void)
{
    TEST(http_parse_get_request);
    const char *data = "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_STR_EQ(info.method, "GET", "method should be GET");
    ASSERT_STR_EQ(info.path, "/api/v1/users", "path");
    ASSERT_STR_EQ(info.host, "example.com", "host");
    ASSERT_STR_EQ(info.version, "1.1", "HTTP version");
    ASSERT_EQ(info.status_code, 0, "not a response");
    PASS();
}

static void test_http_post_request(void)
{
    TEST(http_parse_post_request);
    const char *data = "POST /submit HTTP/1.1\r\nHost: api.test.com\r\nContent-Type: application/json\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_STR_EQ(info.method, "POST", "method should be POST");
    ASSERT_STR_EQ(info.path, "/submit", "path");
    ASSERT_STR_EQ(info.host, "api.test.com", "host");
    PASS();
}

static void test_http_response_200(void)
{
    TEST(http_parse_response_200);
    const char *data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_EQ(info.status_code, 200, "status code 200");
    ASSERT_STR_EQ(info.version, "1.1", "version 1.1");
    PASS();
}

static void test_http_response_404(void)
{
    TEST(http_parse_response_404);
    const char *data = "HTTP/1.1 404 Not Found\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_EQ(info.status_code, 404, "status code 404");
    PASS();
}

static void test_http_response_500(void)
{
    TEST(http_parse_response_500);
    const char *data = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_EQ(info.status_code, 500, "status code 500");
    PASS();
}

static void test_http_user_agent(void)
{
    TEST(http_parse_user_agent);
    const char *data = "GET / HTTP/1.1\r\nHost: test.com\r\nUser-Agent: curl/7.88.1\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_STR_EQ(info.user_agent, "curl/7.88.1", "user agent");
    PASS();
}

static void test_http_websocket_upgrade(void)
{
    TEST(http_parse_websocket_upgrade);
    const char *data = "GET /ws HTTP/1.1\r\nHost: ws.test.com\r\nUpgrade: websocket\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_EQ(info.websocket, 1, "websocket detected");
    PASS();
}

static void test_http_grpc_status(void)
{
    TEST(http_parse_grpc_status);
    const char *data = "HTTP/1.1 200 OK\r\ngrpc-status: 14\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_EQ(info.grpc_status, 14, "grpc status 14 (UNAVAILABLE)");
    PASS();
}

static void test_http_all_methods(void)
{
    TEST(http_parse_all_methods);
    const char *methods[] = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT"};
    for (int i = 0; i < 8; i++) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s /path HTTP/1.1\r\nHost: x\r\n\r\n", methods[i]);
        struct http_info info;
        parse_http_info(buf, strlen(buf), &info);
        if (strcmp(info.method, methods[i]) != 0) {
            printf("(%s) ", methods[i]);
            FAIL("method not parsed correctly");
        }
    }
    PASS();
}

static void test_http_too_short(void)
{
    TEST(http_parse_too_short);
    struct http_info info;
    parse_http_info("GET", 3, &info);
    ASSERT_EQ(info.method[0], '\0', "too short for any method");
    ASSERT_EQ(info.status_code, 0, "no status");
    PASS();
}

static void test_http_binary_data(void)
{
    TEST(http_parse_binary_garbage);
    char data[] = {0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0xfc};
    struct http_info info;
    parse_http_info(data, sizeof(data), &info);
    ASSERT_EQ(info.method[0], '\0', "binary data has no HTTP method");
    ASSERT_EQ(info.status_code, 0, "binary data has no status");
    PASS();
}

static void test_http_long_path(void)
{
    TEST(http_parse_long_path);
    char data[1024];
    memset(data, 0, sizeof(data));
    strcpy(data, "GET /");
    /* Fill with 'a' to exceed path buffer */
    memset(data + 5, 'a', 600);
    strcpy(data + 605, " HTTP/1.1\r\n\r\n");
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_STR_EQ(info.method, "GET", "method parsed");
    ASSERT_TRUE(strlen(info.path) < 512, "path truncated to buffer size");
    PASS();
}

/* ===== Kafka detection tests ===== */

static void test_kafka_valid_produce_request(void)
{
    TEST(kafka_detect_produce_request);
    /* Construct a valid Kafka Produce request header:
     * msg_size(4) + api_key=0(2) + api_version=9(2) + correlation_id=1(4) + client_id_len=5(2) */
    unsigned char data[20] = {
        0x00, 0x00, 0x00, 0x14,  /* msg_size = 20 */
        0x00, 0x00,              /* api_key = 0 (Produce) */
        0x00, 0x09,              /* api_version = 9 */
        0x00, 0x00, 0x00, 0x01,  /* correlation_id = 1 */
        0x00, 0x05,              /* client_id_len = 5 */
        'k', 'a', 'f', 'k', 'a', 0x00  /* client_id = "kafka" */
    };
    int api_key = -1;
    int result = detect_kafka_protocol((char *)data, sizeof(data), &api_key);
    ASSERT_EQ(result, 1, "detected as Kafka");
    ASSERT_EQ(api_key, 0, "api_key should be 0 (Produce)");
    PASS();
}

static void test_kafka_fetch_request(void)
{
    TEST(kafka_detect_fetch_request);
    unsigned char data[14] = {
        0x00, 0x00, 0x00, 0x20,  /* msg_size = 32 */
        0x00, 0x01,              /* api_key = 1 (Fetch) */
        0x00, 0x0c,              /* api_version = 12 */
        0x00, 0x00, 0x00, 0x02,  /* correlation_id = 2 */
        0xff, 0xff,              /* client_id_len = -1 (null) */
    };
    int api_key = -1;
    int result = detect_kafka_protocol((char *)data, sizeof(data), &api_key);
    ASSERT_EQ(result, 1, "detected as Kafka Fetch");
    ASSERT_EQ(api_key, 1, "api_key should be 1 (Fetch)");
    PASS();
}

static void test_kafka_invalid_api_key(void)
{
    TEST(kafka_reject_invalid_api_key);
    unsigned char data[14] = {
        0x00, 0x00, 0x00, 0x20,
        0x00, 0x4C,  /* api_key = 76 (out of range) */
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00,
    };
    int api_key = -1;
    ASSERT_EQ(detect_kafka_protocol((char *)data, sizeof(data), &api_key), 0,
              "should reject api_key > 74");
    PASS();
}

static void test_kafka_too_short(void)
{
    TEST(kafka_reject_too_short);
    unsigned char data[10] = {0};
    int api_key = -1;
    ASSERT_EQ(detect_kafka_protocol((char *)data, sizeof(data), &api_key), 0,
              "should reject < 14 bytes");
    PASS();
}

static void test_kafka_negative_correlation_id(void)
{
    TEST(kafka_reject_negative_corr_id);
    unsigned char data[14] = {
        0x00, 0x00, 0x00, 0x20,
        0x00, 0x00,
        0x00, 0x01,
        0x80, 0x00, 0x00, 0x00,  /* correlation_id = -2147483648 */
        0x00, 0x00,
    };
    int api_key = -1;
    ASSERT_EQ(detect_kafka_protocol((char *)data, sizeof(data), &api_key), 0,
              "should reject negative correlation_id");
    PASS();
}

/* Issue 3 fix: correlation_id must be > 0 (not just >= 0) to reduce
 * false positives from HTTP/2 binary frames. */
static void test_kafka_zero_correlation_id(void)
{
    TEST(kafka_reject_zero_corr_id);
    unsigned char data[14] = {
        0x00, 0x00, 0x00, 0x20,
        0x00, 0x00,              /* api_key = 0 (Produce) */
        0x00, 0x01,              /* api_version = 1 */
        0x00, 0x00, 0x00, 0x00,  /* correlation_id = 0 */
        0x00, 0x05,              /* client_id_len = 5 */
    };
    int api_key = -1;
    ASSERT_EQ(detect_kafka_protocol((char *)data, sizeof(data), &api_key), 0,
              "should reject zero correlation_id (HTTP/2 false positive guard)");
    PASS();
}

static void test_kafka_response_valid(void)
{
    TEST(kafka_detect_valid_response);
    unsigned char data[12] = {
        0x00, 0x00, 0x00, 0x10,  /* msg_size = 16 */
        0x00, 0x00, 0x00, 0x01,  /* correlation_id = 1 */
        0x00, 0x00,              /* error_code = 0 */
        0x00, 0x00,
    };
    ASSERT_EQ(detect_kafka_response((char *)data, sizeof(data)), 1,
              "valid Kafka response");
    PASS();
}

static void test_kafka_response_too_short(void)
{
    TEST(kafka_reject_short_response);
    unsigned char data[8] = {0};
    ASSERT_EQ(detect_kafka_response((char *)data, sizeof(data)), 0,
              "should reject < 12 bytes");
    PASS();
}

static void test_kafka_response_huge_msg_size(void)
{
    TEST(kafka_reject_huge_response);
    unsigned char data[12] = {
        0x10, 0x00, 0x00, 0x00,  /* msg_size = 268435456 (> 100MB) */
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
    };
    ASSERT_EQ(detect_kafka_response((char *)data, sizeof(data)), 0,
              "should reject msg_size > 100MB");
    PASS();
}

/* ===== Sanitization tests ===== */

static void test_sanitize_apikey(void)
{
    TEST(sanitize_apikey_pattern);
    test_cfg.sanitize_count = 0;
    add_test_sanitize_pattern("apikey=[^&]*");
    char str[256] = "/api/v1?apikey=secret123&foo=bar";
    sanitize_string(str, sizeof(str));
    ASSERT_STR_CONTAINS(str, "[REDACTED]", "apikey redacted");
    ASSERT_TRUE(strstr(str, "secret123") == NULL, "secret removed");
    ASSERT_STR_CONTAINS(str, "foo=bar", "other params preserved");
    PASS();
}

static void test_sanitize_multiple_matches(void)
{
    TEST(sanitize_multiple_matches);
    test_cfg.sanitize_count = 0;
    add_test_sanitize_pattern("token=[^&]*");
    char str[256] = "/a?token=abc&x=1&token=def";
    sanitize_string(str, sizeof(str));
    /* Both tokens should be redacted */
    ASSERT_TRUE(strstr(str, "abc") == NULL, "first token removed");
    ASSERT_TRUE(strstr(str, "def") == NULL, "second token removed");
    PASS();
}

static void test_sanitize_no_match(void)
{
    TEST(sanitize_no_match);
    test_cfg.sanitize_count = 0;
    add_test_sanitize_pattern("secret=[^&]*");
    char str[256] = "/api/v1?name=test&id=123";
    char original[256];
    strcpy(original, str);
    sanitize_string(str, sizeof(str));
    ASSERT_STR_EQ(str, original, "no change when no match");
    PASS();
}

static void test_sanitize_empty_string(void)
{
    TEST(sanitize_empty_string);
    test_cfg.sanitize_count = 0;
    add_test_sanitize_pattern("secret=[^&]*");
    char str[4] = "";
    sanitize_string(str, sizeof(str));
    ASSERT_STR_EQ(str, "", "empty string unchanged");
    PASS();
}

static void test_sanitize_case_insensitive(void)
{
    TEST(sanitize_case_insensitive);
    test_cfg.sanitize_count = 0;
    add_test_sanitize_pattern("APIKEY=[^&]*");
    char str[256] = "/a?apikey=secret";
    sanitize_string(str, sizeof(str));
    ASSERT_STR_CONTAINS(str, "[REDACTED]", "case-insensitive match");
    PASS();
}

/* ===== Address formatting tests ===== */

static void test_format_addr_ipv4(void)
{
    TEST(format_addr_ipv4);
    struct tls_event_t event = {};
    event.addr_family = ADDR_FAMILY_IPV4;
    /* 127.0.0.1 in network byte order */
    event.remote_addr_v4 = htonl(0x7f000001);
    event.remote_port = 443;
    char buf[128];
    format_addr(&event, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "127.0.0.1:443", "IPv4 addr formatted");
    PASS();
}

static void test_format_addr_ipv6_loopback(void)
{
    TEST(format_addr_ipv6_loopback);
    struct tls_event_t event = {};
    event.addr_family = ADDR_FAMILY_IPV6;
    memset(event.remote_addr_v6, 0, 16);
    event.remote_addr_v6[15] = 1;  /* ::1 */
    event.remote_port = 8443;
    char buf[128];
    format_addr(&event, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "[::1]:8443", "IPv6 loopback formatted");
    PASS();
}

static void test_format_addr_no_addr(void)
{
    TEST(format_addr_no_address);
    struct tls_event_t event = {};
    event.addr_family = 0;
    char buf[128];
    format_addr(&event, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "-", "no addr shows dash");
    PASS();
}

static void test_format_addr_ipv4_zero(void)
{
    TEST(format_addr_ipv4_zero_addr);
    struct tls_event_t event = {};
    event.addr_family = ADDR_FAMILY_IPV4;
    event.remote_addr_v4 = 0;
    event.remote_port = 80;
    char buf[128];
    format_addr(&event, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "-", "zero IPv4 addr shows dash");
    PASS();
}

static void test_format_addr_ipv6_full(void)
{
    TEST(format_addr_ipv6_full);
    struct tls_event_t event = {};
    event.addr_family = ADDR_FAMILY_IPV6;
    /* 2001:db8::1 */
    event.remote_addr_v6[0] = 0x20;
    event.remote_addr_v6[1] = 0x01;
    event.remote_addr_v6[2] = 0x0d;
    event.remote_addr_v6[3] = 0xb8;
    event.remote_addr_v6[15] = 1;
    event.remote_port = 443;
    char buf[128];
    format_addr(&event, buf, sizeof(buf));
    ASSERT_STR_CONTAINS(buf, "2001:db8::", "IPv6 2001:db8::1");
    ASSERT_STR_CONTAINS(buf, ":443", "port 443");
    PASS();
}

/* ===== Edge case tests ===== */

static void test_edge_zero_length_data(void)
{
    TEST(edge_zero_length_data);
    struct http_info info;
    parse_http_info("", 0, &info);
    ASSERT_EQ(info.method[0], '\0', "no method from empty data");
    ASSERT_EQ(info.status_code, 0, "no status from empty data");
    PASS();
}

static void test_edge_max_comm_length(void)
{
    TEST(edge_max_comm_json);
    /* MAX_COMM_LEN = 16, should truncate correctly */
    char comm[20] = "abcdefghijklmnopqrst";
    char *out = capture_stdout(print_json_string_n, comm, MAX_COMM_LEN);
    ASSERT_TRUE(strlen(out) <= MAX_COMM_LEN + 2, "output bounded by maxlen");
    /* Should contain the first 16 chars */
    ASSERT_STR_CONTAINS(out, "abcdefghijklmnop", "first 16 chars present");
    /* Should NOT contain chars beyond 16 */
    ASSERT_TRUE(strstr(out, "qrst") == NULL, "chars beyond 16 not present");
    free(out);
    PASS();
}

static void test_edge_single_char_data(void)
{
    TEST(edge_single_char_data);
    struct http_info info;
    parse_http_info("G", 1, &info);
    ASSERT_EQ(info.method[0], '\0', "single char too short for HTTP");
    PASS();
}

static void test_edge_conn_key_size(void)
{
    TEST(edge_conn_key_8_bytes);
    /* conn_key_t must be exactly 8 bytes for BPF map key */
    ASSERT_EQ(sizeof(struct conn_key_t), 8, "conn_key_t is 8 bytes");
    PASS();
}

static void test_edge_http_response_101(void)
{
    TEST(edge_http_response_101);
    const char *data = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_EQ(info.status_code, 101, "status 101");
    ASSERT_EQ(info.websocket, 1, "websocket detected in response");
    PASS();
}

static void test_edge_http_version_2(void)
{
    TEST(edge_http_version_2);
    const char *data = "HTTP/2 200 OK\r\n\r\n";
    struct http_info info;
    parse_http_info(data, strlen(data), &info);
    ASSERT_EQ(info.status_code, 200, "status 200");
    ASSERT_STR_EQ(info.version, "2", "HTTP/2 version");
    PASS();
}

/* ===== Main ===== */

int main(void)
{
    printf("\n=== TLS Tracer Helper Function Tests ===\n\n");

    /* JSON output tests */
    test_json_simple_string();
    test_json_escape_quotes();
    test_json_escape_backslash();
    test_json_escape_newline_tab();
    test_json_escape_carriage_return();
    test_json_escape_nonprintable_uses_unicode();
    test_json_escape_null_byte_handling();
    test_json_empty_string();
    test_json_maxlen_truncation();
    test_json_high_byte_unicode_escape();

    /* HTTP parsing tests */
    test_http_get_request();
    test_http_post_request();
    test_http_response_200();
    test_http_response_404();
    test_http_response_500();
    test_http_user_agent();
    test_http_websocket_upgrade();
    test_http_grpc_status();
    test_http_all_methods();
    test_http_too_short();
    test_http_binary_data();
    test_http_long_path();

    /* Kafka detection tests */
    test_kafka_valid_produce_request();
    test_kafka_fetch_request();
    test_kafka_invalid_api_key();
    test_kafka_too_short();
    test_kafka_negative_correlation_id();
    test_kafka_zero_correlation_id();
    test_kafka_response_valid();
    test_kafka_response_too_short();
    test_kafka_response_huge_msg_size();

    /* Sanitization tests */
    test_sanitize_apikey();
    test_sanitize_multiple_matches();
    test_sanitize_no_match();
    test_sanitize_empty_string();
    test_sanitize_case_insensitive();

    /* Address formatting tests */
    test_format_addr_ipv4();
    test_format_addr_ipv6_loopback();
    test_format_addr_no_addr();
    test_format_addr_ipv4_zero();
    test_format_addr_ipv6_full();

    /* Edge case tests */
    test_edge_zero_length_data();
    test_edge_max_comm_length();
    test_edge_single_char_data();
    test_edge_conn_key_size();
    test_edge_http_response_101();
    test_edge_http_version_2();

    printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
