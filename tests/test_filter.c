// SPDX-License-Identifier: MIT
//
// Unit tests for traffic filtering: CIDR parsing, IP matching,
// keyword expansion, protocol/method/direction filters.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "tracer.h"
#include "filter.h"
#include "protocol.h"

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s (line %d)\n", msg, __LINE__); \
    } else { \
        tests_passed++; \
    } \
} while (0)

/* Helper to create an event with an IPv4 remote address */
static struct tls_event_t make_event_v4(const char *ip, __u16 port,
                                         __u8 event_type, __u8 direction)
{
    struct tls_event_t e;
    memset(&e, 0, sizeof(e));
    e.addr_family = ADDR_FAMILY_IPV4;
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    e.remote_addr_v4 = addr.s_addr;
    e.remote_port = port;
    e.event_type = event_type;
    e.direction = direction;
    return e;
}

/* Helper to create an event with an IPv6 remote address */
static struct tls_event_t make_event_v6(const char *ip, __u16 port,
                                         __u8 event_type, __u8 direction)
{
    struct tls_event_t e;
    memset(&e, 0, sizeof(e));
    e.addr_family = ADDR_FAMILY_IPV6;
    inet_pton(AF_INET6, ip, e.remote_addr_v6);
    e.remote_port = port;
    e.event_type = event_type;
    e.direction = direction;
    return e;
}

static void test_parse_cidr_ipv4(void)
{
    printf("  test_parse_cidr_ipv4\n");
    struct cidr_entry entry;

    ASSERT(parse_cidr("10.0.0.0/8", &entry) == 0, "parse 10.0.0.0/8");
    ASSERT(entry.family == AF_INET, "family is AF_INET");
    ASSERT(entry.prefix_len == 8, "prefix_len is 8");

    ASSERT(parse_cidr("192.168.1.0/24", &entry) == 0, "parse 192.168.1.0/24");
    ASSERT(entry.prefix_len == 24, "prefix_len is 24");

    ASSERT(parse_cidr("0.0.0.0/0", &entry) == 0, "parse 0.0.0.0/0");
    ASSERT(entry.prefix_len == 0, "prefix_len is 0");

    ASSERT(parse_cidr("255.255.255.255/32", &entry) == 0, "parse /32");
    ASSERT(entry.prefix_len == 32, "prefix_len is 32");
}

static void test_parse_cidr_ipv6(void)
{
    printf("  test_parse_cidr_ipv6\n");
    struct cidr_entry entry;

    ASSERT(parse_cidr("fc00::/7", &entry) == 0, "parse fc00::/7");
    ASSERT(entry.family == AF_INET6, "family is AF_INET6");
    ASSERT(entry.prefix_len == 7, "prefix_len is 7");

    ASSERT(parse_cidr("::1/128", &entry) == 0, "parse ::1/128");
    ASSERT(entry.prefix_len == 128, "prefix_len is 128");

    ASSERT(parse_cidr("2001:db8::/32", &entry) == 0, "parse 2001:db8::/32");
    ASSERT(entry.prefix_len == 32, "prefix_len is 32");
}

static void test_parse_cidr_invalid(void)
{
    printf("  test_parse_cidr_invalid\n");
    struct cidr_entry entry;

    ASSERT(parse_cidr("10.0.0.0", &entry) != 0, "missing prefix length");
    ASSERT(parse_cidr("10.0.0.0/33", &entry) != 0, "v4 prefix > 32");
    ASSERT(parse_cidr("fc00::/129", &entry) != 0, "v6 prefix > 128");
    ASSERT(parse_cidr("not-an-ip/8", &entry) != 0, "garbage address");
    ASSERT(parse_cidr("/8", &entry) != 0, "empty address");
    ASSERT(parse_cidr("10.0.0.0/-1", &entry) != 0, "negative prefix");
}

static void test_ip_matches_cidr_v4(void)
{
    printf("  test_ip_matches_cidr_v4\n");
    struct cidr_entry entry;
    parse_cidr("10.0.0.0/8", &entry);

    struct tls_event_t e1 = make_event_v4("10.1.2.3", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e1, &entry) == 1, "10.1.2.3 in 10.0.0.0/8");

    struct tls_event_t e2 = make_event_v4("11.0.0.1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e2, &entry) == 0, "11.0.0.1 NOT in 10.0.0.0/8");

    /* Boundary: 10.255.255.255 should match */
    struct tls_event_t e3 = make_event_v4("10.255.255.255", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e3, &entry) == 1, "10.255.255.255 in 10.0.0.0/8");

    /* /32 — exact match */
    struct cidr_entry exact;
    parse_cidr("192.168.1.1/32", &exact);
    struct tls_event_t e4 = make_event_v4("192.168.1.1", 80, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e4, &exact) == 1, "exact /32 match");
    struct tls_event_t e5 = make_event_v4("192.168.1.2", 80, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e5, &exact) == 0, "exact /32 non-match");
}

static void test_ip_matches_cidr_v6(void)
{
    printf("  test_ip_matches_cidr_v6\n");
    struct cidr_entry entry;
    parse_cidr("fc00::/7", &entry);

    struct tls_event_t e1 = make_event_v6("fd12:3456::1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e1, &entry) == 1, "fd12::1 in fc00::/7");

    struct tls_event_t e2 = make_event_v6("2001:db8::1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e2, &entry) == 0, "2001:db8::1 NOT in fc00::/7");

    /* ::1/128 */
    struct cidr_entry lo;
    parse_cidr("::1/128", &lo);
    struct tls_event_t e3 = make_event_v6("::1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e3, &lo) == 1, "::1 matches ::1/128");
}

static void test_ip_matches_cross_family(void)
{
    printf("  test_ip_matches_cross_family\n");
    struct cidr_entry v4_entry;
    parse_cidr("10.0.0.0/8", &v4_entry);

    /* IPv6 event against IPv4 CIDR should not match */
    struct tls_event_t e = make_event_v6("::1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_matches_cidr(&e, &v4_entry) == 0, "IPv6 event vs IPv4 CIDR = no match");
}

static void test_expand_keyword_private(void)
{
    printf("  test_expand_keyword_private\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));

    ASSERT(expand_keyword_cidrs("private", &f) == 0, "expand private");
    ASSERT(f.cidr_count == 5, "private = 5 CIDRs (4 v4 + 1 v6)");
    ASSERT(f.cidr_public == 0, "not public");
}

static void test_expand_keyword_public(void)
{
    printf("  test_expand_keyword_public\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));

    ASSERT(expand_keyword_cidrs("public", &f) == 0, "expand public");
    ASSERT(f.cidr_count == 5, "public expands same CIDRs as private");
    ASSERT(f.cidr_public == 1, "public flag set");
}

static void test_expand_keyword_loopback(void)
{
    printf("  test_expand_keyword_loopback\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));

    ASSERT(expand_keyword_cidrs("loopback", &f) == 0, "expand loopback");
    ASSERT(f.cidr_count == 2, "loopback = 2 CIDRs (1 v4 + 1 v6)");
}

static void test_expand_keyword_unknown(void)
{
    printf("  test_expand_keyword_unknown\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));

    ASSERT(expand_keyword_cidrs("bogus", &f) != 0, "unknown keyword fails");
}

static void test_ip_is_private(void)
{
    printf("  test_ip_is_private\n");

    struct tls_event_t priv = make_event_v4("10.1.2.3", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_is_private(&priv) == 1, "10.1.2.3 is private");

    struct tls_event_t priv2 = make_event_v4("172.16.0.1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_is_private(&priv2) == 1, "172.16.0.1 is private");

    struct tls_event_t priv3 = make_event_v4("192.168.0.1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_is_private(&priv3) == 1, "192.168.0.1 is private");

    struct tls_event_t priv4 = make_event_v4("100.64.0.1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_is_private(&priv4) == 1, "100.64.0.1 is private (CGN)");

    struct tls_event_t pub = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_is_private(&pub) == 0, "8.8.8.8 is NOT private");

    struct tls_event_t lo = make_event_v4("127.0.0.1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_is_private(&lo) == 1, "127.0.0.1 is private (loopback)");

    /* IPv6 */
    struct tls_event_t priv6 = make_event_v6("fd00::1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_is_private(&priv6) == 1, "fd00::1 is private (ULA)");

    struct tls_event_t pub6 = make_event_v6("2001:db8::1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(ip_is_private(&pub6) == 0, "2001:db8::1 is NOT private");
}

static void test_parse_filter_arg(void)
{
    printf("  test_parse_filter_arg\n");
    enum filter_mode mode;
    const char *value;

    ASSERT(parse_filter_arg("include:10.0.0.0/8", &mode, &value) == 0, "parse include:...");
    ASSERT(mode == FILTER_MODE_INCLUDE, "mode is include");
    ASSERT(strcmp(value, "10.0.0.0/8") == 0, "value is CIDR");

    ASSERT(parse_filter_arg("exclude:private", &mode, &value) == 0, "parse exclude:...");
    ASSERT(mode == FILTER_MODE_EXCLUDE, "mode is exclude");
    ASSERT(strcmp(value, "private") == 0, "value is private");

    /* Invalid cases */
    ASSERT(parse_filter_arg("bogus:value", &mode, &value) != 0, "invalid mode");
    ASSERT(parse_filter_arg("include:", &mode, &value) != 0, "empty value");
    ASSERT(parse_filter_arg(":value", &mode, &value) != 0, "empty mode");
}

static void test_parse_proto_name(void)
{
    printf("  test_parse_proto_name\n");
    ASSERT(parse_proto_name("tcp") == PROTO_FILTER_TCP, "tcp");
    ASSERT(parse_proto_name("TCP") == PROTO_FILTER_TCP, "TCP (case-insensitive)");
    ASSERT(parse_proto_name("udp") == PROTO_FILTER_UDP, "udp");
    ASSERT(parse_proto_name("http") == PROTO_FILTER_HTTP, "http");
    ASSERT(parse_proto_name("https") == PROTO_FILTER_HTTPS, "https");
    ASSERT(parse_proto_name("non-https") == PROTO_FILTER_NON_HTTPS, "non-https");
    ASSERT(parse_proto_name("bogus") == 0, "unknown returns 0");
}

static void test_filter_cidr_include(void)
{
    printf("  test_filter_cidr_include\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.cidr_mode = FILTER_MODE_INCLUDE;
    parse_cidr("10.0.0.0/8", &f.cidrs[0]);
    f.cidr_count = 1;

    struct tls_event_t in = make_event_v4("10.1.2.3", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &in, NULL) == 1, "10.1.2.3 included");

    struct tls_event_t out = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &out, NULL) == 0, "8.8.8.8 filtered out");
}

static void test_filter_cidr_exclude(void)
{
    printf("  test_filter_cidr_exclude\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.cidr_mode = FILTER_MODE_EXCLUDE;
    parse_cidr("10.0.0.0/8", &f.cidrs[0]);
    f.cidr_count = 1;

    struct tls_event_t in = make_event_v4("10.1.2.3", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &in, NULL) == 0, "10.1.2.3 excluded");

    struct tls_event_t out = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &out, NULL) == 1, "8.8.8.8 passes exclude");
}

static void test_filter_cidr_public_keyword(void)
{
    printf("  test_filter_cidr_public_keyword\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.cidr_mode = FILTER_MODE_INCLUDE;
    expand_keyword_cidrs("public", &f);

    /* Public IP should pass include:public */
    struct tls_event_t pub = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &pub, NULL) == 1, "8.8.8.8 passes include:public");

    /* Private IP should be filtered by include:public */
    struct tls_event_t priv = make_event_v4("10.1.2.3", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &priv, NULL) == 0, "10.1.2.3 filtered by include:public");
}

static void test_filter_proto_include(void)
{
    printf("  test_filter_proto_include\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.proto_mode = FILTER_MODE_INCLUDE;
    f.proto_flags = PROTO_FILTER_HTTPS;

    struct tls_event_t https = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &https, NULL) == 1, "TLS event passes include:https");

    struct tls_event_t quic = make_event_v4("8.8.8.8", 443, EVENT_QUIC_DETECTED, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &quic, NULL) == 0, "QUIC event filtered by include:https");
}

static void test_filter_proto_udp(void)
{
    printf("  test_filter_proto_udp\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.proto_mode = FILTER_MODE_INCLUDE;
    f.proto_flags = PROTO_FILTER_UDP;

    struct tls_event_t quic = make_event_v4("8.8.8.8", 443, EVENT_QUIC_DETECTED, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &quic, NULL) == 1, "QUIC passes include:udp");

    struct tls_event_t tls = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &tls, NULL) == 0, "TLS filtered by include:udp");
}

static void test_filter_method_include(void)
{
    printf("  test_filter_method_include\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.method_mode = FILTER_MODE_INCLUDE;
    snprintf(f.methods[0], sizeof(f.methods[0]), "GET");
    f.method_count = 1;

    struct http_info get = {0};
    snprintf(get.method, sizeof(get.method), "GET");

    struct http_info post = {0};
    snprintf(post.method, sizeof(post.method), "POST");

    struct tls_event_t e = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e, &get) == 1, "GET passes include:GET");
    ASSERT(filter_event(&f, &e, &post) == 0, "POST filtered by include:GET");

    /* Non-HTTP event should pass method filter */
    ASSERT(filter_event(&f, &e, NULL) == 1, "non-HTTP passes method filter");

    /* Event with no method detected should pass */
    struct http_info empty = {0};
    ASSERT(filter_event(&f, &e, &empty) == 1, "empty method passes method filter");
}

static void test_filter_method_exclude(void)
{
    printf("  test_filter_method_exclude\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.method_mode = FILTER_MODE_EXCLUDE;
    snprintf(f.methods[0], sizeof(f.methods[0]), "DELETE");
    f.method_count = 1;

    struct http_info del = {0};
    snprintf(del.method, sizeof(del.method), "DELETE");

    struct http_info get = {0};
    snprintf(get.method, sizeof(get.method), "GET");

    struct tls_event_t e = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e, &del) == 0, "DELETE excluded");
    ASSERT(filter_event(&f, &e, &get) == 1, "GET passes exclude:DELETE");
}

static void test_filter_direction(void)
{
    printf("  test_filter_direction\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.dir_mode = FILTER_MODE_INCLUDE;
    f.dir_flags = DIR_FILTER_INBOUND;

    struct tls_event_t inb = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_READ);
    ASSERT(filter_event(&f, &inb, NULL) == 1, "inbound passes include:inbound");

    struct tls_event_t outb = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &outb, NULL) == 0, "outbound filtered by include:inbound");
}

static void test_filter_combined_and(void)
{
    printf("  test_filter_combined_and\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));

    /* include:public AND include:https AND include:GET */
    f.cidr_mode = FILTER_MODE_INCLUDE;
    expand_keyword_cidrs("public", &f);

    f.proto_mode = FILTER_MODE_INCLUDE;
    f.proto_flags = PROTO_FILTER_HTTPS;

    f.method_mode = FILTER_MODE_INCLUDE;
    snprintf(f.methods[0], sizeof(f.methods[0]), "GET");
    f.method_count = 1;

    struct http_info get = {0};
    snprintf(get.method, sizeof(get.method), "GET");

    /* Public + HTTPS + GET → pass */
    struct tls_event_t e1 = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e1, &get) == 1, "public+https+GET passes");

    /* Private + HTTPS + GET → filtered (CIDR fails) */
    struct tls_event_t e2 = make_event_v4("10.1.2.3", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e2, &get) == 0, "private+https+GET filtered by CIDR");

    /* Public + QUIC + GET → filtered (proto fails) */
    struct tls_event_t e3 = make_event_v4("8.8.8.8", 443, EVENT_QUIC_DETECTED, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e3, &get) == 0, "public+quic+GET filtered by proto");

    /* Public + HTTPS + POST → filtered (method fails) */
    struct http_info post = {0};
    snprintf(post.method, sizeof(post.method), "POST");
    struct tls_event_t e4 = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e4, &post) == 0, "public+https+POST filtered by method");
}

static void test_filter_no_filters(void)
{
    printf("  test_filter_no_filters\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));

    struct tls_event_t e = make_event_v4("1.2.3.4", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e, NULL) == 1, "no filters = pass all");
}

static void test_filter_multiple_cidrs(void)
{
    printf("  test_filter_multiple_cidrs\n");
    struct traffic_filter f;
    memset(&f, 0, sizeof(f));
    f.cidr_mode = FILTER_MODE_INCLUDE;
    parse_cidr("10.0.0.0/8", &f.cidrs[0]);
    parse_cidr("172.16.0.0/12", &f.cidrs[1]);
    f.cidr_count = 2;

    struct tls_event_t e1 = make_event_v4("10.1.2.3", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e1, NULL) == 1, "10.x matches first CIDR");

    struct tls_event_t e2 = make_event_v4("172.16.5.1", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e2, NULL) == 1, "172.16.x matches second CIDR");

    struct tls_event_t e3 = make_event_v4("8.8.8.8", 443, EVENT_TLS_DATA, DIRECTION_WRITE);
    ASSERT(filter_event(&f, &e3, NULL) == 0, "8.8.8.8 matches neither CIDR");
}

int main(void)
{
    printf("Running filter tests...\n");

    test_parse_cidr_ipv4();
    test_parse_cidr_ipv6();
    test_parse_cidr_invalid();
    test_ip_matches_cidr_v4();
    test_ip_matches_cidr_v6();
    test_ip_matches_cross_family();
    test_expand_keyword_private();
    test_expand_keyword_public();
    test_expand_keyword_loopback();
    test_expand_keyword_unknown();
    test_ip_is_private();
    test_parse_filter_arg();
    test_parse_proto_name();
    test_filter_cidr_include();
    test_filter_cidr_exclude();
    test_filter_cidr_public_keyword();
    test_filter_proto_include();
    test_filter_proto_udp();
    test_filter_method_include();
    test_filter_method_exclude();
    test_filter_direction();
    test_filter_combined_and();
    test_filter_no_filters();
    test_filter_multiple_cidrs();

    printf("\nFilter tests: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
