#ifndef CONFIG_H
#define CONFIG_H

#include "tracer.h"
#include "filter.h"
#include <regex.h>
#include <arpa/inet.h>  /* INET6_ADDRSTRLEN */

#define MAX_SANITIZE_PATTERNS 32
#define DNS_CACHE_SIZE     4096
#define DNS_CACHE_TTL      300

/* Output format */
enum output_fmt {
    FMT_TEXT,
    FMT_JSON,
};

/* Compiled sanitization regex pattern */
struct sanitize_pattern {
    regex_t regex;
    char    original[256];
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
    int             enable_quic;
    char            host_ip[INET6_ADDRSTRLEN];
    struct sanitize_pattern sanitize[MAX_SANITIZE_PATTERNS];
    int             sanitize_count;
    struct traffic_filter filter;
};

/* DNS cache: hostname lookup/store per {pid, fd} connection */
const char *dns_cache_lookup(__u32 pid, __u32 fd);
void dns_cache_store(__u32 pid, __u32 fd, const char *hostname);

/* Apply sanitization patterns to a string, replacing matches with [REDACTED] */
void sanitize_string(char *str, size_t len, const struct config *c);

#endif /* CONFIG_H */
