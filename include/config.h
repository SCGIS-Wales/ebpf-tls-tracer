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
    char            boringssl_bin[256]; /* path to binary with statically-linked BoringSSL (e.g., Envoy) */
    __u32           filter_pid;
    __u32           filter_uid;
    int             hex_dump;
    int             data_only;
    int             verbose;
    int             enable_quic;
    int             headers_only;   /* truncate at HTTP body boundary */
    __u64           max_events;     /* exit after N events (0 = unlimited) */
    int             duration;       /* exit after N seconds (0 = unlimited) */
    char            host_ip[INET6_ADDRSTRLEN];
    int             ecs_detected;   /* 1 if running on AWS ECS (detected via env var) */
    struct sanitize_pattern sanitize[MAX_SANITIZE_PATTERNS];
    int             sanitize_count;
    __u32           ring_buffer_mb; /* ring buffer size in MB (must be power-of-2, default 4) */
    int             aggregate;      /* enable session aggregation */
    int             aggregate_only; /* suppress per-event output, only emit summaries */
    int             aggregate_timeout; /* idle timeout in seconds (default: 30) */
    char            pcap_path[256]; /* pcap-ng output file path (empty = disabled) */
    int             pcap_snaplen;   /* max bytes per packet in pcap (default: 4096) */
    int             metrics_port;   /* Prometheus metrics port (0 = disabled) */
    char            metrics_path[64]; /* metrics HTTP path (default: /metrics) */
    struct traffic_filter filter;
};

/* DNS cache: hostname lookup/store per {pid, fd} connection */
const char *dns_cache_lookup(__u32 pid, __u32 fd);
void dns_cache_store(__u32 pid, __u32 fd, const char *hostname);

/* Apply sanitization patterns to a string, replacing matches with [REDACTED] */
void sanitize_string(char *str, size_t len, const struct config *c);

#endif /* CONFIG_H */
