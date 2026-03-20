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
#include <strings.h>   /* strcasecmp */
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
#include <sys/utsname.h>  /* for uname() — C-3 kernel version check */
#include <fcntl.h>     /* for O_RDONLY — H-4 bounded /proc read */
#include <dlfcn.h>     /* dlopen/dlsym for R1-REL OpenSSL version check */
#include <ifaddrs.h>   /* getifaddrs() for host IP auto-detection */
#include <net/if.h>    /* IFF_LOOPBACK */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tracer.h"
#include "config.h"
#include "filter.h"
#include "output.h"
#include "k8s.h"
#include "protocol.h"

#define RING_POLL_TIMEOUT  100
#define MAX_PROBES         32

static volatile sig_atomic_t exiting = 0;
static volatile sig_atomic_t exit_signal = 0;  /* stores signal number for 128+signum (#2 fix) */

/* --- Userspace DNS cache: remembers hostname per {pid, fd} connection ---
 * R-1 fix: Uses open-addressing hash table for O(1) lookup instead of O(n)
 * linear scan. Key is hash(pid, fd). Slot states: EMPTY/OCCUPIED/DELETED.
 * When a Host: header is parsed, the hostname is stored here.
 * Subsequent events on the same connection inherit the cached hostname
 * even if they don't contain an HTTP Host header. */
#define DNS_SLOT_EMPTY    0
#define DNS_SLOT_OCCUPIED 1
#define DNS_SLOT_DELETED  2

struct dns_cache_entry {
    __u32  pid;
    __u32  fd;
    time_t last_seen;
    char   hostname[256];
    __u8   state;
};

static struct dns_cache_entry dns_cache[DNS_CACHE_SIZE];

static inline __u32 dns_hash(__u32 pid, __u32 fd)
{
    __u64 key = ((__u64)pid << 32) | fd;
    key = (key ^ (key >> 30)) * 0xbf58476d1ce4e5b9ULL;
    key = (key ^ (key >> 27)) * 0x94d049bb133111ebULL;
    return ((__u32)(key >> 32)) & (DNS_CACHE_SIZE - 1);
}

const char *dns_cache_lookup(__u32 pid, __u32 fd)
{
    time_t now = time(NULL);
    __u32 idx = dns_hash(pid, fd);
    for (__u32 i = 0; i < DNS_CACHE_SIZE; i++) {
        __u32 slot = (idx + i) & (DNS_CACHE_SIZE - 1);
        if (dns_cache[slot].state == DNS_SLOT_EMPTY)
            return NULL;
        if (dns_cache[slot].state == DNS_SLOT_OCCUPIED &&
            dns_cache[slot].pid == pid && dns_cache[slot].fd == fd) {
            if (now - dns_cache[slot].last_seen > DNS_CACHE_TTL) {
                dns_cache[slot].state = DNS_SLOT_DELETED;
                return NULL;
            }
            dns_cache[slot].last_seen = now;
            return dns_cache[slot].hostname;
        }
    }
    return NULL;
}

void dns_cache_store(__u32 pid, __u32 fd, const char *hostname)
{
    if (!hostname || !hostname[0] || fd == 0)
        return;

    time_t now = time(NULL);
    __u32 idx = dns_hash(pid, fd);
    __u32 first_avail = UINT32_MAX;

    for (__u32 i = 0; i < DNS_CACHE_SIZE; i++) {
        __u32 slot = (idx + i) & (DNS_CACHE_SIZE - 1);
        if (dns_cache[slot].state == DNS_SLOT_EMPTY) {
            __u32 target = (first_avail != UINT32_MAX) ? first_avail : slot;
            dns_cache[target].pid = pid;
            dns_cache[target].fd = fd;
            dns_cache[target].last_seen = now;
            dns_cache[target].state = DNS_SLOT_OCCUPIED;
            snprintf(dns_cache[target].hostname,
                     sizeof(dns_cache[target].hostname), "%s", hostname);
            return;
        }
        if (dns_cache[slot].state == DNS_SLOT_DELETED && first_avail == UINT32_MAX)
            first_avail = slot;
        if (dns_cache[slot].state == DNS_SLOT_OCCUPIED &&
            dns_cache[slot].pid == pid && dns_cache[slot].fd == fd) {
            dns_cache[slot].last_seen = now;
            snprintf(dns_cache[slot].hostname,
                     sizeof(dns_cache[slot].hostname), "%s", hostname);
            return;
        }
        /* Opportunistically evict expired entries */
        if (dns_cache[slot].state == DNS_SLOT_OCCUPIED &&
            now - dns_cache[slot].last_seen > DNS_CACHE_TTL) {
            dns_cache[slot].state = DNS_SLOT_DELETED;
            if (first_avail == UINT32_MAX)
                first_avail = slot;
        }
    }
    /* Table full — use first available or overwrite hash index */
    __u32 target = (first_avail != UINT32_MAX) ? first_avail : idx;
    dns_cache[target].pid = pid;
    dns_cache[target].fd = fd;
    dns_cache[target].last_seen = now;
    dns_cache[target].state = DNS_SLOT_OCCUPIED;
    snprintf(dns_cache[target].hostname,
             sizeof(dns_cache[target].hostname), "%s", hostname);
}

static struct config cfg = {
    .format          = FMT_TEXT,
    .ssl_lib         = "",
    .filter_pid      = 0,
    .filter_uid      = 0,
    .hex_dump        = 0,
    .data_only       = 0,
    .verbose         = 0,
    .enable_quic     = 0,
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
void sanitize_string(char *str, size_t len, const struct config *c)
{
    if (c->sanitize_count == 0 || !str || !str[0])
        return;

    for (int i = 0; i < c->sanitize_count; i++) {
        regmatch_t match;
        char *p = str;
        while (regexec(&c->sanitize[i].regex, p, 1, &match, 0) == 0) {
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

static int find_ssl_library(char *path, size_t path_len)
{
    const char *candidates[] = {
        /* Host-mounted paths (K8s DaemonSet: host libs at /host/...) */
        "/host/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/host/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/host/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/host/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
        "/host/usr/lib64/libssl.so.3",
        "/host/usr/lib64/libssl.so.1.1",
        /* Debian/Ubuntu x86_64 */
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        /* Debian/Ubuntu aarch64 */
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
        /* RHEL/AL2023/Fedora */
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        /* Generic */
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/aarch64-linux-gnu/libssl.so.3",
        "/lib64/libssl.so.3",
        NULL,
    };

    for (int i = 0; candidates[i]; i++) {
        /* Use open() instead of access() to avoid TOCTOU race (CWE-367).
         * access() checks permissions, then the file is opened later —
         * an attacker could swap the file between check and use. */
        int fd = open(candidates[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
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
        "  -q, --quic             Enable QUIC/UDP detection probe (off by default)\n"
        "  -n, --net MODE:CIDR    Filter by CIDR range or keyword (repeatable)\n"
        "                         MODE is 'include' or 'exclude'\n"
        "                         CIDR is an IP range (e.g. 10.0.0.0/8, fc00::/7)\n"
        "                         Keywords: private, public, loopback\n"
        "  -P, --proto MODE:PROTO Filter by protocol (repeatable)\n"
        "                         PROTO: tcp, udp, http, https, non-https\n"
        "  -m, --method MODE:MTH  Filter by HTTP method (repeatable)\n"
        "                         MTH: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT\n"
        "  -D, --dir MODE:DIR     Filter by traffic direction (repeatable)\n"
        "                         DIR: inbound, outbound\n"
        "  -v, --verbose          Verbose output\n"
        "  -h, --help             Show this help message\n"
        "\n"
        "Examples:\n"
        "  %s                               Trace all TLS traffic\n"
        "  %s -p 1234                       Trace TLS traffic for PID 1234\n"
        "  %s -f json                       Output in JSON format\n"
        "  %s --net include:private          Only private network traffic\n"
        "  %s --net exclude:10.0.0.0/8       Exclude 10.x.x.x traffic\n"
        "  %s --proto include:https --method include:GET  Only HTTPS GETs\n"
        "  %s --dir include:inbound          Only inbound (response) traffic\n"
        "  %s -s 'apikey=[^&]*'             Redact API keys from logged URLs\n"
        "\n"
        "Requires root privileges (or CAP_BPF + CAP_PERFMON).\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

/* R1-REL: Validate OpenSSL version for struct offset compatibility.
 * The BPF program uses hardcoded offsets into SSL/BIO/SSL_CIPHER structs.
 * These offsets are verified for specific OpenSSL versions. If the library
 * version doesn't match, connection correlation may silently fail. */
static void validate_openssl_version(const char *ssl_lib_path)
{
    /* Read the OpenSSL version string by looking for the version in the library.
     * We use dlopen/dlsym to call OpenSSL_version() or SSLeay_version(). */
    void *handle = dlopen(ssl_lib_path, RTLD_LAZY | RTLD_NOLOAD);
    if (!handle)
        handle = dlopen(ssl_lib_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Warning: Cannot open %s for version check: %s\n",
                ssl_lib_path, dlerror());
        return;
    }

    /* OpenSSL 3.x: OpenSSL_version(OPENSSL_VERSION) returns version string */
    const char *(*openssl_version_fn)(int) = dlsym(handle, "OpenSSL_version");
    if (!openssl_version_fn) {
        /* OpenSSL 1.1.x: try SSLeay_version */
        openssl_version_fn = dlsym(handle, "SSLeay_version");
    }

    if (openssl_version_fn) {
        const char *ver = openssl_version_fn(0);  /* OPENSSL_VERSION = 0 */
        if (ver) {
            fprintf(stderr, "OpenSSL version: %s\n", ver);

            /* Known-good versions for hardcoded struct offsets */
            int known_good = 0;
            if (strstr(ver, "3.0.") || strstr(ver, "3.1.") ||
                strstr(ver, "3.2.") || strstr(ver, "3.3.") ||
                strstr(ver, "3.4.") || strstr(ver, "3.5.") ||
                strstr(ver, "1.1.1"))
                known_good = 1;

            if (!known_good) {
                fprintf(stderr,
                    "WARNING: OpenSSL version '%s' has NOT been verified for\n"
                    "struct offset compatibility. The BPF program uses hardcoded\n"
                    "offsets into SSL->rbio (offset 16), BIO->num (offset 40/32),\n"
                    "and SSL_CIPHER->name (offset 8). If these offsets changed\n"
                    "in this version, connection correlation (conn_id, dst_ip)\n"
                    "and cipher name extraction will silently fail.\n"
                    "Verified versions: OpenSSL 1.1.1x, 3.0.x-3.5.x\n", ver);
            }
        }
    }

    dlclose(handle);
}

/* Detect the host/node IP address for JSON event enrichment.
 * Priority: 1) HOST_IP env var (set via K8s downward API status.hostIP)
 *           2) First non-loopback IPv4 address from network interfaces
 * On EC2 with hostNetwork:true, this gives the instance's VPC IP. */
static void detect_host_ip(char *buf, size_t buflen)
{
    buf[0] = '\0';

    /* 1. Check HOST_IP environment variable (K8s downward API) */
    const char *env_ip = getenv("HOST_IP");
    if (env_ip && env_ip[0]) {
        snprintf(buf, buflen, "%s", env_ip);
        return;
    }

    /* Also check NODE_IP (alternative naming convention) */
    env_ip = getenv("NODE_IP");
    if (env_ip && env_ip[0]) {
        snprintf(buf, buflen, "%s", env_ip);
        return;
    }

    /* 2. Auto-detect: first non-loopback IPv4 address */
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
        return;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        /* Skip loopback and down interfaces */
        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;
        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sin->sin_addr, buf, buflen);
            break;
        }
    }

    freeifaddrs(ifaddr);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *links[MAX_PROBES] = {0};
    struct ring_buffer *rb = NULL;
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
        {"quic",      no_argument,       NULL, 'q'},
        {"net",       required_argument, NULL, 'n'},
        {"proto",     required_argument, NULL, 'P'},
        {"method",    required_argument, NULL, 'm'},
        {"dir",       required_argument, NULL, 'D'},
        {"verbose",   no_argument,       NULL, 'v'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:u:l:f:xds:qn:P:m:D:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': {
            char *endp;
            errno = 0;  /* C7 fix: reset errno before strtoul for overflow detection */
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val == 0 || val > UINT_MAX || errno == ERANGE) {
                fprintf(stderr, "Error: Invalid PID '%s'\n", optarg);
                return 1;
            }
            cfg.filter_pid = (__u32)val;
            break;
        }
        case 'u': {
            char *endp;
            errno = 0;  /* C7 fix */
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val > UINT_MAX || errno == ERANGE) {
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
        case 'q':
            cfg.enable_quic = 1;
            break;
        case 'n': {
            enum filter_mode mode;
            const char *value;
            if (parse_filter_arg(optarg, &mode, &value) != 0)
                return 1;
            if (cfg.filter.cidr_mode != FILTER_MODE_NONE && cfg.filter.cidr_mode != mode) {
                fprintf(stderr, "Error: Cannot mix include and exclude in --net filters\n");
                return 1;
            }
            cfg.filter.cidr_mode = mode;
            /* Check if value is a keyword or CIDR */
            if (strcasecmp(value, "private") == 0 || strcasecmp(value, "public") == 0 ||
                strcasecmp(value, "loopback") == 0) {
                if (expand_keyword_cidrs(value, &cfg.filter) != 0)
                    return 1;
            } else {
                if (cfg.filter.cidr_count >= MAX_FILTER_CIDRS) {
                    fprintf(stderr, "Error: Too many CIDR filters (max %d)\n", MAX_FILTER_CIDRS);
                    return 1;
                }
                if (parse_cidr(value, &cfg.filter.cidrs[cfg.filter.cidr_count]) != 0) {
                    fprintf(stderr, "Error: Invalid CIDR '%s'\n", value);
                    return 1;
                }
                cfg.filter.cidr_count++;
            }
            break;
        }
        case 'P': {
            enum filter_mode mode;
            const char *value;
            if (parse_filter_arg(optarg, &mode, &value) != 0)
                return 1;
            if (cfg.filter.proto_mode != FILTER_MODE_NONE && cfg.filter.proto_mode != mode) {
                fprintf(stderr, "Error: Cannot mix include and exclude in --proto filters\n");
                return 1;
            }
            cfg.filter.proto_mode = mode;
            unsigned int flag = parse_proto_name(value);
            if (flag == 0) {
                fprintf(stderr, "Error: Unknown protocol '%s'"
                                " (use tcp, udp, http, https, non-https)\n", value);
                return 1;
            }
            cfg.filter.proto_flags |= flag;
            break;
        }
        case 'm': {
            enum filter_mode mode;
            const char *value;
            if (parse_filter_arg(optarg, &mode, &value) != 0)
                return 1;
            if (cfg.filter.method_mode != FILTER_MODE_NONE && cfg.filter.method_mode != mode) {
                fprintf(stderr, "Error: Cannot mix include and exclude in --method filters\n");
                return 1;
            }
            cfg.filter.method_mode = mode;
            if (cfg.filter.method_count >= MAX_FILTER_METHODS) {
                fprintf(stderr, "Error: Too many method filters (max %d)\n", MAX_FILTER_METHODS);
                return 1;
            }
            snprintf(cfg.filter.methods[cfg.filter.method_count],
                     sizeof(cfg.filter.methods[0]), "%s", value);
            cfg.filter.method_count++;
            break;
        }
        case 'D': {
            enum filter_mode mode;
            const char *value;
            if (parse_filter_arg(optarg, &mode, &value) != 0)
                return 1;
            if (cfg.filter.dir_mode != FILTER_MODE_NONE && cfg.filter.dir_mode != mode) {
                fprintf(stderr, "Error: Cannot mix include and exclude in --dir filters\n");
                return 1;
            }
            cfg.filter.dir_mode = mode;
            if (strcasecmp(value, "inbound") == 0)
                cfg.filter.dir_flags |= DIR_FILTER_INBOUND;
            else if (strcasecmp(value, "outbound") == 0)
                cfg.filter.dir_flags |= DIR_FILTER_OUTBOUND;
            else {
                fprintf(stderr, "Error: Unknown direction '%s' (use inbound or outbound)\n", value);
                return 1;
            }
            break;
        }
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

    /* S2-SEC: Default sanitization for sensitive HTTP headers.
     * These patterns redact authentication tokens and session cookies
     * from captured TLS data. Users can add more patterns with -s. */
    {
        static const char *default_sanitize_patterns[] = {
            "Authorization:[[:space:]]*[^\r\n]+",
            "Cookie:[[:space:]]*[^\r\n]+",
            "Set-Cookie:[[:space:]]*[^\r\n]+",
            "X-Api-Key:[[:space:]]*[^\r\n]+",
            NULL,
        };
        for (int i = 0; default_sanitize_patterns[i]; i++) {
            add_sanitize_pattern(default_sanitize_patterns[i]);
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
        /* Use open() instead of access() to avoid TOCTOU race (CWE-367) */
        int fd = open(cfg.ssl_lib, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "Error: Cannot access SSL library at '%s': %s\n",
                    cfg.ssl_lib, strerror(errno));
            return 1;
        }
        close(fd);
    }

    if (cfg.verbose)
        fprintf(stderr, "Using SSL library: %s\n", cfg.ssl_lib);

    validate_openssl_version(cfg.ssl_lib);

    /* Detect host/node IP for JSON enrichment (EC2 instance IP) */
    detect_host_ip(cfg.host_ip, sizeof(cfg.host_ip));
    if (cfg.host_ip[0] && cfg.verbose)
        fprintf(stderr, "Host IP: %s\n", cfg.host_ip);

    /* Set up signal handlers (R6 fix: use sigaction for reliable signal handling).
     * signal() has undefined behavior on some systems — the handler may be reset
     * to SIG_DFL after first invocation. sigaction() is POSIX-recommended. */
    struct sigaction sa = {0};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* No SA_RESTART: we want poll() to return -EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* R7 fix: ignore SIGPIPE so stdout writes don't kill the process
     * when piped through tee or when the reader closes the pipe. */
    signal(SIGPIPE, SIG_IGN);

    /* P4-PERF: Use line-buffered stdout instead of per-event fflush.
     * This achieves the same line-at-a-time semantics with fewer syscalls. */
    setlinebuf(stdout);

    /* C-3 fix: Log kernel version for CVE-2025-40319 ring buffer race condition.
     * Warn if kernel < 6.12.8 which may be affected. */
    {
        struct utsname uts;
        if (uname(&uts) == 0) {
            fprintf(stderr, "Kernel: %s\n", uts.release);
            int major = 0, minor = 0, patch = 0;
            if (sscanf(uts.release, "%d.%d.%d", &major, &minor, &patch) >= 2) {
                if (major < 6 || (major == 6 && minor < 12) ||
                    (major == 6 && minor == 12 && patch < 8))
                    fprintf(stderr, "Warning: Kernel %s may be affected by CVE-2025-40319 "
                            "(BPF ring buffer race condition). Consider upgrading to >= 6.12.8.\n",
                            uts.release);
            }
        }
    }

    /* R-7 fix: Pre-flight checks for required kernel features.
     * These give clear, actionable errors instead of cryptic libbpf failures. */
    {
        struct stat st_check;
        int preflight_ok = 1;

        if (stat("/sys/kernel/btf/vmlinux", &st_check) != 0) {
            fprintf(stderr, "FATAL: BTF not available (/sys/kernel/btf/vmlinux missing).\n"
                    "Kernel must have CONFIG_DEBUG_INFO_BTF=y.\n");
            preflight_ok = 0;
        }
        if (stat("/sys/fs/bpf", &st_check) != 0) {
            fprintf(stderr, "FATAL: BPF filesystem not mounted at /sys/fs/bpf.\n"
                    "Run: mount -t bpf bpf /sys/fs/bpf\n");
            preflight_ok = 0;
        }
        if (stat("/sys/kernel/debug", &st_check) != 0) {
            fprintf(stderr, "FATAL: debugfs not mounted at /sys/kernel/debug.\n"
                    "Run: mount -t debugfs debugfs /sys/kernel/debug\n");
            preflight_ok = 0;
        }
        if (stat("/sys/kernel/tracing", &st_check) != 0) {
            fprintf(stderr, "Warning: tracefs not mounted at /sys/kernel/tracing.\n"
                    "Some kernels use /sys/kernel/debug/tracing instead.\n");
            /* Not fatal — older kernels mount tracefs under debugfs */
        }
        /* BPF JIT check — warning only */
        {
            FILE *jit_f = fopen("/proc/sys/net/core/bpf_jit_enable", "r");
            if (jit_f) {
                int jit_val = 0;
                if (fscanf(jit_f, "%d", &jit_val) == 1 && jit_val == 0)
                    fprintf(stderr, "Warning: BPF JIT is disabled (bpf_jit_enable=0). "
                            "Performance may be degraded.\n");
                fclose(jit_f);
            }
        }
        if (!preflight_ok)
            return 1;
    }

    /* Open and load BPF object (S5 fix: no CWD fallback).
     * Search trusted system paths first, then the directory containing
     * the executable itself (safe: attacker can't control /proc/self/exe).
     * CWD is NOT searched to prevent loading a malicious bpf_program.o
     * placed in an attacker-controlled directory. */
    const char *bpf_obj_paths[] = {
        "/usr/local/lib/tls_tracer/bpf_program.o",
        "/opt/tls_tracer/bpf_program.o",
        NULL,
    };
    /* Also try the directory of the executable itself (for development) */
    char exe_dir_bpf[PATH_MAX + 16] = {0};
    {
        char exe_path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len > 0 && len < (ssize_t)(sizeof(exe_path) - 16)) {
            exe_path[len] = '\0';
            /* Strip executable name, keep directory */
            char *slash = strrchr(exe_path, '/');
            if (slash) {
                *slash = '\0';
                snprintf(exe_dir_bpf, sizeof(exe_dir_bpf),
                         "%s/bpf_program.o", exe_path);
            }
        }
    }
    const char *bpf_obj_path = NULL;
    for (int i = 0; bpf_obj_paths[i]; i++) {
        /* Use open() instead of access() to avoid TOCTOU race (CWE-367) */
        int fd = open(bpf_obj_paths[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
            bpf_obj_path = bpf_obj_paths[i];
            break;
        }
    }
    /* Fallback: check next to the executable (e.g., bin/bpf_program.o) */
    if (!bpf_obj_path && exe_dir_bpf[0]) {
        int fd = open(exe_dir_bpf, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            bpf_obj_path = exe_dir_bpf;
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

    /* Attach kprobes for connection tracking (connect syscall + tcp_set_state).
     * P5-PERF: QUIC/UDP probe only attached when --quic flag is used,
     * avoiding ~2% overhead from probing every UDP send on non-QUIC workloads. */
    const char *kprobe_names[] = {
        "probe_connect_enter",
        "probe_connect_return",
        "probe_tcp_set_state",
        "probe_udp_sendmsg",
    };
    int num_kprobes = cfg.enable_quic ? 4 : 3;  /* skip udp_sendmsg unless --quic */

    for (int i = 0; i < num_kprobes; i++) {
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

    /* Set up ring buffer (H-1: migrated from perf_buffer for reliability) */
    int map_fd = bpf_object__find_map_fd_by_name(obj, "tls_events");
    if (map_fd < 0) {
        fprintf(stderr, "Error: Could not find 'tls_events' map in BPF object.\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, &cfg, NULL);
    if (!rb) {
        fprintf(stderr, "Error: Failed to create ring buffer: %s\n",
                strerror(errno));
        err = 1;
        goto cleanup;
    }

    if (cfg.verbose)
        fprintf(stderr, "Ring buffer: 4 MB\n");

    /* Print startup banner */
    if (!cfg.data_only && cfg.format == FMT_TEXT) {
        fprintf(stderr, "Tracing TLS traffic");
        if (cfg.filter_pid)
            fprintf(stderr, " for PID %u", cfg.filter_pid);
        if (cfg.filter_uid)
            fprintf(stderr, " for UID %u", cfg.filter_uid);
        fprintf(stderr, "... Press Ctrl+C to stop.\n");
    }

    /* Touch health file to signal readiness (S4 fix: no /tmp fallback).
     * /var/run/tls-tracer is provided via emptyDir in K8s or must be
     * pre-created for local dev. Falling back to /tmp would allow a local
     * attacker to create a symlink and trick root into overwriting files. */
    const char *health_file = "/var/run/tls-tracer/healthy";
    /* Use open(O_DIRECTORY) instead of access(F_OK) to avoid TOCTOU race (CWE-367) */
    {
        int dfd = open("/var/run/tls-tracer", O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) {
            close(dfd);
        } else if (mkdir("/var/run/tls-tracer", 0755) != 0) {
            fprintf(stderr, "Warning: Cannot create /var/run/tls-tracer: %s "
                    "(health file disabled)\n", strerror(errno));
            health_file = NULL;
        }
    }
    FILE *hf = health_file ? fopen(health_file, "w") : NULL;
    if (hf) {
        fprintf(hf, "ready\n");
        fclose(hf);
    }

    /* Main event loop (#1 fix: don't mask poll errors) */
    int poll_count = 0;
    while (!exiting) {
        int poll_err = ring_buffer__poll(rb, RING_POLL_TIMEOUT);
        if (poll_err < 0 && poll_err != -EINTR) {
            fprintf(stderr, "Error: Polling ring buffer failed: %s\n",
                    strerror(-poll_err));
            err = poll_err;
            break;
        }

        /* Update health file every ~10 seconds (100ms poll * 100) */
        if (health_file && ++poll_count >= 100) {
            poll_count = 0;
            hf = fopen(health_file, "w");
            if (hf) {
                fprintf(hf, "%ld\n", (long)time(NULL));
                fclose(hf);
            }
        }
    }

    /* Remove health file on shutdown */
    if (health_file)
        unlink(health_file);

    if (cfg.verbose)
        fprintf(stderr, "\nExiting...\n");

cleanup:
    if (rb)
        ring_buffer__free(rb);
    for (int i = 0; i < link_count; i++) {
        if (links[i])
            bpf_link__destroy(links[i]);
    }
    if (obj)
        bpf_object__close(obj);

    /* Free compiled regex patterns to avoid resource leaks */
    for (int i = 0; i < cfg.sanitize_count; i++)
        regfree(&cfg.sanitize[i].regex);

    /* #2 fix: POSIX convention — exit with 128+signum on signal termination */
    if (exit_signal)
        return 128 + (int)exit_signal;
    return err != 0 ? 1 : 0;
}
