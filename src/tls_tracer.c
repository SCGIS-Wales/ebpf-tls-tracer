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
#include <gelf.h>      /* ELF symbol parsing for BoringSSL binary verification */
#include <libelf.h>
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
#include "session.h"
#include "pcap.h"
#include "metrics.h"

#ifndef VERSION
#define VERSION "dev"
#endif

#define RING_POLL_TIMEOUT  100
#define MAX_PROBES         64

static volatile sig_atomic_t exiting = 0;
static volatile sig_atomic_t exit_signal = 0;  /* stores signal number for 128+signum (#2 fix) */

/* Event statistics counters (printed to stderr on exit, read by metrics thread) */
__u64 stat_events_captured = 0;
__u64 stat_events_filtered = 0;

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
    .ring_buffer_mb  = 4,
    .aggregate_timeout = 30,
    .pcap_snaplen    = 4096,
    .metrics_path    = "/metrics",
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

static int find_gnutls_library(char *path, size_t path_len)
{
    const char *candidates[] = {
        "/host/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
        "/host/usr/lib/aarch64-linux-gnu/libgnutls.so.30",
        "/host/usr/lib64/libgnutls.so.30",
        "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
        "/usr/lib/aarch64-linux-gnu/libgnutls.so.30",
        "/usr/lib64/libgnutls.so.30",
        "/usr/lib/libgnutls.so.30",
        NULL,
    };
    for (int i = 0; candidates[i]; i++) {
        int fd = open(candidates[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
            snprintf(path, path_len, "%s", candidates[i]);
            return 0;
        }
    }
    return -1;
}

static int find_wolfssl_library(char *path, size_t path_len)
{
    const char *candidates[] = {
        "/host/usr/lib/x86_64-linux-gnu/libwolfssl.so",
        "/host/usr/lib/aarch64-linux-gnu/libwolfssl.so",
        "/host/usr/lib64/libwolfssl.so",
        "/usr/lib/x86_64-linux-gnu/libwolfssl.so",
        "/usr/lib/aarch64-linux-gnu/libwolfssl.so",
        "/usr/lib64/libwolfssl.so",
        "/usr/lib/libwolfssl.so",
        NULL,
    };
    for (int i = 0; candidates[i]; i++) {
        int fd = open(candidates[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
            snprintf(path, path_len, "%s", candidates[i]);
            return 0;
        }
    }
    return -1;
}

/* Find binary with statically-linked BoringSSL (e.g., Envoy for Apigee Hybrid).
 * Unlike shared libraries, BoringSSL is compiled directly into the binary.
 * Search common Envoy/Istio/Apigee paths in K8s DaemonSet and host contexts. */
static int find_boringssl_binary(char *path, size_t path_len)
{
    const char *candidates[] = {
        /* K8s DaemonSet with host filesystem at /host */
        "/host/usr/local/bin/envoy",
        "/host/usr/bin/envoy",
        /* Direct access (container or host) */
        "/usr/local/bin/envoy",
        "/usr/bin/envoy",
        /* Apigee-specific paths */
        "/host/opt/apigee/bin/envoy",
        "/opt/apigee/bin/envoy",
        NULL,
    };
    for (int i = 0; candidates[i]; i++) {
        int fd = open(candidates[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
            snprintf(path, path_len, "%s", candidates[i]);
            return 0;
        }
    }
    return -1;
}

/* Verify a binary contains required SSL symbols using ELF parsing.
 * Returns 0 if all required symbols found, -1 if any missing.
 * Used to detect stripped binaries before attempting uprobe attachment. */
static int verify_boringssl_symbols(const char *binary_path, int verbose)
{
    const char *required[] = {"SSL_read", "SSL_write"};
    const char *optional[] = {"SSL_get_fd", "SSL_version",
                               "SSL_get_current_cipher", "SSL_get_certificate"};
    int required_count = 2;
    int optional_count = 4;

    int bin_fd = open(binary_path, O_RDONLY);
    if (bin_fd < 0)
        return -1;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        close(bin_fd);
        return -1;
    }

    Elf *elf = elf_begin(bin_fd, ELF_C_READ, NULL);
    if (!elf) {
        close(bin_fd);
        return -1;
    }

    /* Scan all symbol tables (.symtab and .dynsym) */
    int found_required[2] = {0, 0};
    int found_optional[4] = {0, 0, 0, 0};

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL)
            continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data)
            continue;

        int num_syms = (int)(shdr.sh_size / shdr.sh_entsize);
        for (int i = 0; i < num_syms; i++) {
            GElf_Sym sym;
            if (gelf_getsym(data, i, &sym) == NULL)
                continue;

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name)
                continue;

            for (int r = 0; r < required_count; r++) {
                if (strcmp(name, required[r]) == 0)
                    found_required[r] = 1;
            }
            for (int o = 0; o < optional_count; o++) {
                if (strcmp(name, optional[o]) == 0)
                    found_optional[o] = 1;
            }
        }
    }

    elf_end(elf);
    close(bin_fd);

    int all_required = 1;
    for (int r = 0; r < required_count; r++) {
        if (!found_required[r]) {
            fprintf(stderr, "Error: Required symbol '%s' not found in %s\n",
                    required[r], binary_path);
            all_required = 0;
        }
    }

    if (verbose) {
        for (int r = 0; r < required_count; r++)
            fprintf(stderr, "  %s: %s %s\n", found_required[r] ? "Found" : "MISSING",
                    required[r], found_required[r] ? "" : "(REQUIRED)");
        for (int o = 0; o < optional_count; o++)
            fprintf(stderr, "  %s: %s %s\n", found_optional[o] ? "Found" : "Missing",
                    optional[o], found_optional[o] ? "" : "(optional)");
    }

    return all_required ? 0 : -1;
}

/* Probe specification for library-specific uprobe attachment */
struct probe_spec {
    const char *bpf_name;
    const char *func_name;
    int is_retprobe;
};

static const struct probe_spec gnutls_probes[] = {
    {"probe_gnutls_recv_enter",       "gnutls_record_recv",       0},
    {"probe_gnutls_recv_return",      "gnutls_record_recv",       1},
    {"probe_gnutls_send_enter",       "gnutls_record_send",       0},
    {"probe_gnutls_send_return",      "gnutls_record_send",       1},
    {"probe_gnutls_transport_enter",  "gnutls_transport_get_int", 0},
    {"probe_gnutls_transport_return", "gnutls_transport_get_int", 1},
};

static const struct probe_spec wolfssl_probes[] = {
    {"probe_wolfssl_read_enter",    "wolfSSL_read",   0},
    {"probe_wolfssl_read_return",   "wolfSSL_read",   1},
    {"probe_wolfssl_write_enter",   "wolfSSL_write",  0},
    {"probe_wolfssl_write_return",  "wolfSSL_write",  1},
    {"probe_wolfssl_getfd_enter",   "wolfSSL_get_fd", 0},
    {"probe_wolfssl_getfd_return",  "wolfSSL_get_fd", 1},
};

/* BoringSSL probes: attach to statically-linked binary (e.g., Envoy).
 * Same function names as OpenSSL (API-compatible), but mapped to
 * BoringSSL-specific BPF programs with syscall-based fd correlation. */
static const struct probe_spec boringssl_probes[] = {
    {"probe_boringssl_read_enter",    "SSL_read",    0},
    {"probe_boringssl_read_return",   "SSL_read",    1},
    {"probe_boringssl_write_enter",   "SSL_write",   0},
    {"probe_boringssl_write_return",  "SSL_write",   1},
    {"probe_boringssl_getfd_enter",   "SSL_get_fd",  0},
    {"probe_boringssl_getfd_return",  "SSL_get_fd",  1},
};

/* Optional BoringSSL probes — attach if symbols present, no error if missing */
static const struct probe_spec boringssl_optional_probes[] = {
    {"probe_boringssl_version_enter",  "SSL_version",             0},
    {"probe_boringssl_version_return", "SSL_version",             1},
    {"probe_boringssl_cipher_enter",   "SSL_get_current_cipher",  0},
    {"probe_boringssl_cipher_return",  "SSL_get_current_cipher",  1},
    {"probe_boringssl_cert_enter",     "SSL_get_certificate",     0},
    {"probe_boringssl_cert_return",    "SSL_get_certificate",     1},
};

/* Attach probes for a specific TLS library.
 * Returns the number of probes successfully attached. */
static int attach_library_probes(struct bpf_object *obj,
                                  const struct probe_spec *probes,
                                  int probe_count,
                                  const char *lib_path,
                                  const char *lib_name,
                                  struct bpf_link **links,
                                  int *link_count,
                                  int verbose)
{
    int attached = 0;
    for (int i = 0; i < probe_count; i++) {
        struct bpf_program *p = bpf_object__find_program_by_name(obj, probes[i].bpf_name);
        if (!p) {
            if (verbose)
                fprintf(stderr, "Note: BPF program '%s' not found for %s\n",
                        probes[i].bpf_name, lib_name);
            continue;
        }
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
            .retprobe = probes[i].is_retprobe,
            .func_name = probes[i].func_name,
        );
        links[*link_count] = bpf_program__attach_uprobe_opts(
            p, -1, lib_path, 0, &uprobe_opts);
        if (!links[*link_count] || libbpf_get_error(links[*link_count])) {
            links[*link_count] = NULL;
            if (verbose)
                fprintf(stderr, "Warning: Could not attach %s uprobe for %s (%s)\n",
                        probes[i].func_name, lib_name,
                        probes[i].is_retprobe ? "return" : "entry");
            continue;
        }
        (*link_count)++;
        attached++;
    }
    return attached;
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
        "  -B, --boringssl-bin PATH  Path to binary with statically-linked BoringSSL\n"
        "                            (e.g., /usr/local/bin/envoy for Apigee Hybrid/Istio).\n"
        "                            Auto-detects common Envoy paths if not specified.\n"
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
        "  -H, --headers-only     Capture HTTP headers only (truncate at body boundary)\n"
        "  -r, --ring-buffer-size MB  Ring buffer size in MB (power-of-2, 1-64, default: 4)\n"
        "  -A, --aggregate        Enable session aggregation (emit summaries on close/timeout)\n"
        "      --aggregate-timeout SECS  Idle timeout before summary emission (default: 30)\n"
        "      --aggregate-only   Only emit session summaries, suppress per-event output\n"
        "      --pcap FILE        Write captured events to pcap-ng file\n"
        "      --pcap-snaplen N   Max bytes per packet in pcap (default: 4096)\n"
        "      --metrics-port PORT  Enable Prometheus metrics endpoint on PORT\n"
        "      --metrics-path PATH  HTTP path for metrics (default: /metrics)\n"
        "  -c, --max-events N     Exit after capturing N events\n"
        "  -t, --duration SECS    Exit after SECS seconds\n"
        "  -v, --verbose          Verbose output\n"
        "  -V, --version          Show version and exit\n"
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
    struct pcap_handle *pcap = NULL;
    int err = 0;
    int link_count = 0;

    static const struct option long_opts[] = {
        {"pid",          required_argument, NULL, 'p'},
        {"uid",          required_argument, NULL, 'u'},
        {"lib",          required_argument, NULL, 'l'},
        {"format",       required_argument, NULL, 'f'},
        {"hex",          no_argument,       NULL, 'x'},
        {"data-only",    no_argument,       NULL, 'd'},
        {"sanitize",     required_argument, NULL, 's'},
        {"quic",         no_argument,       NULL, 'q'},
        {"net",          required_argument, NULL, 'n'},
        {"proto",        required_argument, NULL, 'P'},
        {"method",       required_argument, NULL, 'm'},
        {"dir",          required_argument, NULL, 'D'},
        {"headers-only", no_argument,       NULL, 'H'},
        {"max-events",   required_argument, NULL, 'c'},
        {"duration",     required_argument, NULL, 't'},
        {"ring-buffer-size", required_argument, NULL, 'r'},
        {"aggregate",    no_argument,       NULL, 'A'},
        {"aggregate-timeout", required_argument, NULL, 1001},
        {"aggregate-only", no_argument,     NULL, 1002},
        {"pcap",         required_argument, NULL, 1003},
        {"pcap-snaplen", required_argument, NULL, 1004},
        {"metrics-port", required_argument, NULL, 1005},
        {"metrics-path", required_argument, NULL, 1006},
        {"boringssl-bin", required_argument, NULL, 'B'},
        {"verbose",      no_argument,       NULL, 'v'},
        {"version",      no_argument,       NULL, 'V'},
        {"help",         no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:u:l:B:f:xds:qn:P:m:D:Hc:t:r:AvVh", long_opts, NULL)) != -1) {
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
        case 'B':
            snprintf(cfg.boringssl_bin, sizeof(cfg.boringssl_bin), "%s", optarg);
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
        case 'H':
            cfg.headers_only = 1;
            break;
        case 'c': {
            char *endp;
            errno = 0;
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val == 0 || val > UINT_MAX || errno == ERANGE) {
                fprintf(stderr, "Error: Invalid max-events '%s'\n", optarg);
                return 1;
            }
            cfg.max_events = (__u64)val;
            break;
        }
        case 't': {
            char *endp;
            errno = 0;
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val == 0 || val > 86400 || errno == ERANGE) {
                fprintf(stderr, "Error: Invalid duration '%s' (1-86400 seconds)\n", optarg);
                return 1;
            }
            cfg.duration = (int)val;
            break;
        }
        case 'r': {
            char *endp;
            errno = 0;
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val == 0 || val > 64 || errno == ERANGE) {
                fprintf(stderr, "Error: Invalid ring-buffer-size '%s' (1-64 MB)\n", optarg);
                return 1;
            }
            /* Must be power of 2 */
            if ((val & (val - 1)) != 0) {
                fprintf(stderr, "Error: ring-buffer-size must be a power of 2 (got %lu)\n", val);
                return 1;
            }
            cfg.ring_buffer_mb = (__u32)val;
            break;
        }
        case 'A':
            cfg.aggregate = 1;
            break;
        case 1001: {  /* --aggregate-timeout */
            char *endp;
            errno = 0;
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val == 0 || val > 3600 || errno == ERANGE) {
                fprintf(stderr, "Error: Invalid aggregate-timeout '%s' (1-3600 seconds)\n", optarg);
                return 1;
            }
            cfg.aggregate_timeout = (int)val;
            break;
        }
        case 1002:  /* --aggregate-only */
            cfg.aggregate = 1;
            cfg.aggregate_only = 1;
            break;
        case 1003:  /* --pcap */
            snprintf(cfg.pcap_path, sizeof(cfg.pcap_path), "%s", optarg);
            break;
        case 1004: {  /* --pcap-snaplen */
            char *endp;
            errno = 0;
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val == 0 || val > 65535 || errno == ERANGE) {
                fprintf(stderr, "Error: Invalid pcap-snaplen '%s'\n", optarg);
                return 1;
            }
            cfg.pcap_snaplen = (int)val;
            break;
        }
        case 1005: {  /* --metrics-port */
            char *endp;
            errno = 0;
            unsigned long val = strtoul(optarg, &endp, 10);
            if (*endp != '\0' || val == 0 || val > 65535 || errno == ERANGE) {
                fprintf(stderr, "Error: Invalid metrics-port '%s'\n", optarg);
                return 1;
            }
            cfg.metrics_port = (int)val;
            break;
        }
        case 1006:  /* --metrics-path */
            snprintf(cfg.metrics_path, sizeof(cfg.metrics_path), "%s", optarg);
            break;
        case 'v':
            cfg.verbose = 1;
            break;
        case 'V':
            printf("tls_tracer %s\n", VERSION);
            return 0;
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

    /* Find SSL library (OpenSSL).
     * Not fatal if BoringSSL binary is specified/detected — allows running
     * on systems where only Envoy with statically-linked BoringSSL exists. */
    if (cfg.ssl_lib[0] == '\0') {
        if (find_ssl_library(cfg.ssl_lib, sizeof(cfg.ssl_lib)) != 0) {
            if (cfg.boringssl_bin[0]) {
                if (cfg.verbose)
                    fprintf(stderr, "OpenSSL not found (using BoringSSL binary instead)\n");
            } else {
                /* Check if auto-detect finds a BoringSSL binary */
                char tmp_boring[256] = "";
                if (find_boringssl_binary(tmp_boring, sizeof(tmp_boring)) == 0) {
                    if (cfg.verbose)
                        fprintf(stderr, "OpenSSL not found, but found BoringSSL binary: %s\n", tmp_boring);
                } else {
                    fprintf(stderr, "Error: Could not find libssl.so. "
                            "Specify with --lib PATH or --boringssl-bin PATH.\n");
                    return 1;
                }
            }
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

    if (cfg.ssl_lib[0]) {
        if (cfg.verbose)
            fprintf(stderr, "Using SSL library: %s\n", cfg.ssl_lib);
        validate_openssl_version(cfg.ssl_lib);
    }

    /* Detect host/node IP for JSON enrichment (EC2 instance IP) */
    detect_host_ip(cfg.host_ip, sizeof(cfg.host_ip));
    if (cfg.host_ip[0] && cfg.verbose)
        fprintf(stderr, "Host IP: %s\n", cfg.host_ip);

    /* Detect AWS ECS runtime environment */
    if (getenv("ECS_CONTAINER_METADATA_URI_V4") || getenv("ECS_CONTAINER_METADATA_URI")) {
        cfg.ecs_detected = 1;
        if (cfg.verbose)
            fprintf(stderr, "Runtime: AWS ECS detected\n");
    }

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

    /* Override ring buffer size before loading (must be between open and load) */
    {
        struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "tls_events");
        if (rb_map) {
            err = bpf_map__set_max_entries(rb_map, cfg.ring_buffer_mb * 1024 * 1024);
            if (err) {
                fprintf(stderr, "Warning: Could not set ring buffer size to %u MB: %s\n",
                        cfg.ring_buffer_mb, strerror(-err));
            }
        }
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

    /* Attach uprobes to OpenSSL functions (skip if no OpenSSL library found) */
    int uprobe_count = 0;
    if (cfg.ssl_lib[0]) {
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
            fprintf(stderr, "Error: Could not attach any OpenSSL probes. "
                    "Check that the SSL library path is correct and has symbols.\n");
            err = 1;
            goto cleanup;
        }

        if (cfg.verbose)
            fprintf(stderr, "Attached %d/%d OpenSSL probes.\n", uprobe_count, 10);
    }

    /* Auto-detect and attach GnuTLS probes */
    {
        char gnutls_lib[256] = "";
        if (find_gnutls_library(gnutls_lib, sizeof(gnutls_lib)) == 0) {
            int n = attach_library_probes(obj, gnutls_probes,
                        sizeof(gnutls_probes) / sizeof(gnutls_probes[0]),
                        gnutls_lib, "GnuTLS", links, &link_count, cfg.verbose);
            if (n > 0 && cfg.verbose)
                fprintf(stderr, "Attached %d/%d GnuTLS probes (%s)\n",
                        n, (int)(sizeof(gnutls_probes) / sizeof(gnutls_probes[0])),
                        gnutls_lib);
        } else if (cfg.verbose) {
            fprintf(stderr, "GnuTLS library not found (optional)\n");
        }
    }

    /* Auto-detect and attach wolfSSL probes */
    {
        char wolfssl_lib[256] = "";
        if (find_wolfssl_library(wolfssl_lib, sizeof(wolfssl_lib)) == 0) {
            int n = attach_library_probes(obj, wolfssl_probes,
                        sizeof(wolfssl_probes) / sizeof(wolfssl_probes[0]),
                        wolfssl_lib, "wolfSSL", links, &link_count, cfg.verbose);
            if (n > 0 && cfg.verbose)
                fprintf(stderr, "Attached %d/%d wolfSSL probes (%s)\n",
                        n, (int)(sizeof(wolfssl_probes) / sizeof(wolfssl_probes[0])),
                        wolfssl_lib);
        } else if (cfg.verbose) {
            fprintf(stderr, "wolfSSL library not found (optional)\n");
        }
    }

    /* Auto-detect and attach BoringSSL probes (statically-linked in binary).
     * BoringSSL is used by Envoy (Apigee Hybrid / Istio ingress gateway).
     * Unlike shared libraries, uprobes attach to the binary itself. */
    {
        char boringssl_bin[256] = "";
        int boringssl_explicit = (cfg.boringssl_bin[0] != '\0');

        if (boringssl_explicit) {
            snprintf(boringssl_bin, sizeof(boringssl_bin), "%s", cfg.boringssl_bin);
            int bfd = open(boringssl_bin, O_RDONLY);
            if (bfd < 0) {
                fprintf(stderr, "Error: Cannot access BoringSSL binary '%s': %s\n",
                        boringssl_bin, strerror(errno));
                err = 1;
                goto cleanup;
            }
            close(bfd);
        } else {
            find_boringssl_binary(boringssl_bin, sizeof(boringssl_bin));
        }

        if (boringssl_bin[0]) {
            if (verify_boringssl_symbols(boringssl_bin, cfg.verbose) == 0) {
                int n = attach_library_probes(obj, boringssl_probes,
                            (int)(sizeof(boringssl_probes) / sizeof(boringssl_probes[0])),
                            boringssl_bin, "BoringSSL", links, &link_count, cfg.verbose);
                /* Also try optional probes (version, cipher, cert) — no error if missing */
                int n2 = attach_library_probes(obj, boringssl_optional_probes,
                            (int)(sizeof(boringssl_optional_probes) / sizeof(boringssl_optional_probes[0])),
                            boringssl_bin, "BoringSSL (optional)", links, &link_count, 0);

                if (n > 0)
                    fprintf(stderr, "Attached %d+%d BoringSSL probes (%s)\n",
                            n, n2, boringssl_bin);
                else if (boringssl_explicit) {
                    fprintf(stderr, "Error: Could not attach any BoringSSL probes to %s\n",
                            boringssl_bin);
                    err = 1;
                    goto cleanup;
                }
            } else if (boringssl_explicit) {
                fprintf(stderr, "Error: %s is missing required SSL symbols (binary may be stripped).\n"
                        "Hint: Check with: readelf -s %s | grep SSL_read\n",
                        boringssl_bin, boringssl_bin);
                err = 1;
                goto cleanup;
            } else if (cfg.verbose) {
                fprintf(stderr, "Note: Found %s but SSL symbols missing (stripped?), skipping BoringSSL\n",
                        boringssl_bin);
            }
        } else if (cfg.verbose) {
            fprintf(stderr, "BoringSSL binary not found (optional)\n");
        }
    }

    /* Attach BoringSSL syscall-based fd correlation kprobes.
     * These are lightweight — only a single map lookup per syscall,
     * and only match for threads currently inside a BoringSSL SSL call. */
    {
        const char *boringssl_kprobe_names[] = {
            "probe_boringssl_sys_write",
            "probe_boringssl_sys_writev",
            "probe_boringssl_sys_sendmsg",
        };
        for (int i = 0; i < 3; i++) {
            struct bpf_program *kp = bpf_object__find_program_by_name(obj,
                                        boringssl_kprobe_names[i]);
            if (!kp) {
                if (cfg.verbose)
                    fprintf(stderr, "Note: BoringSSL kprobe '%s' not found\n",
                            boringssl_kprobe_names[i]);
                continue;
            }
            links[link_count] = bpf_program__attach(kp);
            if (!links[link_count] || libbpf_get_error(links[link_count])) {
                links[link_count] = NULL;
                if (cfg.verbose)
                    fprintf(stderr, "Warning: Could not attach BoringSSL kprobe '%s'\n",
                            boringssl_kprobe_names[i]);
                continue;
            }
            link_count++;
            if (cfg.verbose)
                fprintf(stderr, "Attached BoringSSL kprobe: %s\n",
                        boringssl_kprobe_names[i]);
        }
    }

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
        fprintf(stderr, "Ring buffer: %u MB\n", cfg.ring_buffer_mb);

    /* Open PCAP file if requested */
    if (cfg.pcap_path[0]) {
        pcap = pcap_open(cfg.pcap_path);
        if (!pcap) {
            fprintf(stderr, "Error: Failed to open pcap file '%s'\n", cfg.pcap_path);
            err = 1;
            goto cleanup;
        }
        if (cfg.verbose)
            fprintf(stderr, "PCAP output: %s (snaplen=%d)\n",
                    cfg.pcap_path, cfg.pcap_snaplen);
    }

    /* Start Prometheus metrics server if requested */
    if (cfg.metrics_port > 0) {
        metrics_set_ring_buffer_size((__u64)cfg.ring_buffer_mb * 1024 * 1024);
        if (metrics_start(cfg.metrics_port, cfg.metrics_path) != 0) {
            fprintf(stderr, "Error: Failed to start metrics server on port %d\n",
                    cfg.metrics_port);
            err = 1;
            goto cleanup;
        }
        if (cfg.verbose)
            fprintf(stderr, "Metrics: http://0.0.0.0:%d%s\n",
                    cfg.metrics_port, cfg.metrics_path);
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
    time_t start_time = time(NULL);
    while (!exiting) {
        int poll_err = ring_buffer__poll(rb, RING_POLL_TIMEOUT);
        if (poll_err < 0 && poll_err != -EINTR) {
            fprintf(stderr, "Error: Polling ring buffer failed: %s\n",
                    strerror(-poll_err));
            err = poll_err;
            break;
        }

        /* Check max-events limit */
        if (cfg.max_events > 0 && stat_events_captured >= cfg.max_events) {
            if (cfg.verbose)
                fprintf(stderr, "Reached max-events limit (%llu)\n",
                        (unsigned long long)cfg.max_events);
            break;
        }

        /* Check duration limit */
        if (cfg.duration > 0 && (time(NULL) - start_time) >= cfg.duration) {
            if (cfg.verbose)
                fprintf(stderr, "Reached duration limit (%d seconds)\n", cfg.duration);
            break;
        }

        /* Periodic tasks every ~10 poll cycles (~1 second) */
        poll_count++;

        /* Session sweep: emit summaries for idle connections */
        if (cfg.aggregate && poll_count % 10 == 0) {
            session_sweep(time(NULL), cfg.aggregate_timeout,
                          session_emit_json, &cfg);
        }

        /* Update health file every ~10 seconds (100ms poll * 100) */
        if (health_file && poll_count >= 100) {
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

    /* Print event statistics on exit */
    {
        time_t elapsed = time(NULL) - start_time;
        __u64 dropped = 0;
        /* Read BPF dropped_events per-CPU array to get total drops */
        int drop_fd = bpf_object__find_map_fd_by_name(obj, "dropped_events");
        if (drop_fd >= 0) {
            int nr_cpus = libbpf_num_possible_cpus();
            if (nr_cpus > 0 && nr_cpus <= 1024) {
                __u64 *per_cpu = calloc((size_t)nr_cpus, sizeof(__u64));
                if (per_cpu) {
                    __u32 key = 0;
                    if (bpf_map_lookup_elem(drop_fd, &key, per_cpu) == 0) {
                        for (int i = 0; i < nr_cpus; i++)
                            dropped += per_cpu[i];
                    }
                    free(per_cpu);
                }
            }
        }
        fprintf(stderr, "\nEvents captured: %llu, filtered: %llu, dropped: %llu, "
                "runtime: %llds\n",
                (unsigned long long)stat_events_captured,
                (unsigned long long)stat_events_filtered,
                (unsigned long long)dropped,
                (long long)elapsed);
    }

cleanup:
    if (cfg.metrics_port > 0)
        metrics_stop();
    if (pcap)
        pcap_close(pcap);
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
