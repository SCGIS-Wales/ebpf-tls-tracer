// SPDX-License-Identifier: MIT
//
// tls_tracer - eBPF-based TLS traffic interceptor
//
// Attaches uprobes to OpenSSL's SSL_read/SSL_write to capture
// plaintext data flowing through TLS connections, along with
// the remote IP address and port of each connection.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tracer.h"

#define PERF_BUFFER_PAGES  64
#define PERF_POLL_TIMEOUT  100
#define MAX_PROBES         8

static volatile sig_atomic_t exiting = 0;

/* Output format */
enum output_fmt {
    FMT_TEXT,
    FMT_JSON,
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
};

static struct config cfg = {
    .format     = FMT_TEXT,
    .ssl_lib    = "",
    .filter_pid = 0,
    .filter_uid = 0,
    .hex_dump   = 0,
    .data_only  = 0,
    .verbose    = 0,
};

static void sig_handler(int signo)
{
    (void)signo;
    exiting = 1;
}

static const char *direction_str(int dir)
{
    return dir == DIRECTION_READ ? "READ" : "WRITE";
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
};

static void parse_http_info(const char *data, __u32 len, struct http_info *info)
{
    memset(info, 0, sizeof(*info));
    if (len < 4)
        return;

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

    if (!found)
        return;

    /* Extract Host header */
    const char *host_hdr = NULL;
    const char *p = data;
    const char *end = data + len;
    while (p < end - 6) {
        if ((*p == '\n' || p == data) &&
            (strncasecmp(p + (p == data ? 0 : 1), "Host:", 5) == 0 ||
             strncasecmp(p + (p == data ? 0 : 1), "host:", 5) == 0)) {
            host_hdr = p + (p == data ? 5 : 6);
            /* Skip whitespace */
            while (host_hdr < end && (*host_hdr == ' ' || *host_hdr == '\t'))
                host_hdr++;
            break;
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

/* Print a JSON string value, escaping special characters */
static void print_json_string(const char *s)
{
    putchar('"');
    for (; *s; s++) {
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
        /* Get wall-clock timestamp */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        char iso_time[64];
        struct tm *tm = gmtime(&ts.tv_sec);
        strftime(iso_time, sizeof(iso_time), "%Y-%m-%dT%H:%M:%S", tm);

        /* K8s metadata enrichment */
        struct k8s_meta meta;
        get_k8s_meta((pid_t)event->pid, &meta);

        /* HTTP Layer 7 parsing (only for WRITE direction) */
        struct http_info http;
        memset(&http, 0, sizeof(http));
        if (event->direction == DIRECTION_WRITE && data_len > 0)
            parse_http_info(event->data, data_len, &http);

        /* Emit one self-contained JSON event */
        printf("{\"timestamp\":\"%s.%06ldZ\",\"timestamp_ns\":%llu,"
               "\"pid\":%u,\"tid\":%u,\"uid\":%u,"
               "\"comm\":\"%.*s\",\"direction\":\"%s\","
               "\"src_ip\":\"%s\",\"src_port\":%u,"
               "\"dst_ip\":\"%s\",\"dst_port\":%u,"
               "\"data_len\":%u",
               iso_time, ts.tv_nsec / 1000,
               (unsigned long long)event->timestamp_ns,
               event->pid, event->tid, event->uid,
               MAX_COMM_LEN, event->comm,
               direction_str(event->direction),
               local_ip, event->local_port,
               remote_ip, event->remote_port,
               data_len);

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

        /* HTTP Layer 7 fields (only if HTTP detected) */
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

        if (!c->data_only) {
            printf(",\"data\":\"");
            for (__u32 i = 0; i < data_len; i++)
                printf("\\x%02x", (unsigned char)event->data[i]);
            printf("\"");
        }
        printf("}\n");
    } else {
        if (!c->data_only) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            struct tm *tm = localtime(&ts.tv_sec);
            char timebuf[64];
            strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

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
        "  -v, --verbose          Verbose output\n"
        "  -h, --help             Show this help message\n"
        "\n"
        "Examples:\n"
        "  %s                     Trace all TLS traffic\n"
        "  %s -p 1234             Trace TLS traffic for PID 1234\n"
        "  %s -f json             Output in JSON format\n"
        "  %s -x -p 1234          Hex dump of TLS data for PID 1234\n"
        "\n"
        "Requires root privileges (or CAP_BPF + CAP_PERFMON).\n",
        prog, prog, prog, prog, prog);
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
        {"verbose",   no_argument,       NULL, 'v'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:u:l:f:xdvh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            cfg.filter_pid = (__u32)atoi(optarg);
            break;
        case 'u':
            cfg.filter_uid = (__u32)atoi(optarg);
            break;
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

    /* Open and load BPF object */
    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error: Failed to open BPF object file: %s\n",
                strerror(errno));
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

    /* Attach kprobes for connection tracking (connect syscall) */
    const char *kprobe_names[] = {
        "probe_connect_enter",
        "probe_connect_return",
    };

    for (int i = 0; i < 2; i++) {
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
    };
    int is_retprobe[] = {0, 1, 0, 1};
    const char *func_names[] = {
        "SSL_read",
        "SSL_read",
        "SSL_write",
        "SSL_write",
    };

    int uprobe_count = 0;
    for (int i = 0; i < 4; i++) {
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
        fprintf(stderr, "Attached %d/%d SSL probes.\n", uprobe_count, 4);

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

    /* Main event loop */
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error: Polling perf buffer failed: %s\n",
                    strerror(-err));
            break;
        }
        err = 0;
    }

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

    return err != 0 ? 1 : 0;
}
