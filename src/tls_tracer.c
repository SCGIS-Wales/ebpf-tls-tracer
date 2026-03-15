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

    if (c->format == FMT_JSON) {
        printf("{\"timestamp_ns\":%llu,\"pid\":%u,\"tid\":%u,\"uid\":%u,"
               "\"comm\":\"%.*s\",\"direction\":\"%s\","
               "\"remote_addr\":\"%s\",\"data_len\":%u",
               (unsigned long long)event->timestamp_ns,
               event->pid, event->tid, event->uid,
               MAX_COMM_LEN, event->comm,
               direction_str(event->direction),
               addr_buf,
               data_len);

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
