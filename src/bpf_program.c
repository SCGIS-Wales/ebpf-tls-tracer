// src/bpf_program.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include "tracer.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// Hook function for SSL_read
SEC("uretprobe/SSL_read")
int trace_ssl_read(struct pt_regs *ctx) {
    struct probe_data_t data = {};
    data.timestamp_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();

    // Logic to capture relevant TLS data...
    // Fill in with actual capture logic for cipher suite, IP, URL, etc.

    // Output data to user-space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

// Hook function for SSL_write
SEC("uretprobe/SSL_write")
int trace_ssl_write(struct pt_regs *ctx) {
    // Similar logic to trace_ssl_read...
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
