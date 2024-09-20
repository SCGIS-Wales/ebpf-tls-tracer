// src/user_space.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "tracer.h"

static volatile bool exiting = false;

void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct probe_data_t *event = data;
    printf("Timestamp: %llu, PID: %u, UID: %u\n", event->timestamp_ns, event->pid, event->uid);
    // Print other captured fields...
}

void sigint_handler(int signo) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    struct perf_buffer *pb = NULL;

    signal(SIGINT, sigint_handler);

    obj = bpf_object__open_file("src/bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }

    bpf_object__load(obj);
    prog_fd = bpf_program__fd(bpf_object__find_program_by_title(obj, "uretprobe/SSL_read"));
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");

    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer\n");
        return 1;
    }

    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

    perf_buffer__free(pb);
    bpf_object__close(obj);
    return 0;
}
