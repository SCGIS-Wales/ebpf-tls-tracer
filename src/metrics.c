// SPDX-License-Identifier: MIT
//
// Prometheus metrics endpoint: exposes event counters in OpenMetrics
// format via a minimal HTTP server on a dedicated thread.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include "metrics.h"

#ifndef VERSION
#define VERSION "dev"
#endif

/* Atomic counters — main thread writes, metrics thread reads */
static _Atomic uint64_t m_events_data = 0;
static _Atomic uint64_t m_events_close = 0;
static _Atomic uint64_t m_events_error = 0;
static _Atomic uint64_t m_bytes_request = 0;
static _Atomic uint64_t m_bytes_response = 0;
static _Atomic uint64_t m_ring_buffer_size = 0;

/* Server state */
static int server_fd = -1;
static pthread_t metrics_thread;
static volatile int metrics_running = 0;
static char metrics_http_path[64] = "/metrics";
static time_t metrics_start_time = 0;

/* Event statistics from tls_tracer.c */
extern __u64 stat_events_captured;
extern __u64 stat_events_filtered;

void metrics_update_event(const struct tls_event_t *event)
{
    switch (event->event_type) {
    case EVENT_TLS_DATA:
        atomic_fetch_add(&m_events_data, 1);
        if (event->direction == DIRECTION_WRITE)
            atomic_fetch_add(&m_bytes_request, event->data_len);
        else
            atomic_fetch_add(&m_bytes_response, event->data_len);
        break;
    case EVENT_TLS_CLOSE:
        atomic_fetch_add(&m_events_close, 1);
        break;
    case EVENT_TLS_ERROR:
        atomic_fetch_add(&m_events_error, 1);
        break;
    default:
        break;
    }
}

void metrics_set_ring_buffer_size(__u64 size_bytes)
{
    atomic_store(&m_ring_buffer_size, size_bytes);
}

static int metrics_format(char *buf, size_t bufsize)
{
    time_t uptime = time(NULL) - metrics_start_time;

    return snprintf(buf, bufsize,
        "# HELP tls_tracer_events_total Total TLS events captured\n"
        "# TYPE tls_tracer_events_total counter\n"
        "tls_tracer_events_total{type=\"data\"} %llu\n"
        "tls_tracer_events_total{type=\"close\"} %llu\n"
        "tls_tracer_events_total{type=\"error\"} %llu\n"
        "\n"
        "# HELP tls_tracer_events_filtered_total Events filtered out\n"
        "# TYPE tls_tracer_events_filtered_total counter\n"
        "tls_tracer_events_filtered_total %llu\n"
        "\n"
        "# HELP tls_tracer_bytes_total Bytes captured\n"
        "# TYPE tls_tracer_bytes_total counter\n"
        "tls_tracer_bytes_total{direction=\"request\"} %llu\n"
        "tls_tracer_bytes_total{direction=\"response\"} %llu\n"
        "\n"
        "# HELP tls_tracer_ring_buffer_size_bytes Ring buffer size\n"
        "# TYPE tls_tracer_ring_buffer_size_bytes gauge\n"
        "tls_tracer_ring_buffer_size_bytes %llu\n"
        "\n"
        "# HELP tls_tracer_uptime_seconds Tracer uptime\n"
        "# TYPE tls_tracer_uptime_seconds gauge\n"
        "tls_tracer_uptime_seconds %lld\n"
        "\n"
        "# HELP tls_tracer_info Build info\n"
        "# TYPE tls_tracer_info gauge\n"
        "tls_tracer_info{version=\"%s\"} 1\n",
        (unsigned long long)atomic_load(&m_events_data),
        (unsigned long long)atomic_load(&m_events_close),
        (unsigned long long)atomic_load(&m_events_error),
        (unsigned long long)stat_events_filtered,
        (unsigned long long)atomic_load(&m_bytes_request),
        (unsigned long long)atomic_load(&m_bytes_response),
        (unsigned long long)atomic_load(&m_ring_buffer_size),
        (long long)uptime,
        VERSION);
}

static void handle_client(int client_fd)
{
    char req[512];
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    req[n] = '\0';

    /* Verify it's a GET request for the metrics path */
    if (strncmp(req, "GET ", 4) != 0 ||
        strncmp(req + 4, metrics_http_path, strlen(metrics_http_path)) != 0) {
        const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        send(client_fd, resp, strlen(resp), MSG_NOSIGNAL);
        close(client_fd);
        return;
    }

    /* Format metrics */
    char body[4096];
    int body_len = metrics_format(body, sizeof(body));
    if (body_len < 0)
        body_len = 0;

    char header[256];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "\r\n", body_len);

    send(client_fd, header, (size_t)header_len, MSG_NOSIGNAL);
    send(client_fd, body, (size_t)body_len, MSG_NOSIGNAL);
    close(client_fd);
}

static void *metrics_thread_fn(void *arg)
{
    (void)arg;

    while (metrics_running) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (!metrics_running)
                break;
            continue;
        }
        handle_client(client_fd);
    }
    return NULL;
}

int metrics_start(int port, const char *path)
{
    if (path && path[0])
        snprintf(metrics_http_path, sizeof(metrics_http_path), "%s", path);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
        return -1;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    if (listen(server_fd, 5) < 0) {
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    /* Set accept timeout so thread can check metrics_running flag */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    metrics_start_time = time(NULL);
    metrics_running = 1;

    if (pthread_create(&metrics_thread, NULL, metrics_thread_fn, NULL) != 0) {
        metrics_running = 0;
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    return 0;
}

void metrics_stop(void)
{
    if (!metrics_running)
        return;

    metrics_running = 0;

    /* Close the server socket to unblock accept() */
    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }

    pthread_join(metrics_thread, NULL);
}
