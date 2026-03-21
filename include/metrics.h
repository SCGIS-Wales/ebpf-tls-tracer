#ifndef METRICS_H
#define METRICS_H

#include "tracer.h"

/* Start the Prometheus metrics HTTP server on the given port and bind address.
 * bind_addr may be NULL to default to 127.0.0.1.
 * Returns 0 on success, -1 on error. */
int metrics_start(int port, const char *path, const char *bind_addr);

/* Stop the metrics server and join the thread */
void metrics_stop(void);

/* Update metrics counters from a TLS event (called from handle_event) */
void metrics_update_event(const struct tls_event_t *event);

/* Set the ring buffer size gauge (called once at startup) */
void metrics_set_ring_buffer_size(__u64 size_bytes);

/* Update the dropped events counter (called periodically from main loop) */
void metrics_set_dropped_events(__u64 total_dropped);

/* Update active connections gauge */
void metrics_set_active_connections(__u64 count);

#endif /* METRICS_H */
