#ifndef METRICS_H
#define METRICS_H

#include "tracer.h"

/* Start the Prometheus metrics HTTP server on the given port.
 * Returns 0 on success, -1 on error. */
int metrics_start(int port, const char *path);

/* Stop the metrics server and join the thread */
void metrics_stop(void);

/* Update metrics counters from a TLS event (called from handle_event) */
void metrics_update_event(const struct tls_event_t *event);

/* Set the ring buffer size gauge (called once at startup) */
void metrics_set_ring_buffer_size(__u64 size_bytes);

#endif /* METRICS_H */
