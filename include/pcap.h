#ifndef PCAP_H
#define PCAP_H

#include "tracer.h"

/* Opaque handle for pcap-ng writer */
struct pcap_handle;

/* Open a pcap-ng file for writing. Returns NULL on error. */
struct pcap_handle *pcap_open(const char *path);

/* Write a TLS event to pcap-ng file with synthesized IP+TCP headers.
 * data_len is the number of payload bytes to write (already truncated
 * for --headers-only / --pcap-snaplen); it is clamped to event->data_len. */
void pcap_write_event(struct pcap_handle *h, const struct tls_event_t *event,
                      __u32 data_len);

/* Convenience: write using path lookup (for use from output.c) */
void pcap_write_event_from_tls(const char *path, const struct tls_event_t *event,
                               __u32 data_len);

/* Close the pcap-ng file */
void pcap_close(struct pcap_handle *h);

#endif /* PCAP_H */
