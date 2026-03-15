#ifndef OUTPUT_H
#define OUTPUT_H

#include "tracer.h"
#include <stddef.h>  /* size_t */

/* Direction string: "REQUEST" or "RESPONSE" */
const char *direction_str(int dir);

/* Format remote address as "ip:port" or "[ipv6]:port" or "-" */
void format_addr(const struct tls_event_t *event, char *buf, size_t buflen);

/* JSON string output with escaping. maxlen=0 reads until NUL. */
void print_json_string_n(const char *s, size_t maxlen);
void print_json_string(const char *s);

/* Hex dump and printable-only output */
void print_hex_dump(const char *data, __u32 len);
void print_printable(const char *data, __u32 len);

/* Ring buffer event handler callback */
int handle_event(void *ctx, void *data, size_t size);

#endif /* OUTPUT_H */
