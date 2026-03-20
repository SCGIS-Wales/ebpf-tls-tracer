#ifndef FILTER_H
#define FILTER_H

#include "tracer.h"
#include <arpa/inet.h>
#include <stdint.h>

/* Limits */
#define MAX_FILTER_CIDRS    64
#define MAX_FILTER_METHODS   8

/* Filter mode: include = only show matching, exclude = hide matching */
enum filter_mode {
    FILTER_MODE_NONE = 0,   /* no filter configured */
    FILTER_MODE_INCLUDE,
    FILTER_MODE_EXCLUDE,
};

/* A single CIDR entry (parsed network + mask) */
struct cidr_entry {
    uint8_t family;         /* AF_INET or AF_INET6 */
    uint8_t prefix_len;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } network;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } mask;
};

/* Protocol filter bitmask */
#define PROTO_FILTER_TCP        (1 << 0)
#define PROTO_FILTER_UDP        (1 << 1)
#define PROTO_FILTER_HTTP       (1 << 2)
#define PROTO_FILTER_HTTPS      (1 << 3)
#define PROTO_FILTER_NON_HTTPS  (1 << 4)

/* Direction filter bitmask */
#define DIR_FILTER_INBOUND      (1 << 0)
#define DIR_FILTER_OUTBOUND     (1 << 1)

/* Complete traffic filter configuration */
struct traffic_filter {
    /* CIDR filters (applied to remote address) */
    struct cidr_entry cidrs[MAX_FILTER_CIDRS];
    int               cidr_count;
    enum filter_mode  cidr_mode;

    /* Protocol filters */
    unsigned int      proto_flags;   /* bitmask of PROTO_FILTER_* */
    enum filter_mode  proto_mode;

    /* HTTP method filters */
    char              methods[MAX_FILTER_METHODS][16];
    int               method_count;
    enum filter_mode  method_mode;

    /* Direction filter */
    unsigned int      dir_flags;     /* bitmask of DIR_FILTER_* */
    enum filter_mode  dir_mode;

    /* Internal: "public" keyword inverts private match */
    int               cidr_public;   /* 1 = match public (NOT private) */
};

/* Forward declare http_info to avoid circular include */
struct http_info;

/* Parse a CIDR string (e.g. "10.0.0.0/8" or "fc00::/7") into a cidr_entry.
 * Returns 0 on success, -1 on error. */
int parse_cidr(const char *str, struct cidr_entry *entry);

/* Expand a keyword ("private", "public", "loopback") into CIDR entries.
 * Appends to f->cidrs. Returns 0 on success, -1 on error. */
int expand_keyword_cidrs(const char *keyword, struct traffic_filter *f);

/* Check if an event's remote IP matches a CIDR entry.
 * Returns 1 if matches, 0 otherwise. */
int ip_matches_cidr(const struct tls_event_t *event, const struct cidr_entry *entry);

/* Check if an event's remote IP matches any private RFC range.
 * Returns 1 if private, 0 if public. */
int ip_is_private(const struct tls_event_t *event);

/* Evaluate all configured filters against an event.
 * http may be NULL if no HTTP info is available.
 * Returns 1 if event should be shown, 0 if filtered out. */
int filter_event(const struct traffic_filter *f,
                 const struct tls_event_t *event,
                 const struct http_info *http);

/* Parse a filter argument in "include:value" or "exclude:value" format.
 * Extracts mode and value pointer. Returns 0 on success, -1 on error. */
int parse_filter_arg(const char *arg, enum filter_mode *mode, const char **value);

/* Parse a protocol name into PROTO_FILTER_* flag. Returns 0 on error. */
unsigned int parse_proto_name(const char *name);

#endif /* FILTER_H */
