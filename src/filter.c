// SPDX-License-Identifier: MIT
//
// Traffic filtering: CIDR matching, protocol classification,
// HTTP method filtering, and direction filtering for inbound/outbound.

#include <stdio.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <stdlib.h>
#include <arpa/inet.h>
#include "filter.h"
#include "protocol.h"

/* RFC 1918 + RFC 6598 + RFC 4193 private ranges */
static const char *private_cidrs_v4[] = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",   /* RFC 6598 Carrier-Grade NAT */
    NULL,
};

static const char *private_cidrs_v6[] = {
    "fc00::/7",         /* RFC 4193 Unique Local */
    NULL,
};

static const char *loopback_cidrs[] = {
    "127.0.0.0/8",
    "::1/128",
    NULL,
};

/* Build a netmask from a prefix length for IPv4 */
static struct in_addr prefix_to_mask_v4(int prefix_len)
{
    struct in_addr mask;
    if (prefix_len == 0)
        mask.s_addr = 0;
    else
        mask.s_addr = htonl(~((1U << (32 - prefix_len)) - 1));
    return mask;
}

/* Build a netmask from a prefix length for IPv6 */
static struct in6_addr prefix_to_mask_v6(int prefix_len)
{
    struct in6_addr mask;
    memset(&mask, 0, sizeof(mask));
    for (int i = 0; i < 16; i++) {
        if (prefix_len >= 8) {
            mask.s6_addr[i] = 0xff;
            prefix_len -= 8;
        } else if (prefix_len > 0) {
            mask.s6_addr[i] = (uint8_t)(0xff << (8 - prefix_len));
            prefix_len = 0;
        } else {
            mask.s6_addr[i] = 0;
        }
    }
    return mask;
}

int parse_cidr(const char *str, struct cidr_entry *entry)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", str);

    /* Split on '/' */
    char *slash = strchr(buf, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    const char *prefix_str = slash + 1;

    char *endp;
    long prefix_len = strtol(prefix_str, &endp, 10);
    if (*endp != '\0' || prefix_len < 0)
        return -1;

    /* Try IPv4 first */
    struct in_addr addr4;
    if (inet_pton(AF_INET, buf, &addr4) == 1) {
        if (prefix_len > 32)
            return -1;
        entry->family = AF_INET;
        entry->prefix_len = (uint8_t)prefix_len;
        entry->mask.v4 = prefix_to_mask_v4((int)prefix_len);
        entry->network.v4.s_addr = addr4.s_addr & entry->mask.v4.s_addr;
        return 0;
    }

    /* Try IPv6 */
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, buf, &addr6) == 1) {
        if (prefix_len > 128)
            return -1;
        entry->family = AF_INET6;
        entry->prefix_len = (uint8_t)prefix_len;
        entry->mask.v6 = prefix_to_mask_v6((int)prefix_len);
        for (int i = 0; i < 16; i++)
            entry->network.v6.s6_addr[i] = addr6.s6_addr[i] & entry->mask.v6.s6_addr[i];
        return 0;
    }

    return -1;
}

int expand_keyword_cidrs(const char *keyword, struct traffic_filter *f)
{
    const char **list = NULL;
    const char **list2 = NULL;

    if (strcasecmp(keyword, "private") == 0) {
        list = private_cidrs_v4;
        list2 = private_cidrs_v6;
    } else if (strcasecmp(keyword, "public") == 0) {
        /* "public" is the inverse of "private" — we store private CIDRs
         * and set a flag to invert the match result */
        list = private_cidrs_v4;
        list2 = private_cidrs_v6;
        f->cidr_public = 1;
    } else if (strcasecmp(keyword, "loopback") == 0) {
        list = loopback_cidrs;
    } else {
        fprintf(stderr, "Error: Unknown network keyword '%s'"
                        " (use 'private', 'public', or 'loopback')\n", keyword);
        return -1;
    }

    for (int i = 0; list && list[i]; i++) {
        if (f->cidr_count >= MAX_FILTER_CIDRS) {
            fprintf(stderr, "Error: Too many CIDR filters (max %d)\n", MAX_FILTER_CIDRS);
            return -1;
        }
        if (parse_cidr(list[i], &f->cidrs[f->cidr_count]) != 0) {
            fprintf(stderr, "Error: Internal CIDR parse failure for '%s'\n", list[i]);
            return -1;
        }
        f->cidr_count++;
    }
    for (int i = 0; list2 && list2[i]; i++) {
        if (f->cidr_count >= MAX_FILTER_CIDRS) {
            fprintf(stderr, "Error: Too many CIDR filters (max %d)\n", MAX_FILTER_CIDRS);
            return -1;
        }
        if (parse_cidr(list2[i], &f->cidrs[f->cidr_count]) != 0) {
            fprintf(stderr, "Error: Internal CIDR parse failure for '%s'\n", list2[i]);
            return -1;
        }
        f->cidr_count++;
    }

    return 0;
}

int ip_matches_cidr(const struct tls_event_t *event, const struct cidr_entry *entry)
{
    if (entry->family == AF_INET && event->addr_family == ADDR_FAMILY_IPV4) {
        return (event->remote_addr_v4 & entry->mask.v4.s_addr)
                == entry->network.v4.s_addr;
    }
    if (entry->family == AF_INET6 && event->addr_family == ADDR_FAMILY_IPV6) {
        for (int i = 0; i < 16; i++) {
            if ((event->remote_addr_v6[i] & entry->mask.v6.s6_addr[i])
                    != entry->network.v6.s6_addr[i])
                return 0;
        }
        return 1;
    }
    return 0;
}

int ip_is_private(const struct tls_event_t *event)
{
    struct cidr_entry entry;

    for (int i = 0; private_cidrs_v4[i]; i++) {
        if (parse_cidr(private_cidrs_v4[i], &entry) == 0 &&
            ip_matches_cidr(event, &entry))
            return 1;
    }
    for (int i = 0; private_cidrs_v6[i]; i++) {
        if (parse_cidr(private_cidrs_v6[i], &entry) == 0 &&
            ip_matches_cidr(event, &entry))
            return 1;
    }
    for (int i = 0; loopback_cidrs[i]; i++) {
        if (parse_cidr(loopback_cidrs[i], &entry) == 0 &&
            ip_matches_cidr(event, &entry))
            return 1;
    }
    return 0;
}

int parse_filter_arg(const char *arg, enum filter_mode *mode, const char **value)
{
    const char *colon = strchr(arg, ':');
    if (!colon || colon == arg) {
        fprintf(stderr, "Error: Filter argument must be 'include:<value>' or "
                        "'exclude:<value>', got '%s'\n", arg);
        return -1;
    }

    size_t prefix_len = (size_t)(colon - arg);
    if (prefix_len == 7 && strncmp(arg, "include", 7) == 0) {
        *mode = FILTER_MODE_INCLUDE;
    } else if (prefix_len == 7 && strncmp(arg, "exclude", 7) == 0) {
        *mode = FILTER_MODE_EXCLUDE;
    } else {
        fprintf(stderr, "Error: Filter mode must be 'include' or 'exclude', got '%.*s'\n",
                (int)prefix_len, arg);
        return -1;
    }

    *value = colon + 1;
    if (**value == '\0') {
        fprintf(stderr, "Error: Filter value cannot be empty in '%s'\n", arg);
        return -1;
    }
    return 0;
}

unsigned int parse_proto_name(const char *name)
{
    if (strcasecmp(name, "tcp") == 0)        return PROTO_FILTER_TCP;
    if (strcasecmp(name, "udp") == 0)        return PROTO_FILTER_UDP;
    if (strcasecmp(name, "http") == 0)       return PROTO_FILTER_HTTP;
    if (strcasecmp(name, "https") == 0)      return PROTO_FILTER_HTTPS;
    if (strcasecmp(name, "non-https") == 0)  return PROTO_FILTER_NON_HTTPS;
    return 0;
}

/* Classify an event's protocol into bitmask flags */
static unsigned int classify_event_proto(const struct tls_event_t *event)
{
    unsigned int flags = 0;

    /* Transport layer */
    if (event->event_type == EVENT_QUIC_DETECTED)
        flags |= PROTO_FILTER_UDP;
    else
        flags |= PROTO_FILTER_TCP;

    /* Application layer */
    if (event->event_type == EVENT_TLS_DATA ||
        event->event_type == EVENT_TLS_HANDSHAKE ||
        event->event_type == EVENT_TLS_ERROR ||
        event->event_type == EVENT_TLS_CLOSE) {
        /* TLS events on well-known HTTPS ports or any TLS data */
        flags |= PROTO_FILTER_HTTPS;
    } else if (event->remote_port == 80 || event->remote_port == 8080) {
        flags |= PROTO_FILTER_HTTP;
    }

    /* non-HTTPS is everything except HTTPS */
    if (!(flags & PROTO_FILTER_HTTPS))
        flags |= PROTO_FILTER_NON_HTTPS;

    return flags;
}

int filter_event(const struct traffic_filter *f,
                 const struct tls_event_t *event,
                 const struct http_info *http)
{
    /* --- CIDR filter --- */
    if (f->cidr_mode != FILTER_MODE_NONE && f->cidr_count > 0) {
        int any_match = 0;
        for (int i = 0; i < f->cidr_count; i++) {
            if (ip_matches_cidr(event, &f->cidrs[i])) {
                any_match = 1;
                break;
            }
        }

        /* "public" keyword inverts match: public = NOT private */
        if (f->cidr_public)
            any_match = !any_match;

        if (f->cidr_mode == FILTER_MODE_INCLUDE && !any_match)
            return 0;
        if (f->cidr_mode == FILTER_MODE_EXCLUDE && any_match)
            return 0;
    }

    /* --- Protocol filter --- */
    if (f->proto_mode != FILTER_MODE_NONE && f->proto_flags != 0) {
        unsigned int event_flags = classify_event_proto(event);
        int matches = (event_flags & f->proto_flags) != 0;

        if (f->proto_mode == FILTER_MODE_INCLUDE && !matches)
            return 0;
        if (f->proto_mode == FILTER_MODE_EXCLUDE && matches)
            return 0;
    }

    /* --- HTTP method filter --- */
    if (f->method_mode != FILTER_MODE_NONE && f->method_count > 0) {
        /* Non-HTTP events pass method filters (method filter only applies
         * to events that have a detected HTTP method) */
        const char *event_method = (http && http->method[0]) ? http->method : NULL;
        if (event_method) {
            int method_match = 0;
            for (int i = 0; i < f->method_count; i++) {
                if (strcasecmp(event_method, f->methods[i]) == 0) {
                    method_match = 1;
                    break;
                }
            }
            if (f->method_mode == FILTER_MODE_INCLUDE && !method_match)
                return 0;
            if (f->method_mode == FILTER_MODE_EXCLUDE && method_match)
                return 0;
        }
    }

    /* --- Direction filter --- */
    if (f->dir_mode != FILTER_MODE_NONE && f->dir_flags != 0) {
        unsigned int event_dir = (event->direction == DIRECTION_READ)
                                 ? DIR_FILTER_INBOUND : DIR_FILTER_OUTBOUND;
        int matches = (event_dir & f->dir_flags) != 0;

        if (f->dir_mode == FILTER_MODE_INCLUDE && !matches)
            return 0;
        if (f->dir_mode == FILTER_MODE_EXCLUDE && matches)
            return 0;
    }

    return 1;  /* event passes all filters */
}
