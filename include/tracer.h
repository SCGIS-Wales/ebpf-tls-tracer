// include/tracer.h
#ifndef TRACER_H
#define TRACER_H

#include <linux/types.h>

#define MAX_URL_LEN 256
#define MAX_METHOD_LEN 8

struct probe_data_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    char cipher_suite[32];
    char client_ip[INET6_ADDRSTRLEN];
    char request_url[MAX_URL_LEN];
    char http_method[MAX_METHOD_LEN];
    int response_code;
};

#endif // TRACER_H
