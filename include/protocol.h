#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "tracer.h"

/* Maximum valid Kafka message size (100 MB) */
#define MAX_KAFKA_MESSAGE_SIZE (100 * 1024 * 1024)

/* HTTP Layer 7 parsed info */
struct http_info {
    char method[16];
    char path[512];
    char host[256];
    char user_agent[256];
    char version[16];
    int  status_code;
    int  websocket;
    int  grpc_status;
};

/* Parse HTTP request/response from raw TLS data */
void parse_http_info(const char *data, __u32 len, struct http_info *info);

/* Kafka wire protocol detection */
int detect_kafka_protocol(const char *data, __u32 len, int *api_key);
int detect_kafka_response(const char *data, __u32 len);
const char *kafka_api_key_name(int api_key);

/* HTTP/2 error parsing */
int parse_h2_error_code(const char *data, __u32 len, int *frame_type_out);
const char *h2_error_code_name(int code);

/* gRPC status from HTTP/2 frame payload */
int parse_grpc_status_from_h2(const char *data, __u32 len);

/* WebSocket close code extraction */
int parse_websocket_close_code(const char *data, __u32 len);

#endif /* PROTOCOL_H */
