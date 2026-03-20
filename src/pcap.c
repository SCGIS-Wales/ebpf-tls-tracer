// SPDX-License-Identifier: MIT
//
// PCAP-ng export: writes captured TLS events as pcap-ng files
// with synthesized IP+TCP headers for analysis in Wireshark/tcpdump.
//
// Limitations:
// - Captures decrypted TLS payload, not raw wire packets
// - TCP seq/ack numbers are synthetic (not real)
// - No SYN/FIN/RST frames — only data frames

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "pcap.h"

/* pcap-ng block types */
#define PCAPNG_SHB_TYPE  0x0A0D0D0A
#define PCAPNG_IDB_TYPE  0x00000001
#define PCAPNG_EPB_TYPE  0x00000006

/* pcap-ng byte order magic */
#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D

/* Link types */
#define LINKTYPE_RAW 101  /* Raw IP, no link-layer header */

struct pcap_handle {
    FILE *fp;
};

/* Global handle (simple single-file approach) */
static struct pcap_handle global_pcap = { .fp = NULL };

/* Write a 32-bit little-endian value */
static void write_u32(FILE *fp, __u32 val)
{
    fwrite(&val, 4, 1, fp);
}

/* Write a 16-bit little-endian value */
static void write_u16(FILE *fp, __u16 val)
{
    fwrite(&val, 2, 1, fp);
}

/* Pad to 4-byte boundary */
static void write_padding(FILE *fp, __u32 data_len)
{
    __u32 pad = (4 - (data_len & 3)) & 3;
    __u8 zeros[4] = {0};
    if (pad > 0)
        fwrite(zeros, 1, pad, fp);
}

/* Write Section Header Block (SHB) */
static void write_shb(FILE *fp)
{
    __u32 block_total_len = 28;  /* type(4) + len(4) + bom(4) + ver_major(2) + ver_minor(2) + section_len(8) + len(4) */
    write_u32(fp, PCAPNG_SHB_TYPE);
    write_u32(fp, block_total_len);
    write_u32(fp, PCAPNG_BYTE_ORDER_MAGIC);
    write_u16(fp, 1);   /* version major */
    write_u16(fp, 0);   /* version minor */
    /* section length: -1 (unspecified) */
    __u64 section_len = 0xFFFFFFFFFFFFFFFFULL;
    fwrite(&section_len, 8, 1, fp);
    write_u32(fp, block_total_len);
}

/* Write Interface Description Block (IDB) */
static void write_idb(FILE *fp)
{
    __u32 block_total_len = 20;  /* type(4) + len(4) + linktype(2) + reserved(2) + snaplen(4) + len(4) */
    write_u32(fp, PCAPNG_IDB_TYPE);
    write_u32(fp, block_total_len);
    write_u16(fp, LINKTYPE_RAW);  /* Raw IP */
    write_u16(fp, 0);             /* reserved */
    write_u32(fp, 65535);         /* snaplen */
    write_u32(fp, block_total_len);
}

struct pcap_handle *pcap_open(const char *path)
{
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return NULL;

    write_shb(fp);
    write_idb(fp);
    fflush(fp);

    global_pcap.fp = fp;
    return &global_pcap;
}

/* Synthesize and write an Enhanced Packet Block (EPB) */
void pcap_write_event(struct pcap_handle *h, const struct tls_event_t *event)
{
    if (!h || !h->fp || event->data_len == 0)
        return;

    __u32 data_len = event->data_len;
    if (data_len > MAX_DATA_LEN)
        data_len = MAX_DATA_LEN;

    int is_ipv6 = (event->addr_family == ADDR_FAMILY_IPV6);
    __u32 ip_hdr_len = is_ipv6 ? 40 : 20;
    __u32 tcp_hdr_len = 20;
    __u32 pkt_len = ip_hdr_len + tcp_hdr_len + data_len;
    __u32 pkt_padded = pkt_len + ((4 - (pkt_len & 3)) & 3);

    /* EPB: type(4) + len(4) + iface(4) + ts_high(4) + ts_low(4) + caplen(4) + origlen(4) + packet + padding + len(4) */
    __u32 block_total_len = 32 + pkt_padded;

    /* Timestamp: convert ns to microseconds */
    __u64 ts_us = event->timestamp_ns / 1000;
    __u32 ts_high = (__u32)(ts_us >> 32);
    __u32 ts_low = (__u32)(ts_us & 0xFFFFFFFF);

    /* Determine src/dst based on direction */
    __u32 src_v4, dst_v4;
    const __u8 *src_v6, *dst_v6;
    __u16 src_port, dst_port;

    if (event->direction == DIRECTION_WRITE) {
        src_v4 = event->local_addr_v4;
        dst_v4 = event->remote_addr_v4;
        src_v6 = event->local_addr_v6;
        dst_v6 = event->remote_addr_v6;
        src_port = event->local_port;
        dst_port = event->remote_port;
    } else {
        src_v4 = event->remote_addr_v4;
        dst_v4 = event->local_addr_v4;
        src_v6 = event->remote_addr_v6;
        dst_v6 = event->local_addr_v6;
        src_port = event->remote_port;
        dst_port = event->local_port;
    }

    FILE *fp = h->fp;

    /* Write EPB header */
    write_u32(fp, PCAPNG_EPB_TYPE);
    write_u32(fp, block_total_len);
    write_u32(fp, 0);        /* interface ID */
    write_u32(fp, ts_high);
    write_u32(fp, ts_low);
    write_u32(fp, pkt_len);  /* captured length */
    write_u32(fp, pkt_len);  /* original length */

    if (is_ipv6) {
        /* IPv6 header (40 bytes) */
        __u8 ipv6_hdr[40] = {0};
        ipv6_hdr[0] = 0x60;  /* version 6 */
        __u16 payload_len = htons(tcp_hdr_len + data_len);
        memcpy(&ipv6_hdr[4], &payload_len, 2);
        ipv6_hdr[6] = 6;     /* next header: TCP */
        ipv6_hdr[7] = 64;    /* hop limit */
        memcpy(&ipv6_hdr[8], src_v6, 16);
        memcpy(&ipv6_hdr[24], dst_v6, 16);
        fwrite(ipv6_hdr, 1, 40, fp);
    } else {
        /* IPv4 header (20 bytes) */
        __u8 ipv4_hdr[20] = {0};
        ipv4_hdr[0] = 0x45;  /* version 4, IHL 5 */
        __u16 total_len = htons(ip_hdr_len + tcp_hdr_len + data_len);
        memcpy(&ipv4_hdr[2], &total_len, 2);
        ipv4_hdr[8] = 64;    /* TTL */
        ipv4_hdr[9] = 6;     /* protocol: TCP */
        memcpy(&ipv4_hdr[12], &src_v4, 4);
        memcpy(&ipv4_hdr[16], &dst_v4, 4);
        fwrite(ipv4_hdr, 1, 20, fp);
    }

    /* TCP header (20 bytes) */
    __u8 tcp_hdr[20] = {0};
    __u16 sp = htons(src_port);
    __u16 dp = htons(dst_port);
    memcpy(&tcp_hdr[0], &sp, 2);
    memcpy(&tcp_hdr[2], &dp, 2);
    /* seq=0, ack=0 */
    tcp_hdr[12] = 0x50;  /* data offset: 5 (20 bytes) */
    tcp_hdr[13] = 0x18;  /* flags: PSH|ACK */
    __u16 window = htons(65535);
    memcpy(&tcp_hdr[14], &window, 2);
    fwrite(tcp_hdr, 1, 20, fp);

    /* Payload */
    fwrite(event->data, 1, data_len, fp);

    /* Padding to 4-byte boundary */
    write_padding(fp, pkt_len);

    /* Block total length (repeated) */
    write_u32(fp, block_total_len);

    fflush(fp);
}

void pcap_write_event_from_tls(const char *path, const struct tls_event_t *event)
{
    (void)path;
    if (global_pcap.fp)
        pcap_write_event(&global_pcap, event);
}

void pcap_close(struct pcap_handle *h)
{
    if (h && h->fp) {
        fflush(h->fp);
        fclose(h->fp);
        h->fp = NULL;
    }
}
