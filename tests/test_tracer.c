// SPDX-License-Identifier: MIT
//
// Unit tests for TLS Tracer data structures and helpers

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "tracer.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  TEST  %-50s", #name); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf(" PASS\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        printf(" FAIL: %s\n", msg); \
    } while (0)

#define ASSERT_EQ(a, b, msg) \
    do { \
        if ((a) != (b)) { FAIL(msg); return; } \
    } while (0)

#define ASSERT_STR_EQ(a, b, msg) \
    do { \
        if (strcmp((a), (b)) != 0) { FAIL(msg); return; } \
    } while (0)

/* --- Test: struct sizes and field offsets --- */

static void test_tls_event_struct_size(void)
{
    TEST(tls_event_struct_size);
    /* Struct must be large enough to hold all fields + MAX_DATA_LEN data */
    assert(sizeof(struct tls_event_t) >= MAX_DATA_LEN);
    PASS();
}

static void test_tls_event_data_field_offset(void)
{
    TEST(tls_event_data_field_at_end);
    /* data[] should be the last field so perf events can truncate */
    struct tls_event_t event;
    size_t data_offset = (size_t)((char *)event.data - (char *)&event);
    size_t expected_end = data_offset + MAX_DATA_LEN;
    ASSERT_EQ(expected_end, sizeof(struct tls_event_t),
              "data field should extend to end of struct");
    PASS();
}

/* --- Test: constants --- */

static void test_direction_constants(void)
{
    TEST(direction_constants);
    ASSERT_EQ(DIRECTION_READ, 0, "DIRECTION_READ should be 0");
    ASSERT_EQ(DIRECTION_WRITE, 1, "DIRECTION_WRITE should be 1");
    PASS();
}

static void test_event_type_constants(void)
{
    TEST(event_type_constants);
    ASSERT_EQ(EVENT_TLS_DATA, 1, "EVENT_TLS_DATA should be 1");
    ASSERT_EQ(EVENT_TLS_HANDSHAKE, 2, "EVENT_TLS_HANDSHAKE should be 2");
    PASS();
}

static void test_max_constants(void)
{
    TEST(max_constants);
    ASSERT_EQ(MAX_URL_LEN, 256, "MAX_URL_LEN");
    ASSERT_EQ(MAX_METHOD_LEN, 16, "MAX_METHOD_LEN");
    ASSERT_EQ(MAX_COMM_LEN, 16, "MAX_COMM_LEN");
    ASSERT_EQ(MAX_CIPHER_LEN, 64, "MAX_CIPHER_LEN");
    ASSERT_EQ(MAX_IP_LEN, 46, "MAX_IP_LEN");
    ASSERT_EQ(MAX_DATA_LEN, 4096, "MAX_DATA_LEN");
    PASS();
}

/* --- Test: struct initialization --- */

static void test_zero_init(void)
{
    TEST(zero_initialization);
    struct tls_event_t event = {};
    ASSERT_EQ(event.timestamp_ns, 0, "timestamp should be 0");
    ASSERT_EQ(event.pid, 0, "pid should be 0");
    ASSERT_EQ(event.tid, 0, "tid should be 0");
    ASSERT_EQ(event.uid, 0, "uid should be 0");
    ASSERT_EQ(event.data_len, 0, "data_len should be 0");
    ASSERT_EQ(event.tls_version, 0, "tls_version should be 0");
    ASSERT_EQ(event.direction, 0, "direction should be 0 (READ)");
    ASSERT_EQ(event.event_type, 0, "event_type should be 0");
    ASSERT_EQ(event.comm[0], '\0', "comm should be empty");
    ASSERT_EQ(event.data[0], '\0', "data should be empty");
    PASS();
}

static void test_field_assignment(void)
{
    TEST(field_assignment);
    struct tls_event_t event = {};

    event.timestamp_ns = 1234567890;
    event.pid = 42;
    event.tid = 43;
    event.uid = 1000;
    event.data_len = 5;
    event.direction = DIRECTION_WRITE;
    event.event_type = EVENT_TLS_DATA;
    strncpy(event.comm, "test_proc", MAX_COMM_LEN);
    memcpy(event.data, "hello", 5);

    ASSERT_EQ(event.timestamp_ns, 1234567890ULL, "timestamp");
    ASSERT_EQ(event.pid, 42U, "pid");
    ASSERT_EQ(event.tid, 43U, "tid");
    ASSERT_EQ(event.uid, 1000U, "uid");
    ASSERT_EQ(event.data_len, 5U, "data_len");
    ASSERT_EQ(event.direction, DIRECTION_WRITE, "direction");
    ASSERT_EQ(event.event_type, EVENT_TLS_DATA, "event_type");
    ASSERT_STR_EQ(event.comm, "test_proc", "comm");
    ASSERT_EQ(memcmp(event.data, "hello", 5), 0, "data content");
    PASS();
}

/* --- Test: data boundary conditions --- */

static void test_max_data_fill(void)
{
    TEST(max_data_fill);
    struct tls_event_t event = {};
    memset(event.data, 'A', MAX_DATA_LEN);
    event.data_len = MAX_DATA_LEN;

    ASSERT_EQ(event.data[0], 'A', "first byte");
    ASSERT_EQ(event.data[MAX_DATA_LEN - 1], 'A', "last byte");
    ASSERT_EQ(event.data_len, (unsigned)MAX_DATA_LEN, "data_len at max");
    PASS();
}

static void test_comm_max_length(void)
{
    TEST(comm_max_length);
    struct tls_event_t event = {};
    memset(event.comm, 'x', MAX_COMM_LEN);

    ASSERT_EQ(event.comm[0], 'x', "first char");
    ASSERT_EQ(event.comm[MAX_COMM_LEN - 1], 'x', "last char");
    PASS();
}

/* --- Test: data_len power of 2 (required for BPF masking) --- */

static void test_max_data_len_power_of_2(void)
{
    TEST(max_data_len_is_power_of_2);
    /* BPF programs use (len & (MAX_DATA_LEN - 1)) for bounds checking.
     * This only works correctly if MAX_DATA_LEN is a power of 2. */
    int is_power_of_2 = (MAX_DATA_LEN > 0) && ((MAX_DATA_LEN & (MAX_DATA_LEN - 1)) == 0);
    ASSERT_EQ(is_power_of_2, 1, "MAX_DATA_LEN must be a power of 2 for BPF masking");
    PASS();
}

int main(void)
{
    printf("\n=== TLS Tracer Unit Tests ===\n\n");

    test_tls_event_struct_size();
    test_tls_event_data_field_offset();
    test_direction_constants();
    test_event_type_constants();
    test_max_constants();
    test_zero_init();
    test_field_assignment();
    test_max_data_fill();
    test_comm_max_length();
    test_max_data_len_power_of_2();

    printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
