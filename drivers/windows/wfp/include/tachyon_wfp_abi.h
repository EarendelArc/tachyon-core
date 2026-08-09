// SPDX-License-Identifier: Apache-2.0
#pragma once

// This header is shared by the kernel driver and the privileged Helper only.
// Every multi-byte integer is little-endian and every wire structure is packed.

#include <stdint.h>

#define TACHYON_WFP_ABI_MAGIC 0x46574754u /* "TGWF" */
#define TACHYON_WFP_ABI_MAJOR 2u
#define TACHYON_WFP_ABI_MINOR 0u
#define TACHYON_WFP_MAX_MESSAGE_SIZE (64u * 1024u)
#define TACHYON_WFP_MAX_PAYLOAD_SIZE 65507u
#define TACHYON_WFP_DEFAULT_QUEUE_CAPACITY 512u
#define TACHYON_WFP_DEFAULT_RESIDENT_BYTES (8u * 1024u * 1024u)
#define TACHYON_WFP_DEFAULT_VERDICT_TIMEOUT_MS 250u
#define TACHYON_WFP_DRIVER_BUILD_ID_INIT \
    { 0x4f, 0xbb, 0x3a, 0xa7, 0x69, 0x1d, 0x41, 0x02, 0xa5, 0x52, 0x17, 0x84, 0x64, 0x20, 0x00, 0x02 }
#define TACHYON_WFP_HELPER_BUILD_ID_INIT \
    { 0x54, 0x47, 0x48, 0x50, 0x2d, 0x41, 0x42, 0x49, 0x2d, 0x32, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x01 }
#define TACHYON_WFP_HELPER_SERVICE_SID_ASCII \
    "S-1-5-80-1356003462-1404488631-2219046169-124586702-828318184"
#define TACHYON_WFP_HELPER_SERVICE_SID_WIDE \
    L"S-1-5-80-1356003462-1404488631-2219046169-124586702-828318184"
#define TACHYON_WFP_HELPER_SERVICE_SID_SHA256_INIT \
    { 0xf0, 0xe1, 0x7a, 0x28, 0x5d, 0xbc, 0x50, 0xc3, 0xea, 0x98, 0xb7, 0xf1, 0x42, 0xef, 0x89, 0x30, \
      0x4b, 0x08, 0xcd, 0x82, 0x1f, 0x42, 0x6f, 0x89, 0x3a, 0x0b, 0x72, 0xc7, 0x24, 0xff, 0x38, 0x6a }

#define TACHYON_WFP_CAP_FLOW_V4 (UINT64_C(1) << 0)
#define TACHYON_WFP_CAP_FLOW_V6 (UINT64_C(1) << 1)
#define TACHYON_WFP_CAP_DATAGRAM_V4 (UINT64_C(1) << 2)
#define TACHYON_WFP_CAP_DATAGRAM_V6 (UINT64_C(1) << 3)
#define TACHYON_WFP_CAP_PROCESS_IDENTITY (UINT64_C(1) << 4)
#define TACHYON_WFP_CAP_USER_SID (UINT64_C(1) << 5)
#define TACHYON_WFP_CAP_APP_ID (UINT64_C(1) << 6)
#define TACHYON_WFP_CAP_INJECT_SEND (UINT64_C(1) << 7)
#define TACHYON_WFP_CAP_INJECTION_STATE (UINT64_C(1) << 8)
#define TACHYON_WFP_CAP_BOUNDED_QUEUE (UINT64_C(1) << 9)
#define TACHYON_WFP_CAP_FAIL_OPEN_TIMEOUT (UINT64_C(1) << 10)
#define TACHYON_WFP_CAP_POLICY_GENERATION (UINT64_C(1) << 11)

#define TACHYON_WFP_REQUIRED_CAPABILITIES                                      \
    (TACHYON_WFP_CAP_FLOW_V4 | TACHYON_WFP_CAP_FLOW_V6 |                     \
     TACHYON_WFP_CAP_DATAGRAM_V4 | TACHYON_WFP_CAP_DATAGRAM_V6 |             \
     TACHYON_WFP_CAP_PROCESS_IDENTITY | TACHYON_WFP_CAP_USER_SID |           \
     TACHYON_WFP_CAP_APP_ID | TACHYON_WFP_CAP_INJECT_SEND |                  \
     TACHYON_WFP_CAP_INJECTION_STATE |                                        \
     TACHYON_WFP_CAP_BOUNDED_QUEUE | TACHYON_WFP_CAP_FAIL_OPEN_TIMEOUT |     \
     TACHYON_WFP_CAP_POLICY_GENERATION)

enum TACHYON_WFP_MESSAGE_KIND {
    TachyonWfpMessageNegotiateRequest = 1,
    TachyonWfpMessageNegotiateResponse = 2,
    TachyonWfpMessagePolicy = 3,
    TachyonWfpMessageDisablePolicy = 4,
    TachyonWfpMessageCapture = 5,
    TachyonWfpMessageVerdict = 6,
    TachyonWfpMessageStatistics = 7
};

enum TACHYON_WFP_DIRECTION {
    TachyonWfpDirectionOutbound = 1,
    TachyonWfpDirectionInbound = 2
};

enum TACHYON_WFP_INJECTION_STATE {
    TachyonWfpInjectionNotInjected = 0,
    TachyonWfpInjectionBySelf = 1,
    TachyonWfpInjectionByOther = 2,
    TachyonWfpInjectionPreviouslyBySelf = 3
};

enum TACHYON_WFP_VERDICT_ACTION {
    TachyonWfpVerdictTunnel = 1,
    TachyonWfpVerdictPermitDirect = 2,
    TachyonWfpVerdictDrop = 3
};

enum TACHYON_WFP_FAIL_POLICY {
    TachyonWfpFailOpenDirect = 1
};

enum TACHYON_WFP_POLICY_FLAGS {
    TachyonWfpPolicyMatchPid = 1u << 0,
    TachyonWfpPolicyMatchProcessStart = 1u << 1,
    TachyonWfpPolicyMatchAppIdHash = 1u << 2,
    TachyonWfpPolicyMatchUserSidHash = 1u << 3
};

#pragma pack(push, 1)

typedef struct TACHYON_WFP_MESSAGE_HEADER {
    uint32_t magic;
    uint16_t header_size;
    uint16_t abi_major;
    uint16_t abi_minor;
    uint16_t kind;
    uint32_t flags;
    uint32_t total_size;
    uint64_t request_id;
    uint32_t reserved;
} TACHYON_WFP_MESSAGE_HEADER;

typedef struct TACHYON_WFP_NEGOTIATE_REQUEST {
    TACHYON_WFP_MESSAGE_HEADER header;
    uint8_t helper_build_id[16];
    uint64_t required_capabilities;
    uint32_t requested_queue_capacity;
    uint32_t requested_timeout_ms;
} TACHYON_WFP_NEGOTIATE_REQUEST;

typedef struct TACHYON_WFP_NEGOTIATE_RESPONSE {
    TACHYON_WFP_MESSAGE_HEADER header;
    uint8_t driver_build_id[16];
    uint64_t capabilities;
    uint32_t max_message_size;
    uint32_t queue_capacity;
    uint32_t verdict_timeout_ms;
    uint32_t fail_policy;
    uint8_t service_sid_hash[32];
} TACHYON_WFP_NEGOTIATE_RESPONSE;

typedef struct TACHYON_WFP_POLICY_HEADER {
    TACHYON_WFP_MESSAGE_HEADER header;
    uint64_t generation;
    uint8_t lease_nonce[16];
    uint32_t entry_count;
    uint32_t policy_flags;
} TACHYON_WFP_POLICY_HEADER;

typedef struct TACHYON_WFP_POLICY_ENTRY {
    uint64_t process_id;
    uint64_t process_start_key;
    uint8_t app_id_hash[32];
    uint8_t user_sid_hash[32];
    uint32_t match_flags;
    uint32_t reserved;
} TACHYON_WFP_POLICY_ENTRY;

typedef struct TACHYON_WFP_DISABLE_POLICY {
    TACHYON_WFP_MESSAGE_HEADER header;
    uint64_t generation;
    uint8_t lease_nonce[16];
    uint64_t last_sequence;
} TACHYON_WFP_DISABLE_POLICY;

typedef struct TACHYON_WFP_CAPTURE_RECORD {
    TACHYON_WFP_MESSAGE_HEADER header;
    uint8_t flow_id[16];
    uint64_t generation;
    uint8_t lease_nonce[16];
    uint64_t sequence;
    uint64_t process_id;
    uint64_t process_start_key;
    uint8_t app_id_hash[32];
    uint8_t user_sid_hash[32];
    uint16_t address_family;
    uint8_t direction;
    uint8_t protocol;
    uint32_t injection_state;
    uint32_t compartment_id;
    uint32_t interface_index;
    uint32_t sub_interface_index;
    uint8_t local_address[16];
    uint8_t remote_address[16];
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t payload_size;
    uint32_t reserved;
    uint8_t payload[1];
} TACHYON_WFP_CAPTURE_RECORD;

typedef struct TACHYON_WFP_VERDICT {
    TACHYON_WFP_MESSAGE_HEADER header;
    uint8_t flow_id[16];
    uint64_t generation;
    uint8_t lease_nonce[16];
    uint64_t sequence;
    uint32_t action;
    uint32_t reason;
    uint32_t payload_size;
    uint32_t reserved;
    uint8_t payload[1];
} TACHYON_WFP_VERDICT;

typedef struct TACHYON_WFP_STATISTICS {
    TACHYON_WFP_MESSAGE_HEADER header;
    uint64_t captured;
    uint64_t permitted;
    uint64_t dropped;
    uint64_t injected;
    uint64_t self_injected;
    uint64_t queue_overflow;
    uint64_t verdict_timeout;
    uint64_t rejected_frames;
    uint32_t queue_depth;
    uint32_t pending_verdicts;
} TACHYON_WFP_STATISTICS;

#pragma pack(pop)

#define TACHYON_WFP_HEADER_SIZE 32u
#define TACHYON_WFP_NEGOTIATE_REQUEST_SIZE 64u
#define TACHYON_WFP_NEGOTIATE_RESPONSE_SIZE 104u
#define TACHYON_WFP_POLICY_HEADER_SIZE 64u
#define TACHYON_WFP_POLICY_ENTRY_SIZE 88u
#define TACHYON_WFP_DISABLE_POLICY_SIZE 64u
#define TACHYON_WFP_CAPTURE_HEADER_SIZE 224u
#define TACHYON_WFP_VERDICT_HEADER_SIZE 96u
#define TACHYON_WFP_STATISTICS_SIZE 104u

#if defined(_KERNEL_MODE)
#include <devioctl.h>
#define IOCTL_TACHYON_WFP_NEGOTIATE \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_TACHYON_WFP_SET_POLICY \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x901, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define IOCTL_TACHYON_WFP_DISABLE_POLICY \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x902, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_TACHYON_WFP_DEQUEUE \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x903, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_TACHYON_WFP_VERDICT \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x904, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define IOCTL_TACHYON_WFP_STATISTICS \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x905, METHOD_BUFFERED, FILE_READ_DATA)
#endif

#if defined(__cplusplus)
static_assert(sizeof(TACHYON_WFP_MESSAGE_HEADER) == TACHYON_WFP_HEADER_SIZE, "ABI header size");
static_assert(sizeof(TACHYON_WFP_NEGOTIATE_REQUEST) == TACHYON_WFP_NEGOTIATE_REQUEST_SIZE, "negotiate request size");
static_assert(sizeof(TACHYON_WFP_NEGOTIATE_RESPONSE) == TACHYON_WFP_NEGOTIATE_RESPONSE_SIZE, "negotiate response size");
static_assert(sizeof(TACHYON_WFP_POLICY_HEADER) == TACHYON_WFP_POLICY_HEADER_SIZE, "policy header size");
static_assert(sizeof(TACHYON_WFP_POLICY_ENTRY) == TACHYON_WFP_POLICY_ENTRY_SIZE, "policy entry size");
static_assert(sizeof(TACHYON_WFP_DISABLE_POLICY) == TACHYON_WFP_DISABLE_POLICY_SIZE, "disable size");
static_assert(offsetof(TACHYON_WFP_CAPTURE_RECORD, payload) == TACHYON_WFP_CAPTURE_HEADER_SIZE, "capture header size");
static_assert(offsetof(TACHYON_WFP_VERDICT, payload) == TACHYON_WFP_VERDICT_HEADER_SIZE, "verdict header size");
static_assert(sizeof(TACHYON_WFP_STATISTICS) == TACHYON_WFP_STATISTICS_SIZE, "statistics size");
#else
_Static_assert(sizeof(TACHYON_WFP_MESSAGE_HEADER) == TACHYON_WFP_HEADER_SIZE, "ABI header size");
_Static_assert(sizeof(TACHYON_WFP_NEGOTIATE_REQUEST) == TACHYON_WFP_NEGOTIATE_REQUEST_SIZE, "negotiate request size");
_Static_assert(sizeof(TACHYON_WFP_NEGOTIATE_RESPONSE) == TACHYON_WFP_NEGOTIATE_RESPONSE_SIZE, "negotiate response size");
_Static_assert(sizeof(TACHYON_WFP_POLICY_HEADER) == TACHYON_WFP_POLICY_HEADER_SIZE, "policy header size");
_Static_assert(sizeof(TACHYON_WFP_POLICY_ENTRY) == TACHYON_WFP_POLICY_ENTRY_SIZE, "policy entry size");
_Static_assert(sizeof(TACHYON_WFP_DISABLE_POLICY) == TACHYON_WFP_DISABLE_POLICY_SIZE, "disable size");
_Static_assert(offsetof(TACHYON_WFP_CAPTURE_RECORD, payload) == TACHYON_WFP_CAPTURE_HEADER_SIZE, "capture header size");
_Static_assert(offsetof(TACHYON_WFP_VERDICT, payload) == TACHYON_WFP_VERDICT_HEADER_SIZE, "verdict header size");
_Static_assert(sizeof(TACHYON_WFP_STATISTICS) == TACHYON_WFP_STATISTICS_SIZE, "statistics size");
#endif
