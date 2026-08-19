// SPDX-License-Identifier: Apache-2.0
#pragma once

// This header is shared by the kernel driver and the privileged Helper only.
// Every multi-byte integer is little-endian and every wire structure is packed.

#if defined(_KERNEL_MODE)
typedef UINT8 TACHYON_WFP_UINT8;
typedef UINT16 TACHYON_WFP_UINT16;
typedef UINT32 TACHYON_WFP_UINT32;
typedef UINT64 TACHYON_WFP_UINT64;
#ifndef UINT64_C
#define UINT64_C(value) value##ULL
#endif
#define TACHYON_WFP_OFFSET_OF(type, member) FIELD_OFFSET(type, member)
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t TACHYON_WFP_UINT8;
typedef uint16_t TACHYON_WFP_UINT16;
typedef uint32_t TACHYON_WFP_UINT32;
typedef uint64_t TACHYON_WFP_UINT64;
#define TACHYON_WFP_OFFSET_OF(type, member) offsetof(type, member)
#endif

#define TACHYON_WFP_JOIN_INNER(left, right) left##right
#define TACHYON_WFP_JOIN(left, right) TACHYON_WFP_JOIN_INNER(left, right)

#if defined(__cplusplus)
#define TACHYON_WFP_STATIC_ASSERT(condition, message) static_assert((condition), message)
#elif defined(_MSC_VER)
#define TACHYON_WFP_STATIC_ASSERT(condition, message) \
    typedef char TACHYON_WFP_JOIN(tachyon_wfp_static_assert_, __COUNTER__)[(condition) ? 1 : -1]
#else
#define TACHYON_WFP_STATIC_ASSERT(condition, message) _Static_assert((condition), message)
#endif

#if defined(_MSC_VER)
#define TACHYON_WFP_ALIGNOF(type) __alignof(type)
#elif defined(__cplusplus)
#define TACHYON_WFP_ALIGNOF(type) alignof(type)
#elif defined(__clang__) || defined(__GNUC__)
#define TACHYON_WFP_ALIGNOF(type) __alignof__(type)
#else
#define TACHYON_WFP_ALIGNOF(type) _Alignof(type)
#endif

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
#define TACHYON_WFP_CAP_USER_SECURITY_DESCRIPTOR (UINT64_C(1) << 5)
#define TACHYON_WFP_CAP_APP_ID (UINT64_C(1) << 6)
#define TACHYON_WFP_CAP_INJECT_SEND (UINT64_C(1) << 7)
#define TACHYON_WFP_CAP_INJECTION_STATE (UINT64_C(1) << 8)
#define TACHYON_WFP_CAP_BOUNDED_QUEUE (UINT64_C(1) << 9)
#define TACHYON_WFP_CAP_FAIL_OPEN_TIMEOUT (UINT64_C(1) << 10)
#define TACHYON_WFP_CAP_POLICY_GENERATION (UINT64_C(1) << 11)

#define TACHYON_WFP_REQUIRED_CAPABILITIES                                      \
    (TACHYON_WFP_CAP_FLOW_V4 | TACHYON_WFP_CAP_FLOW_V6 |                     \
     TACHYON_WFP_CAP_DATAGRAM_V4 | TACHYON_WFP_CAP_DATAGRAM_V6 |             \
     TACHYON_WFP_CAP_PROCESS_IDENTITY |                                     \
     TACHYON_WFP_CAP_USER_SECURITY_DESCRIPTOR |                             \
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
    TachyonWfpPolicyMatchUserSecurityDescriptorHash = 1u << 3
};

#pragma pack(push, 1)

typedef struct TACHYON_WFP_MESSAGE_HEADER {
    TACHYON_WFP_UINT32 magic;
    TACHYON_WFP_UINT16 header_size;
    TACHYON_WFP_UINT16 abi_major;
    TACHYON_WFP_UINT16 abi_minor;
    TACHYON_WFP_UINT16 kind;
    TACHYON_WFP_UINT32 flags;
    TACHYON_WFP_UINT32 total_size;
    TACHYON_WFP_UINT64 request_id;
    TACHYON_WFP_UINT32 reserved;
} TACHYON_WFP_MESSAGE_HEADER;

typedef struct TACHYON_WFP_NEGOTIATE_REQUEST {
    TACHYON_WFP_MESSAGE_HEADER header;
    TACHYON_WFP_UINT8 helper_build_id[16];
    TACHYON_WFP_UINT64 required_capabilities;
    TACHYON_WFP_UINT32 requested_queue_capacity;
    TACHYON_WFP_UINT32 requested_timeout_ms;
} TACHYON_WFP_NEGOTIATE_REQUEST;

typedef struct TACHYON_WFP_NEGOTIATE_RESPONSE {
    TACHYON_WFP_MESSAGE_HEADER header;
    TACHYON_WFP_UINT8 driver_build_id[16];
    TACHYON_WFP_UINT64 capabilities;
    TACHYON_WFP_UINT32 max_message_size;
    TACHYON_WFP_UINT32 queue_capacity;
    TACHYON_WFP_UINT32 verdict_timeout_ms;
    TACHYON_WFP_UINT32 fail_policy;
    TACHYON_WFP_UINT8 service_sid_hash[32];
} TACHYON_WFP_NEGOTIATE_RESPONSE;

typedef struct TACHYON_WFP_POLICY_HEADER {
    TACHYON_WFP_MESSAGE_HEADER header;
    TACHYON_WFP_UINT64 generation;
    TACHYON_WFP_UINT8 lease_nonce[16];
    TACHYON_WFP_UINT32 entry_count;
    TACHYON_WFP_UINT32 policy_flags;
} TACHYON_WFP_POLICY_HEADER;

typedef struct TACHYON_WFP_POLICY_ENTRY {
    TACHYON_WFP_UINT64 process_id;
    TACHYON_WFP_UINT64 process_start_key;
    TACHYON_WFP_UINT8 app_id_hash[32];
    /* SHA-256 of the exact self-relative security descriptor bytes from ALE_USER_ID. */
    TACHYON_WFP_UINT8 user_security_descriptor_hash[32];
    TACHYON_WFP_UINT32 match_flags;
    TACHYON_WFP_UINT32 reserved;
} TACHYON_WFP_POLICY_ENTRY;

typedef struct TACHYON_WFP_DISABLE_POLICY {
    TACHYON_WFP_MESSAGE_HEADER header;
    TACHYON_WFP_UINT64 generation;
    TACHYON_WFP_UINT8 lease_nonce[16];
    TACHYON_WFP_UINT64 last_sequence;
} TACHYON_WFP_DISABLE_POLICY;

typedef struct TACHYON_WFP_CAPTURE_RECORD {
    TACHYON_WFP_MESSAGE_HEADER header;
    TACHYON_WFP_UINT8 flow_id[16];
    TACHYON_WFP_UINT64 generation;
    TACHYON_WFP_UINT8 lease_nonce[16];
    TACHYON_WFP_UINT64 sequence;
    TACHYON_WFP_UINT64 process_id;
    TACHYON_WFP_UINT64 process_start_key;
    TACHYON_WFP_UINT8 app_id_hash[32];
    TACHYON_WFP_UINT8 user_security_descriptor_hash[32];
    TACHYON_WFP_UINT16 address_family;
    TACHYON_WFP_UINT8 direction;
    TACHYON_WFP_UINT8 protocol;
    TACHYON_WFP_UINT32 injection_state;
    TACHYON_WFP_UINT32 compartment_id;
    TACHYON_WFP_UINT32 interface_index;
    TACHYON_WFP_UINT32 sub_interface_index;
    TACHYON_WFP_UINT8 local_address[16];
    TACHYON_WFP_UINT8 remote_address[16];
    TACHYON_WFP_UINT16 local_port;
    TACHYON_WFP_UINT16 remote_port;
    TACHYON_WFP_UINT32 payload_size;
    TACHYON_WFP_UINT32 reserved;
    TACHYON_WFP_UINT8 payload[1];
} TACHYON_WFP_CAPTURE_RECORD;

typedef struct TACHYON_WFP_VERDICT {
    TACHYON_WFP_MESSAGE_HEADER header;
    TACHYON_WFP_UINT8 flow_id[16];
    TACHYON_WFP_UINT64 generation;
    TACHYON_WFP_UINT8 lease_nonce[16];
    TACHYON_WFP_UINT64 sequence;
    TACHYON_WFP_UINT32 action;
    TACHYON_WFP_UINT32 reason;
    TACHYON_WFP_UINT32 payload_size;
    TACHYON_WFP_UINT32 reserved;
    TACHYON_WFP_UINT8 payload[1];
} TACHYON_WFP_VERDICT;

typedef struct TACHYON_WFP_STATISTICS {
    TACHYON_WFP_MESSAGE_HEADER header;
    TACHYON_WFP_UINT64 captured;
    TACHYON_WFP_UINT64 permitted;
    TACHYON_WFP_UINT64 dropped;
    TACHYON_WFP_UINT64 injected;
    TACHYON_WFP_UINT64 self_injected;
    TACHYON_WFP_UINT64 queue_overflow;
    TACHYON_WFP_UINT64 verdict_timeout;
    TACHYON_WFP_UINT64 rejected_frames;
    TACHYON_WFP_UINT32 queue_depth;
    TACHYON_WFP_UINT32 pending_verdicts;
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

TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_MESSAGE_HEADER) == TACHYON_WFP_HEADER_SIZE, "ABI header size");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_NEGOTIATE_REQUEST) == TACHYON_WFP_NEGOTIATE_REQUEST_SIZE, "negotiate request size");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_NEGOTIATE_RESPONSE) == TACHYON_WFP_NEGOTIATE_RESPONSE_SIZE, "negotiate response size");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_POLICY_HEADER) == TACHYON_WFP_POLICY_HEADER_SIZE, "policy header size");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_POLICY_ENTRY) == TACHYON_WFP_POLICY_ENTRY_SIZE, "policy entry size");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_DISABLE_POLICY) == TACHYON_WFP_DISABLE_POLICY_SIZE, "disable size");
TACHYON_WFP_STATIC_ASSERT(TACHYON_WFP_OFFSET_OF(TACHYON_WFP_CAPTURE_RECORD, payload) == TACHYON_WFP_CAPTURE_HEADER_SIZE, "capture header size");
TACHYON_WFP_STATIC_ASSERT(TACHYON_WFP_OFFSET_OF(TACHYON_WFP_VERDICT, payload) == TACHYON_WFP_VERDICT_HEADER_SIZE, "verdict header size");
TACHYON_WFP_STATIC_ASSERT(sizeof(((TACHYON_WFP_CAPTURE_RECORD*)0)->flow_id) == 16u, "capture flow ID width");
TACHYON_WFP_STATIC_ASSERT(sizeof(((TACHYON_WFP_VERDICT*)0)->flow_id) == 16u, "verdict flow ID width");
TACHYON_WFP_STATIC_ASSERT(sizeof(TACHYON_WFP_STATISTICS) == TACHYON_WFP_STATISTICS_SIZE, "statistics size");
