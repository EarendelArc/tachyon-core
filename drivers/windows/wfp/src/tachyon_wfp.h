// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <ntifs.h>
#include <ntintsafe.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <bcrypt.h>

#include "../include/tachyon_wfp_abi.h"

#define TG_POOL_TAG 'pWgT'
#define TG_DEVICE_NAME L"\\Device\\TachyonWFP"
#define TG_SYMBOLIC_LINK L"\\DosDevices\\TachyonWFP"
#define TG_HELPER_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;" TACHYON_WFP_HELPER_SERVICE_SID_WIDE L")"
#define TG_TIMER_PERIOD_MS 25u
#define TG_STOP_RETRY_COUNT 500u
#define TG_STOP_RETRY_DELAY_MS 10u
#define TG_STOP_DRAIN_TIMEOUT_MS 5000u
#define TG_MAX_CONTROL_DATA_SIZE 4096u
#define TG_FLOW_ID_SIZE 16u
#define TG_SHA256_DIGEST_SIZE 32u

typedef UCHAR TG_SHA256_DIGEST[TG_SHA256_DIGEST_SIZE];

typedef enum TG_PACKET_STATE {
    TgPacketCaptured = 1,
    TgPacketDequeued = 2,
    TgPacketCompleting = 3,
    TgPacketCompleted = 4,
    TgPacketCancelled = 5
} TG_PACKET_STATE;

typedef struct TG_DEVICE_CONTEXT TG_DEVICE_CONTEXT;

typedef struct TG_FILE_CONTEXT {
    EX_RUNDOWN_REF io_rundown;
    volatile LONG negotiated;
    volatile LONG closing;
    UINT64 generation;
} TG_FILE_CONTEXT;

typedef struct TG_SESSION_TOKEN {
    TG_FILE_CONTEXT* file_context;
    WDFFILEOBJECT file_object;
    UINT64 generation;
} TG_SESSION_TOKEN;

typedef struct TG_CAPTURE_SNAPSHOT {
    UINT64 session_generation;
    UINT64 policy_generation;
    UCHAR policy_lease_nonce[16];
} TG_CAPTURE_SNAPSHOT;

typedef struct DECLSPEC_ALIGN(8) TG_STATISTICS_COUNTERS {
    volatile LONG64 captured;
    volatile LONG64 permitted;
    volatile LONG64 dropped;
    volatile LONG64 injected;
    volatile LONG64 self_injected;
    volatile LONG64 queue_overflow;
    volatile LONG64 verdict_timeout;
    volatile LONG64 rejected_frames;
} TG_STATISTICS_COUNTERS;

typedef struct TG_POLICY {
    UINT64 generation;
    UCHAR lease_nonce[16];
    UINT32 entry_count;
    TACHYON_WFP_POLICY_ENTRY entries[1];
} TG_POLICY;

typedef struct TG_FLOW_CONTEXT {
    LIST_ENTRY link;
    TG_DEVICE_CONTEXT* owner;
    UINT64 flow_handle;
    UINT16 layer_id;
    UINT32 callout_id;
    UINT64 session_generation;
    UINT64 generation;
    UINT64 process_id;
    UINT64 process_start_key;
    UCHAR flow_id[TG_FLOW_ID_SIZE];
    UCHAR lease_nonce[16];
    UCHAR app_id_hash[32];
    UCHAR user_security_descriptor_hash[32];
    ADDRESS_FAMILY address_family;
    UINT8 direction;
    volatile LONG references;
    volatile LONG closing;
    volatile LONG remove_requested;
    volatile LONG listed;
    volatile LONG64 next_sequence;
} TG_FLOW_CONTEXT;

typedef struct TG_PENDING_PACKET {
    LIST_ENTRY queue_link;
    LIST_ENTRY pending_link;
    TACHYON_WFP_CAPTURE_RECORD* record;
    SIZE_T record_size;
    SIZE_T control_data_size;
    SIZE_T resident_bytes;
    NET_BUFFER_LIST* clone;
    NET_BUFFER* clone_retreated_buffer;
    ULONG clone_retreat_length;
    TG_FLOW_CONTEXT* flow;
    UINT64 request_id;
    UINT64 sequence;
    UINT64 deadline_100ns;
    ADDRESS_FAMILY address_family;
    UINT8 direction;
    COMPARTMENT_ID compartment_id;
    UINT64 endpoint_handle;
    UINT32 interface_index;
    UINT32 sub_interface_index;
    FWPS_TRANSPORT_SEND_PARAMS0 send_params;
    UCHAR remote_address[16];
    volatile LONG references;
    volatile LONG state;
    volatile LONG terminal_state;
    BOOLEAN queued;
    BOOLEAN pending;
    BOOLEAN clone_retreat_active;
} TG_PENDING_PACKET;

struct TG_DEVICE_CONTEXT {
    WDFDEVICE device;
    WDFQUEUE default_queue;
    WDFQUEUE dequeue_queue;
    WDFSPINLOCK lock;
    WDFTIMER timer;
    LIST_ENTRY capture_queue;
    LIST_ENTRY pending_packets;
    LIST_ENTRY flows;
    UINT32 queue_depth;
    SIZE_T queue_bytes;
    UINT32 pending_count;
    SIZE_T pending_bytes;
    UINT32 queue_capacity;
    SIZE_T resident_byte_capacity;
    UINT32 verdict_timeout_ms;
    UINT64 next_request_id;
    TG_POLICY* policy;
    HANDLE engine_handle;
    HANDLE injection_v4;
    HANDLE injection_v6;
    UINT32 callout_flow_v4;
    UINT32 callout_flow_v6;
    UINT32 callout_datagram_v4;
    UINT32 callout_datagram_v6;
    BCRYPT_ALG_HANDLE sha256;
    EX_RUNDOWN_REF callback_rundown;
    KEVENT flows_drained;
    KEVENT injections_drained;
    volatile LONG flow_count;
    volatile LONG injection_count;
    volatile LONG client_open;
    volatile LONG stopping;
    volatile LONG stopped;
    UINT64 next_session_generation;
    volatile LONG64 active_session_generation;
    WDFFILEOBJECT session_file;
    TG_STATISTICS_COUNTERS statistics;
};

#if defined(_AMD64_) || defined(_M_AMD64) || defined(_ARM64_) || defined(_M_ARM64)
TACHYON_WFP_STATIC_ASSERT(TACHYON_WFP_ALIGNOF(TG_STATISTICS_COUNTERS) >= 8, "private statistics alignment");
TACHYON_WFP_STATIC_ASSERT(TACHYON_WFP_ALIGNOF(TG_DEVICE_CONTEXT) >= 8, "device context alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_STATISTICS_COUNTERS, captured) & 7) == 0, "captured counter alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_STATISTICS_COUNTERS, permitted) & 7) == 0, "permitted counter alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_STATISTICS_COUNTERS, dropped) & 7) == 0, "dropped counter alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_STATISTICS_COUNTERS, injected) & 7) == 0, "injected counter alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_STATISTICS_COUNTERS, self_injected) & 7) == 0, "self-injected counter alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_STATISTICS_COUNTERS, queue_overflow) & 7) == 0, "overflow counter alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_STATISTICS_COUNTERS, verdict_timeout) & 7) == 0, "timeout counter alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_STATISTICS_COUNTERS, rejected_frames) & 7) == 0, "rejected counter alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_DEVICE_CONTEXT, active_session_generation) & 7) == 0, "active session alignment");
TACHYON_WFP_STATIC_ASSERT((FIELD_OFFSET(TG_DEVICE_CONTEXT, statistics) & 7) == 0, "embedded statistics alignment");
#endif

TACHYON_WFP_STATIC_ASSERT(sizeof(TG_SHA256_DIGEST) == TG_SHA256_DIGEST_SIZE, "SHA-256 digest width");
TACHYON_WFP_STATIC_ASSERT(sizeof(((TG_FLOW_CONTEXT*)0)->flow_id) == TG_FLOW_ID_SIZE, "flow ID width");
TACHYON_WFP_STATIC_ASSERT(sizeof(((TG_FLOW_CONTEXT*)0)->lease_nonce) == 16u, "flow lease nonce width");
TACHYON_WFP_STATIC_ASSERT(TG_FLOW_ID_SIZE < TG_SHA256_DIGEST_SIZE, "flow ID is a truncated digest");
TACHYON_WFP_STATIC_ASSERT(TG_MAX_CONTROL_DATA_SIZE <= TACHYON_WFP_MAX_MESSAGE_SIZE, "control data cap");

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(TG_DEVICE_CONTEXT, TgGetDeviceContext)
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(TG_FILE_CONTEXT, TgGetFileContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD TgEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL TgEvtIoDeviceControl;
EVT_WDF_DEVICE_FILE_CREATE TgEvtFileCreate;
EVT_WDF_FILE_CLEANUP TgEvtFileCleanup;
EVT_WDF_TIMER TgEvtTimeoutTimer;

extern WDFDEVICE TgControlDevice;
extern TG_DEVICE_CONTEXT* volatile TgControlContext;

NTSTATUS TgCreateControlDevice(_In_ WDFDRIVER driver, _Out_ WDFDEVICE* device);
NTSTATUS TgWfpStart(_Inout_ TG_DEVICE_CONTEXT* context);
NTSTATUS TgWfpStop(_Inout_ TG_DEVICE_CONTEXT* context);

VOID NTAPI TgClassifyFlowV4(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyFlowV6(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyDatagramV4(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyDatagramV6(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
NTSTATUS NTAPI TgNotify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, const FWPS_FILTER0*);
VOID NTAPI TgFlowDelete(UINT16 layer_id, UINT32 callout_id, UINT64 flow_context);

BOOLEAN TgValidateHeader(const TACHYON_WFP_MESSAGE_HEADER* header, SIZE_T actual, UINT16 kind);
BOOLEAN TgAcquireRequestSession(TG_DEVICE_CONTEXT* context, WDFREQUEST request, BOOLEAN require_negotiated,
                                TG_SESSION_TOKEN* token);
VOID TgReleaseRequestSession(TG_SESSION_TOKEN* token);
BOOLEAN TgSessionIsActiveLocked(const TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* token);
NTSTATUS TgSetPolicy(TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* session,
                     const VOID* input, SIZE_T input_size);
NTSTATUS TgDisablePolicy(TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* session,
                         const VOID* input, SIZE_T input_size);
VOID TgClearPolicy(TG_DEVICE_CONTEXT* context);
NTSTATUS TgApplyVerdict(TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* session,
                        const VOID* input, SIZE_T input_size);
NTSTATUS TgCopyNextCapture(TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* session,
                           WDFREQUEST request, SIZE_T output_size);
VOID TgFlushAll(TG_DEVICE_CONTEXT* context, BOOLEAN permit_direct);
VOID TgFlushGeneration(TG_DEVICE_CONTEXT* context, UINT64 generation, BOOLEAN permit_direct);
VOID TgServiceCaptureWaiter(TG_DEVICE_CONTEXT* context);
VOID TgCompletePacket(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet, UINT32 action);
VOID TgPacketReference(TG_PENDING_PACKET* packet);
VOID TgPacketDereference(TG_PENDING_PACKET* packet);
BOOLEAN TgFlowTryReference(TG_FLOW_CONTEXT* flow);
VOID TgFlowDereference(TG_FLOW_CONTEXT* flow);
TG_DEVICE_CONTEXT* TgAcquireControlContext(VOID);
VOID TgReleaseControlContext(TG_DEVICE_CONTEXT* context);

BOOLEAN TgHashBytes(TG_DEVICE_CONTEXT* context, const VOID* bytes, ULONG length,
                    TG_SHA256_DIGEST* output);
BOOLEAN TgPolicyMatches(TG_DEVICE_CONTEXT* context, const TG_FLOW_CONTEXT* flow);
BOOLEAN TgCaptureSnapshot(TG_DEVICE_CONTEXT* context, const TG_FLOW_CONTEXT* flow,
                          TG_CAPTURE_SNAPSHOT* snapshot);
BOOLEAN TgCaptureSnapshotIsActiveLocked(TG_DEVICE_CONTEXT* context, const TG_FLOW_CONTEXT* flow,
                                         const TG_CAPTURE_SNAPSHOT* snapshot);
UINT64 TgInterruptTime100ns(VOID);
DECLSPEC_NORETURN VOID TgFailStopUnload(NTSTATUS status);
