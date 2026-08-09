// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <ntddk.h>
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

typedef enum TG_PACKET_STATE {
    TgPacketCaptured = 1,
    TgPacketDequeued = 2,
    TgPacketCompleting = 3,
    TgPacketCompleted = 4,
    TgPacketCancelled = 5
} TG_PACKET_STATE;

typedef struct TG_DEVICE_CONTEXT TG_DEVICE_CONTEXT;

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
    UINT64 generation;
    UINT64 process_id;
    UINT64 process_start_key;
    UCHAR flow_id[16];
    UCHAR lease_nonce[16];
    UCHAR app_id_hash[32];
    UCHAR user_sid_hash[32];
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
    NET_BUFFER_LIST* clone;
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
    TACHYON_WFP_STATISTICS statistics;
};

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(TG_DEVICE_CONTEXT, TgGetDeviceContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD TgEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL TgEvtIoDeviceControl;
EVT_WDF_FILE_CREATE TgEvtFileCreate;
EVT_WDF_FILE_CLEANUP TgEvtFileCleanup;
EVT_WDF_TIMER TgEvtTimeoutTimer;

extern WDFDEVICE TgControlDevice;
extern TG_DEVICE_CONTEXT* volatile TgControlContext;

NTSTATUS TgCreateControlDevice(_In_ WDFDRIVER driver, _Out_ WDFDEVICE* device);
NTSTATUS TgWfpStart(_Inout_ TG_DEVICE_CONTEXT* context);
NTSTATUS TgWfpStop(_Inout_ TG_DEVICE_CONTEXT* context);

VOID NTAPI TgClassifyFlowV4(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyFlowV6(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyDatagramV4(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyDatagramV6(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
NTSTATUS NTAPI TgNotify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, const FWPS_FILTER0*);
VOID NTAPI TgFlowDelete(UINT16 layer_id, UINT32 callout_id, UINT64 flow_context);

BOOLEAN TgValidateHeader(const TACHYON_WFP_MESSAGE_HEADER* header, SIZE_T actual, UINT16 kind);
NTSTATUS TgSetPolicy(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size);
NTSTATUS TgDisablePolicy(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size);
VOID TgClearPolicy(TG_DEVICE_CONTEXT* context);
NTSTATUS TgApplyVerdict(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size);
NTSTATUS TgCopyNextCapture(TG_DEVICE_CONTEXT* context, WDFREQUEST request, SIZE_T output_size);
VOID TgFlushAll(TG_DEVICE_CONTEXT* context, BOOLEAN permit_direct);
VOID TgServiceCaptureWaiter(TG_DEVICE_CONTEXT* context);
VOID TgCompletePacket(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet, UINT32 action);
VOID TgPacketReference(TG_PENDING_PACKET* packet);
VOID TgPacketDereference(TG_PENDING_PACKET* packet);
BOOLEAN TgFlowTryReference(TG_FLOW_CONTEXT* flow);
VOID TgFlowDereference(TG_FLOW_CONTEXT* flow);
TG_DEVICE_CONTEXT* TgAcquireControlContext(VOID);
VOID TgReleaseControlContext(TG_DEVICE_CONTEXT* context);

BOOLEAN TgHashBytes(TG_DEVICE_CONTEXT* context, const VOID* bytes, ULONG length, UCHAR output[32]);
BOOLEAN TgPolicyMatches(TG_DEVICE_CONTEXT* context, const TG_FLOW_CONTEXT* flow);
UINT64 TgNow100ns(VOID);
