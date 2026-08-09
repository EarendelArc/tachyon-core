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
#define TG_HELPER_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-80-1356003462-1404488631-2219046169-124586702-828318184)"
#define TG_TIMER_PERIOD_MS 25u

typedef struct TG_POLICY {
    UINT64 generation;
    UCHAR lease_nonce[16];
    UINT32 entry_count;
    TACHYON_WFP_POLICY_ENTRY entries[1];
} TG_POLICY;

typedef struct TG_FLOW_CONTEXT {
    LIST_ENTRY link;
    UINT64 flow_handle;
    UINT64 generation;
    UINT64 process_id;
    UINT64 process_start_key;
    UCHAR flow_id[16];
    UCHAR lease_nonce[16];
    UCHAR app_id_hash[32];
    UCHAR user_sid_hash[32];
    ADDRESS_FAMILY address_family;
    UINT8 direction;
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
    BOOLEAN dequeued;
} TG_PENDING_PACKET;

typedef struct TG_DEVICE_CONTEXT {
    WDFDEVICE device;
    WDFQUEUE default_queue;
    WDFQUEUE dequeue_queue;
    WDFSPINLOCK lock;
    WDFTIMER timer;
    LIST_ENTRY capture_queue;
    LIST_ENTRY pending_packets;
    LIST_ENTRY flows;
    UINT32 queue_depth;
    UINT32 pending_count;
    UINT32 queue_capacity;
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
    volatile LONG client_open;
    volatile LONG stopping;
    TACHYON_WFP_STATISTICS statistics;
} TG_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(TG_DEVICE_CONTEXT, TgGetDeviceContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD TgEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL TgEvtIoDeviceControl;
EVT_WDF_FILE_CREATE TgEvtFileCreate;
EVT_WDF_FILE_CLEANUP TgEvtFileCleanup;
EVT_WDF_TIMER TgEvtTimeoutTimer;

extern WDFDEVICE TgControlDevice;

NTSTATUS TgCreateControlDevice(_In_ WDFDRIVER driver, _Out_ WDFDEVICE* device);
NTSTATUS TgWfpStart(_Inout_ TG_DEVICE_CONTEXT* context);
VOID TgWfpStop(_Inout_ TG_DEVICE_CONTEXT* context);

VOID NTAPI TgClassifyFlowV4(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyFlowV6(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyDatagramV4(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
VOID NTAPI TgClassifyDatagramV6(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*, VOID*, const VOID*, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0*);
NTSTATUS NTAPI TgNotify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, const FWPS_FILTER0*);
VOID NTAPI TgFlowDelete(UINT16 layer_id, UINT32 callout_id, UINT64 flow_context);

BOOLEAN TgValidateHeader(const TACHYON_WFP_MESSAGE_HEADER* header, SIZE_T actual, UINT16 kind);
NTSTATUS TgSetPolicy(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size);
NTSTATUS TgDisablePolicy(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size);
NTSTATUS TgApplyVerdict(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size);
NTSTATUS TgCopyNextCapture(TG_DEVICE_CONTEXT* context, WDFREQUEST request, SIZE_T output_size);
VOID TgFlushAll(TG_DEVICE_CONTEXT* context, BOOLEAN permit_direct);
VOID TgServiceCaptureWaiter(TG_DEVICE_CONTEXT* context);
VOID TgCompletePacket(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet, UINT32 action);

BOOLEAN TgHashBytes(TG_DEVICE_CONTEXT* context, const VOID* bytes, ULONG length, UCHAR output[32]);
BOOLEAN TgPolicyMatches(TG_DEVICE_CONTEXT* context, const TG_FLOW_CONTEXT* flow);
UINT64 TgNow100ns(VOID);
