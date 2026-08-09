// SPDX-License-Identifier: Apache-2.0
#define INITGUID
#include <initguid.h>
#include "tachyon_wfp.h"

DEFINE_GUID(TG_SUBLAYER_KEY, 0x3ed6d6a1,0x53df,0x4f38,0x99,0x11,0x68,0xd2,0xb8,0x2d,0xc7,0x50);
DEFINE_GUID(TG_FLOW_V4_KEY, 0x7780fa02,0x2b27,0x4ad3,0x97,0x23,0x3b,0xb8,0x72,0x0a,0x0e,0x41);
DEFINE_GUID(TG_FLOW_V6_KEY, 0xa4f6d5f3,0x1a25,0x49cd,0x9c,0xc0,0x16,0x65,0xa7,0x20,0x58,0x19);
DEFINE_GUID(TG_DATAGRAM_V4_KEY, 0xf5dc0f13,0x5c2b,0x49f3,0xb8,0xda,0x6e,0x73,0x5d,0x84,0x31,0x9a);
DEFINE_GUID(TG_DATAGRAM_V6_KEY, 0x05e88a2c,0xb73d,0x4d15,0xa2,0x13,0xb8,0x7f,0x9a,0xd8,0x16,0x72);

static VOID TgClassifyFlow(ADDRESS_FAMILY family, const FWPS_INCOMING_VALUES0* values,
                           const FWPS_INCOMING_METADATA_VALUES0* metadata, const FWPS_FILTER0* filter,
                           FWPS_CLASSIFY_OUT0* classify_out);
static VOID TgClassifyDatagram(ADDRESS_FAMILY family, const FWPS_INCOMING_VALUES0* values,
                               const FWPS_INCOMING_METADATA_VALUES0* metadata, VOID* layer_data,
                               UINT64 flow_context, FWPS_CLASSIFY_OUT0* classify_out);
static NTSTATUS TgRegisterRuntimeCallout(TG_DEVICE_CONTEXT* context, const GUID* key,
                                        FWPS_CALLOUT_CLASSIFY_FN0 classify, UINT32* id);
static NTSTATUS TgAddEngineCalloutAndFilter(HANDLE engine, const GUID* key, const GUID* layer,
                                            FWP_ACTION_TYPE action);
static VOID NTAPI TgInjectComplete(VOID* context, NET_BUFFER_LIST* net_buffer_list, BOOLEAN dispatch_level);
static VOID TgFreePendingPacket(TG_PENDING_PACKET* packet);

NTSTATUS TgWfpStart(_Inout_ TG_DEVICE_CONTEXT* context)
{
    FWPM_SESSION0 session;
    FWPM_SUBLAYER0 sublayer;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&context->sha256, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &context->injection_v4);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = FwpsInjectionHandleCreate0(AF_INET6, FWPS_INJECTION_TYPE_TRANSPORT, &context->injection_v6);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = TgRegisterRuntimeCallout(context, &TG_FLOW_V4_KEY, TgClassifyFlowV4, &context->callout_flow_v4);
    if (!NT_SUCCESS(status)) goto Exit;
    status = TgRegisterRuntimeCallout(context, &TG_FLOW_V6_KEY, TgClassifyFlowV6, &context->callout_flow_v6);
    if (!NT_SUCCESS(status)) goto Exit;
    status = TgRegisterRuntimeCallout(context, &TG_DATAGRAM_V4_KEY, TgClassifyDatagramV4, &context->callout_datagram_v4);
    if (!NT_SUCCESS(status)) goto Exit;
    status = TgRegisterRuntimeCallout(context, &TG_DATAGRAM_V6_KEY, TgClassifyDatagramV6, &context->callout_datagram_v6);
    if (!NT_SUCCESS(status)) goto Exit;

    RtlZeroMemory(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"Tachyon WFP dynamic session";
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &context->engine_handle);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FwpmTransactionBegin0(context->engine_handle, 0);
    if (!NT_SUCCESS(status)) goto Exit;
    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = TG_SUBLAYER_KEY;
    sublayer.displayData.name = L"Tachyon game UDP capture";
    sublayer.weight = 0x7fff;
    status = FwpmSubLayerAdd0(context->engine_handle, &sublayer, NULL);
    if (!NT_SUCCESS(status)) goto Abort;
    status = TgAddEngineCalloutAndFilter(context->engine_handle, &TG_FLOW_V4_KEY, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, FWP_ACTION_CALLOUT_INSPECTION);
    if (!NT_SUCCESS(status)) goto Abort;
    status = TgAddEngineCalloutAndFilter(context->engine_handle, &TG_FLOW_V6_KEY, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, FWP_ACTION_CALLOUT_INSPECTION);
    if (!NT_SUCCESS(status)) goto Abort;
    status = TgAddEngineCalloutAndFilter(context->engine_handle, &TG_DATAGRAM_V4_KEY, &FWPM_LAYER_DATAGRAM_DATA_V4, FWP_ACTION_CALLOUT_TERMINATING);
    if (!NT_SUCCESS(status)) goto Abort;
    status = TgAddEngineCalloutAndFilter(context->engine_handle, &TG_DATAGRAM_V6_KEY, &FWPM_LAYER_DATAGRAM_DATA_V6, FWP_ACTION_CALLOUT_TERMINATING);
    if (!NT_SUCCESS(status)) goto Abort;
    status = FwpmTransactionCommit0(context->engine_handle);
    if (NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }
Abort:
    FwpmTransactionAbort0(context->engine_handle);
Exit:
    TgWfpStop(context);
    return status;
}

VOID TgWfpStop(_Inout_ TG_DEVICE_CONTEXT* context)
{
    TG_POLICY* policy;
    if (InterlockedExchange(&context->stopping, 1) != 0) return;
    if (context->timer != NULL) WdfTimerStop(context->timer, TRUE);
    TgFlushAll(context, TRUE);
    if (context->engine_handle != NULL) {
        FwpmEngineClose0(context->engine_handle);
        context->engine_handle = NULL;
    }
    if (context->callout_datagram_v6 != 0) FwpsCalloutUnregisterById0(context->callout_datagram_v6);
    if (context->callout_datagram_v4 != 0) FwpsCalloutUnregisterById0(context->callout_datagram_v4);
    if (context->callout_flow_v6 != 0) FwpsCalloutUnregisterById0(context->callout_flow_v6);
    if (context->callout_flow_v4 != 0) FwpsCalloutUnregisterById0(context->callout_flow_v4);
    if (context->injection_v6 != NULL) FwpsInjectionHandleDestroy0(context->injection_v6);
    if (context->injection_v4 != NULL) FwpsInjectionHandleDestroy0(context->injection_v4);
    if (context->sha256 != NULL) BCryptCloseAlgorithmProvider(context->sha256, 0);
    WdfSpinLockAcquire(context->lock);
    policy = context->policy;
    context->policy = NULL;
    WdfSpinLockRelease(context->lock);
    if (policy != NULL) {
        RtlSecureZeroMemory(policy, FIELD_OFFSET(TG_POLICY, entries) + (SIZE_T)policy->entry_count * sizeof(TACHYON_WFP_POLICY_ENTRY));
        ExFreePoolWithTag(policy, TG_POOL_TAG);
    }
}

static NTSTATUS TgRegisterRuntimeCallout(TG_DEVICE_CONTEXT* context, const GUID* key,
                                        FWPS_CALLOUT_CLASSIFY_FN0 classify, UINT32* id)
{
    FWPS_CALLOUT0 callout;
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *key;
    callout.classifyFn = classify;
    callout.notifyFn = TgNotify;
    callout.flowDeleteFn = TgFlowDelete;
    return FwpsCalloutRegister0(WdfDeviceWdmGetDeviceObject(context->device), &callout, id);
}

static NTSTATUS TgAddEngineCalloutAndFilter(HANDLE engine, const GUID* key, const GUID* layer,
                                            FWP_ACTION_TYPE action)
{
    FWPM_CALLOUT0 callout;
    FWPM_FILTER0 filter;
    FWPM_FILTER_CONDITION0 condition;
    UINT64 id;
    NTSTATUS status;
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *key;
    callout.displayData.name = L"Tachyon WFP callout";
    callout.applicableLayer = *layer;
    status = FwpmCalloutAdd0(engine, &callout, NULL, &id);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(&condition, sizeof(condition));
    condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT8;
    condition.conditionValue.uint8 = IPPROTO_UDP;
    RtlZeroMemory(&filter, sizeof(filter));
    filter.displayData.name = L"Tachyon selected UDP";
    filter.layerKey = *layer;
    filter.subLayerKey = TG_SUBLAYER_KEY;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    filter.action.type = action;
    filter.action.calloutKey = *key;
    return FwpmFilterAdd0(engine, &filter, NULL, &id);
}

NTSTATUS NTAPI TgNotify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filter_key, const FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

BOOLEAN TgHashBytes(TG_DEVICE_CONTEXT* context, const VOID* bytes, ULONG length, UCHAR output[32])
{
    if (bytes == NULL || length == 0 || context->sha256 == NULL) {
        RtlZeroMemory(output, 32);
        return FALSE;
    }
    return NT_SUCCESS(BCryptHash(context->sha256, NULL, 0, (PUCHAR)bytes, length, output, 32));
}

static VOID TgClassifyFlow(ADDRESS_FAMILY family, const FWPS_INCOMING_VALUES0* values,
                           const FWPS_INCOMING_METADATA_VALUES0* metadata, const FWPS_FILTER0* filter,
                           FWPS_CLASSIFY_OUT0* classify_out)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext(TgControlDevice);
    TG_FLOW_CONTEXT candidate;
    TG_FLOW_CONTEXT* flow;
    const FWP_BYTE_BLOB* app_id;
    const FWP_BYTE_BLOB* user_id;
    UINT32 app_index;
    UINT32 user_index;
    UINT16 target_layer;
    UINT32 target_callout;
    UCHAR flow_seed[32];
    NTSTATUS status;
    PEPROCESS process;

    UNREFERENCED_PARAMETER(filter);
    classify_out->actionType = FWP_ACTION_PERMIT;
    if ((classify_out->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || context == NULL || context->policy == NULL ||
        metadata == NULL || (metadata->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) == 0 ||
        (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0) return;
    RtlZeroMemory(&candidate, sizeof(candidate));
    candidate.flow_handle = metadata->flowHandle;
    candidate.process_id = metadata->processId;
    candidate.address_family = family;
    candidate.direction = TachyonWfpDirectionOutbound;
    WdfSpinLockAcquire(context->lock);
    if (context->policy != NULL) {
        candidate.generation = context->policy->generation;
        RtlCopyMemory(candidate.lease_nonce, context->policy->lease_nonce, 16);
    }
    WdfSpinLockRelease(context->lock);
    if (candidate.generation == 0) return;
    if (KeGetCurrentIrql() <= APC_LEVEL && NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)candidate.process_id, &process))) {
        candidate.process_start_key = PsGetProcessStartKey(process);
        ObDereferenceObject(process);
    }
    if (family == AF_INET) {
        app_index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID;
        user_index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_USER_ID;
        target_layer = FWPS_LAYER_DATAGRAM_DATA_V4;
        target_callout = context->callout_datagram_v4;
    } else {
        app_index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID;
        user_index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_USER_ID;
        target_layer = FWPS_LAYER_DATAGRAM_DATA_V6;
        target_callout = context->callout_datagram_v6;
    }
    app_id = values->incomingValue[app_index].value.byteBlob;
    user_id = values->incomingValue[user_index].value.byteBlob;
    if (app_id == NULL || user_id == NULL ||
        !TgHashBytes(context, app_id->data, app_id->size, candidate.app_id_hash) ||
        !TgHashBytes(context, user_id->data, user_id->size, candidate.user_sid_hash) ||
        !TgPolicyMatches(context, &candidate)) return;
    RtlZeroMemory(flow_seed, sizeof(flow_seed));
    RtlCopyMemory(flow_seed, &candidate.flow_handle, sizeof(candidate.flow_handle));
    RtlCopyMemory(flow_seed + 8, &candidate.generation, sizeof(candidate.generation));
    RtlCopyMemory(flow_seed + 16, &candidate.process_id, sizeof(candidate.process_id));
    RtlCopyMemory(flow_seed + 24, &candidate.process_start_key, sizeof(candidate.process_start_key));
    if (!TgHashBytes(context, flow_seed, sizeof(flow_seed), candidate.flow_id)) return;
    flow = (TG_FLOW_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*flow), TG_POOL_TAG);
    if (flow == NULL) return;
    RtlCopyMemory(flow, &candidate, sizeof(*flow));
    InitializeListHead(&flow->link);
    status = FwpsFlowAssociateContext0(metadata->flowHandle, target_layer, target_callout, (UINT64)(ULONG_PTR)flow);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(flow, sizeof(*flow));
        ExFreePoolWithTag(flow, TG_POOL_TAG);
        return;
    }
    WdfSpinLockAcquire(context->lock);
    InsertTailList(&context->flows, &flow->link);
    WdfSpinLockRelease(context->lock);
}

VOID NTAPI TgClassifyFlowV4(const FWPS_INCOMING_VALUES0* values, const FWPS_INCOMING_METADATA_VALUES0* metadata,
                            VOID* layer_data, const VOID* classify_context, const FWPS_FILTER0* filter,
                            UINT64 flow_context, FWPS_CLASSIFY_OUT0* classify_out)
{
    UNREFERENCED_PARAMETER(layer_data); UNREFERENCED_PARAMETER(classify_context); UNREFERENCED_PARAMETER(flow_context);
    TgClassifyFlow(AF_INET, values, metadata, filter, classify_out);
}

VOID NTAPI TgClassifyFlowV6(const FWPS_INCOMING_VALUES0* values, const FWPS_INCOMING_METADATA_VALUES0* metadata,
                            VOID* layer_data, const VOID* classify_context, const FWPS_FILTER0* filter,
                            UINT64 flow_context, FWPS_CLASSIFY_OUT0* classify_out)
{
    UNREFERENCED_PARAMETER(layer_data); UNREFERENCED_PARAMETER(classify_context); UNREFERENCED_PARAMETER(flow_context);
    TgClassifyFlow(AF_INET6, values, metadata, filter, classify_out);
}

static VOID TgClassifyDatagram(ADDRESS_FAMILY family, const FWPS_INCOMING_VALUES0* values,
                               const FWPS_INCOMING_METADATA_VALUES0* metadata, VOID* layer_data,
                               UINT64 flow_context, FWPS_CLASSIFY_OUT0* classify_out)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext(TgControlDevice);
    TG_FLOW_CONTEXT* flow = (TG_FLOW_CONTEXT*)(ULONG_PTR)flow_context;
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layer_data;
    NET_BUFFER* net_buffer;
    TG_PENDING_PACKET* packet;
    SIZE_T record_size;
    ULONG payload_size;
    UCHAR* payload;
    UCHAR* contiguous;
    UINT32 direction_index;
    UINT32 local_address_index, remote_address_index, local_port_index, remote_port_index;
    UINT32 interface_index, sub_interface_index;
    FWPS_PACKET_INJECTION_STATE injection_state;
    HANDLE injection_context = NULL;
    NTSTATUS status;

    classify_out->actionType = FWP_ACTION_PERMIT;
    if ((classify_out->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || context == NULL || flow == NULL || nbl == NULL ||
        InterlockedCompareExchange(&context->client_open, 0, 0) == 0 || !TgPolicyMatches(context, flow)) return;
    injection_state = FwpsQueryPacketInjectionState0(family == AF_INET ? context->injection_v4 : context->injection_v6,
                                                      nbl, &injection_context);
    if (injection_state == FWPS_PACKET_INJECTED_BY_SELF || injection_state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
        InterlockedIncrement64((volatile LONG64*)&context->statistics.self_injected);
        return;
    }
    direction_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION : FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION;
    if (values->incomingValue[direction_index].value.uint32 != FWP_DIRECTION_OUTBOUND) return;
    net_buffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (net_buffer == NULL || NET_BUFFER_NEXT_NB(net_buffer) != NULL) return;
    payload_size = NET_BUFFER_DATA_LENGTH(net_buffer);
    if (payload_size == 0 || payload_size > TACHYON_WFP_MAX_PAYLOAD_SIZE ||
        payload_size > TACHYON_WFP_MAX_MESSAGE_SIZE - TACHYON_WFP_CAPTURE_HEADER_SIZE) return;
    record_size = TACHYON_WFP_CAPTURE_HEADER_SIZE + payload_size;
    packet = (TG_PENDING_PACKET*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*packet), TG_POOL_TAG);
    if (packet == NULL) return;
    RtlZeroMemory(packet, sizeof(*packet));
    packet->record = (TACHYON_WFP_CAPTURE_RECORD*)ExAllocatePool2(POOL_FLAG_NON_PAGED, record_size, TG_POOL_TAG);
    if (packet->record == NULL) {
        ExFreePoolWithTag(packet, TG_POOL_TAG);
        return;
    }
    RtlZeroMemory(packet->record, record_size);
    status = FwpsAllocateCloneNetBufferList0(nbl, NULL, NULL, 0, &packet->clone);
    if (!NT_SUCCESS(status)) {
        TgFreePendingPacket(packet);
        return;
    }
    InitializeListHead(&packet->queue_link);
    InitializeListHead(&packet->pending_link);
    packet->flow = flow;
    packet->record_size = record_size;
    packet->address_family = family;
    packet->direction = TachyonWfpDirectionOutbound;
    packet->compartment_id = (metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) != 0 ? metadata->compartmentId : UNSPECIFIED_COMPARTMENT_ID;
    packet->endpoint_handle = (metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) != 0 ? metadata->transportEndpointHandle : 0;
    packet->deadline_100ns = TgNow100ns() + (UINT64)context->verdict_timeout_ms * 10000u;
    local_address_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS;
    remote_address_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS;
    local_port_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT : FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT;
    remote_port_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
    interface_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX : FWPS_FIELD_DATAGRAM_DATA_V6_INTERFACE_INDEX;
    sub_interface_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_SUB_INTERFACE_INDEX : FWPS_FIELD_DATAGRAM_DATA_V6_SUB_INTERFACE_INDEX;
    packet->interface_index = values->incomingValue[interface_index].value.uint32;
    packet->sub_interface_index = values->incomingValue[sub_interface_index].value.uint32;
    if (family == AF_INET) {
        RtlCopyMemory(packet->record->local_address, &values->incomingValue[local_address_index].value.uint32, 4);
        RtlCopyMemory(packet->record->remote_address, &values->incomingValue[remote_address_index].value.uint32, 4);
        RtlCopyMemory(packet->remote_address, &values->incomingValue[remote_address_index].value.uint32, 4);
    } else {
        RtlCopyMemory(packet->record->local_address, values->incomingValue[local_address_index].value.byteArray16->byteArray16, 16);
        RtlCopyMemory(packet->record->remote_address, values->incomingValue[remote_address_index].value.byteArray16->byteArray16, 16);
        RtlCopyMemory(packet->remote_address, values->incomingValue[remote_address_index].value.byteArray16->byteArray16, 16);
    }
    packet->send_params.remoteAddress = packet->remote_address;
    packet->send_params.remoteScopeId = 0;
    packet->send_params.controlData = NULL;
    packet->send_params.controlDataLength = 0;
    WdfSpinLockAcquire(context->lock);
    if (context->policy == NULL || context->queue_depth >= context->queue_capacity) {
        if (context->queue_depth >= context->queue_capacity) ++context->statistics.queue_overflow;
        WdfSpinLockRelease(context->lock);
        TgFreePendingPacket(packet);
        return;
    }
    packet->request_id = ++context->next_request_id;
    packet->sequence = (UINT64)InterlockedIncrement64(&flow->next_sequence);
    packet->deadline_100ns = TgNow100ns() + (UINT64)context->verdict_timeout_ms * 10000u;
    packet->record->header.magic = TACHYON_WFP_ABI_MAGIC;
    packet->record->header.header_size = TACHYON_WFP_HEADER_SIZE;
    packet->record->header.abi_major = TACHYON_WFP_ABI_MAJOR;
    packet->record->header.abi_minor = TACHYON_WFP_ABI_MINOR;
    packet->record->header.kind = TachyonWfpMessageCapture;
    packet->record->header.total_size = (UINT32)record_size;
    packet->record->header.request_id = packet->request_id;
    RtlCopyMemory(packet->record->flow_id, flow->flow_id, 16);
    packet->record->generation = flow->generation;
    RtlCopyMemory(packet->record->lease_nonce, flow->lease_nonce, 16);
    packet->record->sequence = packet->sequence;
    packet->record->process_id = flow->process_id;
    packet->record->process_start_key = flow->process_start_key;
    RtlCopyMemory(packet->record->app_id_hash, flow->app_id_hash, 32);
    RtlCopyMemory(packet->record->user_sid_hash, flow->user_sid_hash, 32);
    packet->record->address_family = family;
    packet->record->direction = TachyonWfpDirectionOutbound;
    packet->record->protocol = IPPROTO_UDP;
    packet->record->injection_state = injection_state;
    packet->record->compartment_id = packet->compartment_id;
    packet->record->interface_index = packet->interface_index;
    packet->record->sub_interface_index = packet->sub_interface_index;
    packet->record->local_port = values->incomingValue[local_port_index].value.uint16;
    packet->record->remote_port = values->incomingValue[remote_port_index].value.uint16;
    packet->record->payload_size = payload_size;
    payload = ((UCHAR*)packet->record) + TACHYON_WFP_CAPTURE_HEADER_SIZE;
    contiguous = NdisGetDataBuffer(net_buffer, payload_size, payload, 1, 0);
    if (contiguous == NULL) {
        WdfSpinLockRelease(context->lock);
        TgFreePendingPacket(packet);
        return;
    }
    if (contiguous != payload) RtlCopyMemory(payload, contiguous, payload_size);
    InsertTailList(&context->capture_queue, &packet->queue_link);
    InsertTailList(&context->pending_packets, &packet->pending_link);
    ++context->queue_depth;
    ++context->pending_count;
    ++context->statistics.captured;
    WdfSpinLockRelease(context->lock);
    classify_out->actionType = FWP_ACTION_BLOCK;
    classify_out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    TgServiceCaptureWaiter(context);
}

VOID NTAPI TgClassifyDatagramV4(const FWPS_INCOMING_VALUES0* values, const FWPS_INCOMING_METADATA_VALUES0* metadata,
                                VOID* layer_data, const VOID* classify_context, const FWPS_FILTER0* filter,
                                UINT64 flow_context, FWPS_CLASSIFY_OUT0* classify_out)
{
    UNREFERENCED_PARAMETER(classify_context); UNREFERENCED_PARAMETER(filter);
    TgClassifyDatagram(AF_INET, values, metadata, layer_data, flow_context, classify_out);
}

VOID NTAPI TgClassifyDatagramV6(const FWPS_INCOMING_VALUES0* values, const FWPS_INCOMING_METADATA_VALUES0* metadata,
                                VOID* layer_data, const VOID* classify_context, const FWPS_FILTER0* filter,
                                UINT64 flow_context, FWPS_CLASSIFY_OUT0* classify_out)
{
    UNREFERENCED_PARAMETER(classify_context); UNREFERENCED_PARAMETER(filter);
    TgClassifyDatagram(AF_INET6, values, metadata, layer_data, flow_context, classify_out);
}

VOID NTAPI TgFlowDelete(UINT16 layer_id, UINT32 callout_id, UINT64 flow_context)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext(TgControlDevice);
    TG_FLOW_CONTEXT* flow = (TG_FLOW_CONTEXT*)(ULONG_PTR)flow_context;
    UNREFERENCED_PARAMETER(layer_id); UNREFERENCED_PARAMETER(callout_id);
    if (context == NULL || flow == NULL) return;
    WdfSpinLockAcquire(context->lock);
    if (!IsListEmpty(&flow->link)) {
        RemoveEntryList(&flow->link);
        InitializeListHead(&flow->link);
    }
    WdfSpinLockRelease(context->lock);
    RtlSecureZeroMemory(flow, sizeof(*flow));
    ExFreePoolWithTag(flow, TG_POOL_TAG);
}

VOID TgCompletePacket(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet, UINT32 action)
{
    NTSTATUS status;
    HANDLE injection = packet->address_family == AF_INET ? context->injection_v4 : context->injection_v6;
    if (action == TachyonWfpVerdictPermitDirect && packet->clone != NULL && injection != NULL) {
        status = FwpsInjectTransportSendAsync0(injection, (HANDLE)packet, packet->endpoint_handle, 0,
                                               &packet->send_params, packet->address_family, packet->compartment_id,
                                               packet->clone, TgInjectComplete, packet);
        if (NT_SUCCESS(status)) {
            InterlockedIncrement64((volatile LONG64*)&context->statistics.permitted);
            return;
        }
    }
    if (action == TachyonWfpVerdictDrop) InterlockedIncrement64((volatile LONG64*)&context->statistics.dropped);
    if (action == TachyonWfpVerdictTunnel) InterlockedIncrement64((volatile LONG64*)&context->statistics.injected);
    TgFreePendingPacket(packet);
}

static VOID NTAPI TgInjectComplete(VOID* context, NET_BUFFER_LIST* net_buffer_list, BOOLEAN dispatch_level)
{
    TG_PENDING_PACKET* packet = (TG_PENDING_PACKET*)context;
    UNREFERENCED_PARAMETER(dispatch_level);
    if (net_buffer_list != NULL) FwpsFreeCloneNetBufferList0(net_buffer_list, 0);
    packet->clone = NULL;
    TgFreePendingPacket(packet);
}

static VOID TgFreePendingPacket(TG_PENDING_PACKET* packet)
{
    if (packet == NULL) return;
    if (packet->clone != NULL) FwpsFreeCloneNetBufferList0(packet->clone, 0);
    if (packet->record != NULL) {
        RtlSecureZeroMemory(packet->record, packet->record_size);
        ExFreePoolWithTag(packet->record, TG_POOL_TAG);
    }
    RtlSecureZeroMemory(packet, sizeof(*packet));
    ExFreePoolWithTag(packet, TG_POOL_TAG);
}
