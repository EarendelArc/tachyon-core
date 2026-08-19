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
static VOID TgReleasePacketClone(TG_PENDING_PACKET* packet);
static VOID TgFreePendingPacket(TG_PENDING_PACKET* packet);
static VOID TgCloseFlow(TG_FLOW_CONTEXT* flow);
static NTSTATUS TgRemoveAllFlowContexts(TG_DEVICE_CONTEXT* context);
static NTSTATUS TgUnregisterCalloutBlocking(UINT32* callout_id);
static NTSTATUS TgWaitForDrain(KEVENT* event);

TG_DEVICE_CONTEXT* TgAcquireControlContext(VOID)
{
    TG_DEVICE_CONTEXT* context = (TG_DEVICE_CONTEXT*)InterlockedCompareExchangePointer(
        (PVOID volatile*)&TgControlContext, NULL, NULL);
    if (context == NULL || !ExAcquireRundownProtection(&context->callback_rundown)) {
        return NULL;
    }
    if (context != (TG_DEVICE_CONTEXT*)InterlockedCompareExchangePointer(
                       (PVOID volatile*)&TgControlContext, NULL, NULL)) {
        ExReleaseRundownProtection(&context->callback_rundown);
        return NULL;
    }
    return context;
}

VOID TgReleaseControlContext(TG_DEVICE_CONTEXT* context)
{
    if (context != NULL) ExReleaseRundownProtection(&context->callback_rundown);
}

BOOLEAN TgFlowTryReference(TG_FLOW_CONTEXT* flow)
{
    LONG references;
    if (flow == NULL || InterlockedCompareExchange(&flow->closing, 0, 0) != 0) return FALSE;
    do {
        references = InterlockedCompareExchange(&flow->references, 0, 0);
        if (references <= 0 || InterlockedCompareExchange(&flow->closing, 0, 0) != 0) return FALSE;
    } while (InterlockedCompareExchange(&flow->references, references + 1, references) != references);
    if (InterlockedCompareExchange(&flow->closing, 0, 0) != 0) {
        TgFlowDereference(flow);
        return FALSE;
    }
    return TRUE;
}

VOID TgFlowDereference(TG_FLOW_CONTEXT* flow)
{
    TG_DEVICE_CONTEXT* owner;
    if (flow == NULL || InterlockedDecrement(&flow->references) != 0) return;
    owner = flow->owner;
    RtlSecureZeroMemory(flow, sizeof(*flow));
    ExFreePoolWithTag(flow, TG_POOL_TAG);
    if (owner != NULL && InterlockedDecrement(&owner->flow_count) == 0) {
        KeSetEvent(&owner->flows_drained, IO_NO_INCREMENT, FALSE);
    }
}

NTSTATUS TgWfpStart(_Inout_ TG_DEVICE_CONTEXT* context)
{
    FWPM_SESSION0 session;
    FWPM_SUBLAYER0 sublayer;
    NTSTATUS status;
    NTSTATUS cleanup_status;

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
    cleanup_status = TgWfpStop(context);
    if (!NT_SUCCESS(cleanup_status)) {
        TgFailStopUnload(cleanup_status);
    }
    return status;
}

NTSTATUS TgWfpStop(_Inout_ TG_DEVICE_CONTEXT* context)
{
    TG_POLICY* policy;
    NTSTATUS current;
    if (InterlockedCompareExchange(&context->stopped, 0, 0) != 0) return STATUS_SUCCESS;
    if (InterlockedCompareExchange(&context->stopping, 1, 0) != 0) return STATUS_DEVICE_BUSY;

    /* The dynamic session must close before runtime callouts can be drained. */
    if (context->engine_handle != NULL) {
        current = FwpmEngineClose0(context->engine_handle);
        if (!NT_SUCCESS(current)) return current;
        context->engine_handle = NULL;
    }

    InterlockedCompareExchangePointer((PVOID volatile*)&TgControlContext, NULL, context);
    ExWaitForRundownProtectionRelease(&context->callback_rundown);
    if (context->timer != NULL) WdfTimerStop(context->timer, TRUE);
    TgFlushAll(context, TRUE);
    current = TgWaitForDrain(&context->injections_drained);
    if (!NT_SUCCESS(current)) return current;
    current = TgRemoveAllFlowContexts(context);
    if (!NT_SUCCESS(current)) return current;
    current = TgWaitForDrain(&context->flows_drained);
    if (!NT_SUCCESS(current)) return current;

    current = TgUnregisterCalloutBlocking(&context->callout_datagram_v6);
    if (!NT_SUCCESS(current)) return current;
    current = TgUnregisterCalloutBlocking(&context->callout_datagram_v4);
    if (!NT_SUCCESS(current)) return current;
    current = TgUnregisterCalloutBlocking(&context->callout_flow_v6);
    if (!NT_SUCCESS(current)) return current;
    current = TgUnregisterCalloutBlocking(&context->callout_flow_v4);
    if (!NT_SUCCESS(current)) return current;
    if (context->injection_v6 != NULL) {
        FwpsInjectionHandleDestroy0(context->injection_v6);
        context->injection_v6 = NULL;
    }
    if (context->injection_v4 != NULL) {
        FwpsInjectionHandleDestroy0(context->injection_v4);
        context->injection_v4 = NULL;
    }
    if (context->sha256 != NULL) {
        BCryptCloseAlgorithmProvider(context->sha256, 0);
        context->sha256 = NULL;
    }
    WdfSpinLockAcquire(context->lock);
    policy = context->policy;
    context->policy = NULL;
    WdfSpinLockRelease(context->lock);
    if (policy != NULL) {
        RtlSecureZeroMemory(policy, FIELD_OFFSET(TG_POLICY, entries) + (SIZE_T)policy->entry_count * sizeof(TACHYON_WFP_POLICY_ENTRY));
        ExFreePoolWithTag(policy, TG_POOL_TAG);
    }
    InterlockedExchange(&context->stopped, 1);
    return STATUS_SUCCESS;
}

static NTSTATUS TgUnregisterCalloutBlocking(UINT32* callout_id)
{
    LARGE_INTEGER delay;
    NTSTATUS status = STATUS_DEVICE_BUSY;
    UINT32 attempt;
    if (callout_id == NULL || *callout_id == 0) return STATUS_SUCCESS;
    delay.QuadPart = -((LONGLONG)TG_STOP_RETRY_DELAY_MS * 10 * 1000);
    for (attempt = 0; attempt < TG_STOP_RETRY_COUNT; ++attempt) {
        status = FwpsCalloutUnregisterById0(*callout_id);
        if (NT_SUCCESS(status) || status == STATUS_FWP_CALLOUT_NOT_FOUND) {
            *callout_id = 0;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_DEVICE_BUSY && status != STATUS_FWP_IN_USE) return status;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    return status;
}

static NTSTATUS TgWaitForDrain(KEVENT* event)
{
    LARGE_INTEGER timeout;
    NTSTATUS status;
    timeout.QuadPart = -((LONGLONG)TG_STOP_DRAIN_TIMEOUT_MS * 10 * 1000);
    status = KeWaitForSingleObject(event, Executive, KernelMode, FALSE, &timeout);
    return status == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT : status;
}

static NTSTATUS TgRemoveAllFlowContexts(TG_DEVICE_CONTEXT* context)
{
    NTSTATUS result = STATUS_SUCCESS;
    for (;;) {
        TG_FLOW_CONTEXT* flow = NULL;
        PLIST_ENTRY entry;
        WdfSpinLockAcquire(context->lock);
        for (entry = context->flows.Flink; entry != &context->flows; entry = entry->Flink) {
            TG_FLOW_CONTEXT* candidate = CONTAINING_RECORD(entry, TG_FLOW_CONTEXT, link);
            if (InterlockedCompareExchange(&candidate->remove_requested, 1, 0) == 0 && TgFlowTryReference(candidate)) {
                flow = candidate;
                break;
            }
        }
        WdfSpinLockRelease(context->lock);
        if (flow == NULL) break;
        {
            NTSTATUS status = FwpsFlowRemoveContext0(flow->flow_handle, flow->layer_id, flow->callout_id);
            if (status == STATUS_SUCCESS || status == STATUS_PENDING) {
                /* flowDeleteFn releases the association reference, synchronously or asynchronously. */
            } else if (status == STATUS_UNSUCCESSFUL || status == STATUS_NOT_FOUND) {
                TgCloseFlow(flow);
            } else {
                InterlockedExchange(&flow->remove_requested, 0);
                result = status;
            }
        }
        TgFlowDereference(flow);
        if (!NT_SUCCESS(result)) return result;
    }
    return result;
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

BOOLEAN TgHashBytes(TG_DEVICE_CONTEXT* context, const VOID* bytes, ULONG length,
                    TG_SHA256_DIGEST* output)
{
    if (bytes == NULL || length == 0 || context->sha256 == NULL) {
        RtlZeroMemory(*output, sizeof(*output));
        return FALSE;
    }
    return NT_SUCCESS(BCryptHash(context->sha256, NULL, 0, (PUCHAR)bytes, length,
                                 *output, (ULONG)sizeof(*output)));
}

static VOID TgClassifyFlow(ADDRESS_FAMILY family, const FWPS_INCOMING_VALUES0* values,
                           const FWPS_INCOMING_METADATA_VALUES0* metadata, const FWPS_FILTER0* filter,
                           FWPS_CLASSIFY_OUT0* classify_out)
{
    TG_DEVICE_CONTEXT* context = TgAcquireControlContext();
    TG_FLOW_CONTEXT candidate;
    TG_FLOW_CONTEXT* flow;
    const FWP_BYTE_BLOB* app_id;
    const FWP_BYTE_BLOB* user_id;
    UINT32 app_index;
    UINT32 user_index;
    UINT16 target_layer;
    UINT32 target_callout;
    UCHAR flow_seed[40];
    TG_SHA256_DIGEST flow_digest;
    NTSTATUS status;
    PEPROCESS process;

    UNREFERENCED_PARAMETER(filter);
    RtlZeroMemory(flow_digest, sizeof(flow_digest));
    if ((classify_out->rights & FWPS_RIGHT_ACTION_WRITE) == 0) goto Exit;
    classify_out->actionType = FWP_ACTION_PERMIT;
    if (context == NULL ||
        InterlockedCompareExchange(&context->stopping, 0, 0) != 0 ||
        metadata == NULL || (metadata->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) == 0 ||
        (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0) goto Exit;
    RtlZeroMemory(&candidate, sizeof(candidate));
    candidate.flow_handle = metadata->flowHandle;
    candidate.process_id = metadata->processId;
    candidate.address_family = family;
    candidate.direction = TachyonWfpDirectionOutbound;
    WdfSpinLockAcquire(context->lock);
    if (context->active_session_generation != 0 && context->policy != NULL) {
        candidate.session_generation = (UINT64)context->active_session_generation;
        candidate.generation = context->policy->generation;
        RtlCopyMemory(candidate.lease_nonce, context->policy->lease_nonce, 16);
    }
    WdfSpinLockRelease(context->lock);
    if (candidate.session_generation == 0 || candidate.generation == 0) goto Exit;
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
    if (values->incomingValue[app_index].value.type != FWP_BYTE_BLOB_TYPE ||
        values->incomingValue[user_index].value.type != FWP_SECURITY_DESCRIPTOR_TYPE) goto Exit;
    app_id = values->incomingValue[app_index].value.byteBlob;
    user_id = values->incomingValue[user_index].value.sd;
    if (app_id == NULL || user_id == NULL ||
        !TgHashBytes(context, app_id->data, app_id->size, &candidate.app_id_hash) ||
        !TgHashBytes(context, user_id->data, user_id->size, &candidate.user_security_descriptor_hash) ||
        !TgPolicyMatches(context, &candidate)) goto Exit;
    RtlZeroMemory(flow_seed, sizeof(flow_seed));
    RtlCopyMemory(flow_seed, &candidate.flow_handle, sizeof(candidate.flow_handle));
    RtlCopyMemory(flow_seed + 8, &candidate.session_generation, sizeof(candidate.session_generation));
    RtlCopyMemory(flow_seed + 16, &candidate.generation, sizeof(candidate.generation));
    RtlCopyMemory(flow_seed + 24, &candidate.process_id, sizeof(candidate.process_id));
    RtlCopyMemory(flow_seed + 32, &candidate.process_start_key, sizeof(candidate.process_start_key));
    if (!TgHashBytes(context, flow_seed, sizeof(flow_seed), &flow_digest)) goto Exit;
    RtlCopyMemory(candidate.flow_id, flow_digest, sizeof(candidate.flow_id));
    RtlSecureZeroMemory(flow_digest, sizeof(flow_digest));
    flow = (TG_FLOW_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*flow), TG_POOL_TAG);
    if (flow == NULL) goto Exit;
    RtlCopyMemory(flow, &candidate, sizeof(*flow));
    InitializeListHead(&flow->link);
    flow->owner = context;
    flow->layer_id = target_layer;
    flow->callout_id = target_callout;
    flow->references = 2; /* creator + WFP association/list lifetime */
    flow->listed = 1;
    if (InterlockedIncrement(&context->flow_count) == 1) KeClearEvent(&context->flows_drained);
    WdfSpinLockAcquire(context->lock);
    InsertTailList(&context->flows, &flow->link);
    WdfSpinLockRelease(context->lock);
    status = FwpsFlowAssociateContext0(metadata->flowHandle, target_layer, target_callout, (UINT64)(ULONG_PTR)flow);
    if (!NT_SUCCESS(status)) {
        TgCloseFlow(flow);
    }
    TgFlowDereference(flow);
Exit:
    RtlSecureZeroMemory(flow_digest, sizeof(flow_digest));
    TgReleaseControlContext(context);
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
    TG_DEVICE_CONTEXT* context = TgAcquireControlContext();
    TG_FLOW_CONTEXT* flow = (TG_FLOW_CONTEXT*)(ULONG_PTR)flow_context;
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layer_data;
    NET_BUFFER* net_buffer;
    NET_BUFFER* clone_buffer;
    TG_PENDING_PACKET* packet = NULL;
    SIZE_T record_size;
    SIZE_T control_data_size;
    SIZE_T resident_bytes;
    SIZE_T queue_bytes_after;
    SIZE_T pending_bytes_after;
    ULONG payload_size;
    UCHAR* payload;
    UCHAR* contiguous;
    UINT32 direction_index;
    UINT32 local_address_index, remote_address_index, local_port_index, remote_port_index;
    UINT32 interface_index, sub_interface_index;
    UINT32 local_address_v4, remote_address_v4;
    FWPS_PACKET_INJECTION_STATE injection_state;
    HANDLE injection_context = NULL;
    NTSTATUS status;
    NDIS_STATUS ndis_status;
    BOOLEAN flow_referenced = FALSE;
    TG_CAPTURE_SNAPSHOT capture_snapshot;

    RtlZeroMemory(&capture_snapshot, sizeof(capture_snapshot));
    control_data_size = 0;
    resident_bytes = 0;
    if ((classify_out->rights & FWPS_RIGHT_ACTION_WRITE) == 0) goto Exit;
    classify_out->actionType = FWP_ACTION_PERMIT;
    if (context == NULL || flow == NULL || nbl == NULL || metadata == NULL || values == NULL ||
        InterlockedCompareExchange(&context->stopping, 0, 0) != 0 ||
        InterlockedCompareExchange64(&context->active_session_generation, 0, 0) == 0 ||
        (metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) == 0 ||
        !TgFlowTryReference(flow)) goto Exit;
    flow_referenced = TRUE;
    /* Value-only snapshot: no TG_POLICY pointer escapes context->lock. */
    if (!TgCaptureSnapshot(context, flow, &capture_snapshot)) goto Exit;
    injection_state = FwpsQueryPacketInjectionState0(family == AF_INET ? context->injection_v4 : context->injection_v6,
                                                      nbl, &injection_context);
    if (injection_state == FWPS_PACKET_INJECTED_BY_SELF || injection_state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
        InterlockedIncrement64(&context->statistics.self_injected);
        goto Exit;
    }
    direction_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION : FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION;
    if (values->incomingValue[direction_index].value.uint32 != FWP_DIRECTION_OUTBOUND) goto Exit;
    net_buffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (net_buffer == NULL || NET_BUFFER_NEXT_NB(net_buffer) != NULL) goto Exit;
    payload_size = NET_BUFFER_DATA_LENGTH(net_buffer);
    if (payload_size == 0 || payload_size > TACHYON_WFP_MAX_PAYLOAD_SIZE ||
        payload_size > TACHYON_WFP_MAX_MESSAGE_SIZE - TACHYON_WFP_CAPTURE_HEADER_SIZE) goto Exit;
    status = RtlSizeTAdd(TACHYON_WFP_CAPTURE_HEADER_SIZE, (SIZE_T)payload_size, &record_size);
    if (!NT_SUCCESS(status)) goto Exit;
    packet = (TG_PENDING_PACKET*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*packet), TG_POOL_TAG);
    if (packet == NULL) goto Exit;
    RtlZeroMemory(packet, sizeof(*packet));
    packet->references = 1;
    packet->state = TgPacketCaptured;
    packet->terminal_state = TgPacketCompleted;
    packet->record_size = record_size;
    packet->record = (TACHYON_WFP_CAPTURE_RECORD*)ExAllocatePool2(POOL_FLAG_NON_PAGED, record_size, TG_POOL_TAG);
    if (packet->record == NULL) {
        goto Exit;
    }
    RtlZeroMemory(packet->record, record_size);
    status = FwpsAllocateCloneNetBufferList0(nbl, NULL, NULL, 0, &packet->clone);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    if ((metadata->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) != 0 && metadata->ipHeaderSize > 0) {
        clone_buffer = NET_BUFFER_LIST_FIRST_NB(packet->clone);
        /* Raw transport injection accepts exactly one NET_BUFFER per NBL. */
        if (clone_buffer == NULL || NET_BUFFER_NEXT_NB(clone_buffer) != NULL) goto Exit;
        ndis_status = NdisRetreatNetBufferDataStart(clone_buffer, metadata->ipHeaderSize, 0, NULL);
        if (ndis_status != NDIS_STATUS_SUCCESS) goto Exit;
        packet->clone_retreated_buffer = clone_buffer;
        packet->clone_retreat_length = metadata->ipHeaderSize;
        packet->clone_retreat_active = TRUE;
    }
    if (!packet->clone_retreat_active &&
        (metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA) != 0) {
        if (metadata->controlData == NULL || metadata->controlDataLength == 0 ||
            metadata->controlDataLength > TG_MAX_CONTROL_DATA_SIZE) {
            InterlockedIncrement64(&context->statistics.queue_overflow);
            goto Exit;
        }
        control_data_size = (SIZE_T)metadata->controlDataLength;
    }
    status = RtlSizeTAdd(record_size, control_data_size, &resident_bytes);
    if (!NT_SUCCESS(status) || resident_bytes > context->resident_byte_capacity) {
        InterlockedIncrement64(&context->statistics.queue_overflow);
        goto Exit;
    }
    packet->control_data_size = control_data_size;
    packet->resident_bytes = resident_bytes;
    if (control_data_size != 0) {
        packet->send_params.controlData = (WSACMSGHDR*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, control_data_size, TG_POOL_TAG);
        if (packet->send_params.controlData == NULL) goto Exit;
        packet->send_params.controlDataLength = (ULONG)control_data_size;
        RtlCopyMemory(packet->send_params.controlData, metadata->controlData, control_data_size);
    }
    InitializeListHead(&packet->queue_link);
    InitializeListHead(&packet->pending_link);
    packet->flow = flow;
    flow_referenced = FALSE;
    packet->address_family = family;
    packet->direction = TachyonWfpDirectionOutbound;
    packet->compartment_id = (metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) != 0 ? metadata->compartmentId : UNSPECIFIED_COMPARTMENT_ID;
    packet->endpoint_handle = metadata->transportEndpointHandle;
    local_address_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS;
    remote_address_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS;
    local_port_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT : FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT;
    remote_port_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
    interface_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX : FWPS_FIELD_DATAGRAM_DATA_V6_INTERFACE_INDEX;
    sub_interface_index = family == AF_INET ? FWPS_FIELD_DATAGRAM_DATA_V4_SUB_INTERFACE_INDEX : FWPS_FIELD_DATAGRAM_DATA_V6_SUB_INTERFACE_INDEX;
    packet->interface_index = values->incomingValue[interface_index].value.uint32;
    packet->sub_interface_index = values->incomingValue[sub_interface_index].value.uint32;
    if (family == AF_INET) {
        local_address_v4 = RtlUlongByteSwap(values->incomingValue[local_address_index].value.uint32);
        remote_address_v4 = RtlUlongByteSwap(values->incomingValue[remote_address_index].value.uint32);
        RtlCopyMemory(packet->record->local_address, &local_address_v4, 4);
        RtlCopyMemory(packet->record->remote_address, &remote_address_v4, 4);
        RtlCopyMemory(packet->remote_address, &remote_address_v4, 4);
    } else {
        RtlCopyMemory(packet->record->local_address, values->incomingValue[local_address_index].value.byteArray16->byteArray16, 16);
        RtlCopyMemory(packet->record->remote_address, values->incomingValue[remote_address_index].value.byteArray16->byteArray16, 16);
        RtlCopyMemory(packet->remote_address, values->incomingValue[remote_address_index].value.byteArray16->byteArray16, 16);
    }
    packet->send_params.remoteAddress = packet->remote_address;
    if ((metadata->currentMetadataValues & FWPS_METADATA_FIELD_REMOTE_SCOPE_ID) != 0) {
        packet->send_params.remoteScopeId = metadata->remoteScopeId;
    }
    payload = ((UCHAR*)packet->record) + TACHYON_WFP_CAPTURE_HEADER_SIZE;
    contiguous = NdisGetDataBuffer(net_buffer, payload_size, payload, 1, 0);
    if (contiguous == NULL) goto Exit;
    if (contiguous != payload) RtlCopyMemory(payload, contiguous, payload_size);

    WdfSpinLockAcquire(context->lock);
    if (!TgCaptureSnapshotIsActiveLocked(context, flow, &capture_snapshot)) {
        WdfSpinLockRelease(context->lock);
        goto Exit;
    }
    if (context->pending_count >= context->queue_capacity ||
        !NT_SUCCESS(RtlSizeTAdd(context->queue_bytes, packet->resident_bytes, &queue_bytes_after)) ||
        !NT_SUCCESS(RtlSizeTAdd(context->pending_bytes, packet->resident_bytes, &pending_bytes_after)) ||
        queue_bytes_after > context->resident_byte_capacity ||
        pending_bytes_after > context->resident_byte_capacity) {
        InterlockedIncrement64(&context->statistics.queue_overflow);
        WdfSpinLockRelease(context->lock);
        goto Exit;
    }
    packet->request_id = ++context->next_request_id;
    packet->sequence = (UINT64)InterlockedIncrement64(&flow->next_sequence);
    packet->deadline_100ns = TgInterruptTime100ns() + (UINT64)context->verdict_timeout_ms * 10000u;
    packet->record->header.magic = TACHYON_WFP_ABI_MAGIC;
    packet->record->header.header_size = TACHYON_WFP_HEADER_SIZE;
    packet->record->header.abi_major = TACHYON_WFP_ABI_MAJOR;
    packet->record->header.abi_minor = TACHYON_WFP_ABI_MINOR;
    packet->record->header.kind = TachyonWfpMessageCapture;
    packet->record->header.total_size = (UINT32)record_size;
    packet->record->header.request_id = packet->request_id;
    RtlCopyMemory(packet->record->flow_id, flow->flow_id, 16);
    packet->record->generation = capture_snapshot.policy_generation;
    RtlCopyMemory(packet->record->lease_nonce, capture_snapshot.policy_lease_nonce, 16);
    packet->record->sequence = packet->sequence;
    packet->record->process_id = flow->process_id;
    packet->record->process_start_key = flow->process_start_key;
    RtlCopyMemory(packet->record->app_id_hash, flow->app_id_hash, 32);
    RtlCopyMemory(packet->record->user_security_descriptor_hash, flow->user_security_descriptor_hash, 32);
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
    InsertTailList(&context->capture_queue, &packet->queue_link);
    InsertTailList(&context->pending_packets, &packet->pending_link);
    packet->queued = TRUE;
    packet->pending = TRUE;
    ++context->queue_depth;
    context->queue_bytes = queue_bytes_after;
    ++context->pending_count;
    context->pending_bytes = pending_bytes_after;
    InterlockedIncrement64(&context->statistics.captured);
    packet = NULL; /* pending/queue lists now own the base reference */
    WdfSpinLockRelease(context->lock);
    classify_out->actionType = FWP_ACTION_BLOCK;
    classify_out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    TgServiceCaptureWaiter(context);
Exit:
    if (packet != NULL) TgPacketDereference(packet);
    if (flow_referenced) TgFlowDereference(flow);
    RtlSecureZeroMemory(&capture_snapshot, sizeof(capture_snapshot));
    TgReleaseControlContext(context);
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
    TG_FLOW_CONTEXT* flow = (TG_FLOW_CONTEXT*)(ULONG_PTR)flow_context;
    UNREFERENCED_PARAMETER(layer_id); UNREFERENCED_PARAMETER(callout_id);
    TgCloseFlow(flow);
}

static VOID TgCloseFlow(TG_FLOW_CONTEXT* flow)
{
    TG_DEVICE_CONTEXT* context;
    if (flow == NULL || InterlockedExchange(&flow->closing, 1) != 0) return;
    context = flow->owner;
    if (context != NULL) {
        WdfSpinLockAcquire(context->lock);
        if (InterlockedExchange(&flow->listed, 0) != 0) {
            RemoveEntryList(&flow->link);
            InitializeListHead(&flow->link);
        }
        WdfSpinLockRelease(context->lock);
    }
    TgFlowDereference(flow); /* release the association/list lifetime */
}

VOID TgCompletePacket(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet, UINT32 action)
{
    NTSTATUS status;
    HANDLE injection = packet->address_family == AF_INET ? context->injection_v4 : context->injection_v6;
    if (action == TachyonWfpVerdictPermitDirect && packet->clone != NULL && injection != NULL) {
        if (InterlockedIncrement(&context->injection_count) == 1) KeClearEvent(&context->injections_drained);
        status = FwpsInjectTransportSendAsync0(injection, (HANDLE)packet, packet->endpoint_handle, 0,
                                               packet->clone_retreat_active ? NULL : &packet->send_params,
                                               packet->address_family, packet->compartment_id,
                                               packet->clone, TgInjectComplete, packet);
        if (NT_SUCCESS(status)) {
            InterlockedIncrement64(&context->statistics.permitted);
            return;
        }
        if (InterlockedDecrement(&context->injection_count) == 0) KeSetEvent(&context->injections_drained, IO_NO_INCREMENT, FALSE);
        InterlockedIncrement64(&context->statistics.dropped);
    }
    if (action == TachyonWfpVerdictDrop) InterlockedIncrement64(&context->statistics.dropped);
    if (action == TachyonWfpVerdictTunnel) InterlockedIncrement64(&context->statistics.injected);
    InterlockedCompareExchange(&packet->state, packet->terminal_state, TgPacketCompleting);
    TgPacketDereference(packet);
}

static VOID NTAPI TgInjectComplete(VOID* context, NET_BUFFER_LIST* net_buffer_list, BOOLEAN dispatch_level)
{
    TG_PENDING_PACKET* packet = (TG_PENDING_PACKET*)context;
    UNREFERENCED_PARAMETER(dispatch_level);
    NT_ASSERT(net_buffer_list == NULL || net_buffer_list == packet->clone);
    TgReleasePacketClone(packet);
    InterlockedCompareExchange(&packet->state, packet->terminal_state, TgPacketCompleting);
    if (packet->flow != NULL && packet->flow->owner != NULL &&
        InterlockedDecrement(&packet->flow->owner->injection_count) == 0) {
        KeSetEvent(&packet->flow->owner->injections_drained, IO_NO_INCREMENT, FALSE);
    }
    TgPacketDereference(packet);
}

static VOID TgReleasePacketClone(TG_PENDING_PACKET* packet)
{
    NET_BUFFER_LIST* clone;
    if (packet == NULL) return;
    clone = packet->clone;
    if (clone == NULL) {
        NT_ASSERT(!packet->clone_retreat_active);
        return;
    }
    if (packet->clone_retreat_active) {
        NT_ASSERT(packet->clone_retreated_buffer != NULL);
        NT_ASSERT(packet->clone_retreat_length != 0);
        if (packet->clone_retreated_buffer != NULL && packet->clone_retreat_length != 0) {
            NdisAdvanceNetBufferDataStart(packet->clone_retreated_buffer,
                                          packet->clone_retreat_length, TRUE, NULL);
        }
        packet->clone_retreated_buffer = NULL;
        packet->clone_retreat_length = 0;
        packet->clone_retreat_active = FALSE;
    }
    FwpsFreeCloneNetBufferList0(clone, 0);
    packet->clone = NULL;
}

VOID TgPacketReference(TG_PENDING_PACKET* packet)
{
    LONG references;
    NT_ASSERT(packet != NULL);
    references = InterlockedIncrement(&packet->references);
    NT_ASSERT(references > 1);
    UNREFERENCED_PARAMETER(references);
}

VOID TgPacketDereference(TG_PENDING_PACKET* packet)
{
    if (packet != NULL && InterlockedDecrement(&packet->references) == 0) TgFreePendingPacket(packet);
}

static VOID TgFreePendingPacket(TG_PENDING_PACKET* packet)
{
    if (packet == NULL) return;
    TgReleasePacketClone(packet);
    if (packet->record != NULL) {
        RtlSecureZeroMemory(packet->record, packet->record_size);
        ExFreePoolWithTag(packet->record, TG_POOL_TAG);
    }
    if (packet->send_params.controlData != NULL) {
        RtlSecureZeroMemory(packet->send_params.controlData, packet->control_data_size);
        ExFreePoolWithTag(packet->send_params.controlData, TG_POOL_TAG);
        packet->send_params.controlData = NULL;
        packet->send_params.controlDataLength = 0;
        packet->control_data_size = 0;
    }
    if (packet->flow != NULL) {
        TgFlowDereference(packet->flow);
        packet->flow = NULL;
    }
    RtlSecureZeroMemory(packet, sizeof(*packet));
    ExFreePoolWithTag(packet, TG_POOL_TAG);
}
