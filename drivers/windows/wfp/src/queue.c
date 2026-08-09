// SPDX-License-Identifier: Apache-2.0
#include "tachyon_wfp.h"

static BOOLEAN TgAllZero(const UCHAR* value, SIZE_T length)
{
    UCHAR aggregate = 0;
    SIZE_T index;
    for (index = 0; index < length; ++index) {
        aggregate |= value[index];
    }
    return aggregate == 0;
}

static BOOLEAN TgEqualIdentity(const TG_PENDING_PACKET* packet, const TACHYON_WFP_VERDICT* verdict)
{
    return packet->request_id == verdict->header.request_id && packet->sequence == verdict->sequence &&
           packet->flow->generation == verdict->generation &&
           RtlCompareMemory(packet->flow->flow_id, verdict->flow_id, 16) == 16 &&
           RtlCompareMemory(packet->flow->lease_nonce, verdict->lease_nonce, 16) == 16;
}

static VOID TgDetachQueueLocked(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet)
{
    if (!packet->queued) return;
    RemoveEntryList(&packet->queue_link);
    InitializeListHead(&packet->queue_link);
    packet->queued = FALSE;
    --context->queue_depth;
    context->queue_bytes -= packet->record_size;
}

static VOID TgDetachPendingLocked(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet)
{
    if (!packet->pending) return;
    RemoveEntryList(&packet->pending_link);
    InitializeListHead(&packet->pending_link);
    packet->pending = FALSE;
    --context->pending_count;
    context->pending_bytes -= packet->record_size;
}

static BOOLEAN TgBeginCompletionLocked(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet)
{
    LONG state = InterlockedCompareExchange(&packet->state, TgPacketCompleting, TgPacketCaptured);
    if (state != TgPacketCaptured) {
        state = InterlockedCompareExchange(&packet->state, TgPacketCompleting, TgPacketDequeued);
        if (state != TgPacketDequeued) return FALSE;
    }
    TgPacketReference(packet); /* local completion path */
    TgDetachQueueLocked(context, packet);
    TgDetachPendingLocked(context, packet);
    return TRUE;
}

static VOID TgReleasePendingOwnerAndComplete(TG_DEVICE_CONTEXT* context, TG_PENDING_PACKET* packet, UINT32 action)
{
    TgPacketDereference(packet); /* pending-list/base owner */
    TgCompletePacket(context, packet, action); /* consumes local completion reference */
}

NTSTATUS TgSetPolicy(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size)
{
    const TACHYON_WFP_POLICY_HEADER* header = (const TACHYON_WFP_POLICY_HEADER*)input;
    const TACHYON_WFP_POLICY_ENTRY* entries;
    TG_POLICY* policy;
    TG_POLICY* previous;
    SIZE_T entries_size;
    SIZE_T allocation_size;
    UINT32 index;

    if (input_size < TACHYON_WFP_POLICY_HEADER_SIZE || !TgValidateHeader(&header->header, input_size, TachyonWfpMessagePolicy) ||
        header->entry_count == 0 || header->entry_count > 1024 || header->policy_flags != 0 ||
        TgAllZero(header->lease_nonce, sizeof(header->lease_nonce))) {
        return STATUS_INVALID_PARAMETER;
    }
    entries_size = (SIZE_T)header->entry_count * TACHYON_WFP_POLICY_ENTRY_SIZE;
    if (entries_size / TACHYON_WFP_POLICY_ENTRY_SIZE != header->entry_count ||
        input_size != TACHYON_WFP_POLICY_HEADER_SIZE + entries_size) {
        return STATUS_INTEGER_OVERFLOW;
    }
    entries = (const TACHYON_WFP_POLICY_ENTRY*)((const UCHAR*)input + TACHYON_WFP_POLICY_HEADER_SIZE);
    for (index = 0; index < header->entry_count; ++index) {
        const TACHYON_WFP_POLICY_ENTRY* entry = &entries[index];
        const UINT32 known = TachyonWfpPolicyMatchPid | TachyonWfpPolicyMatchProcessStart |
                             TachyonWfpPolicyMatchAppIdHash | TachyonWfpPolicyMatchUserSidHash;
        if (entry->reserved != 0 || entry->match_flags == 0 || (entry->match_flags & ~known) != 0 ||
            ((entry->match_flags & TachyonWfpPolicyMatchPid) != 0 && entry->process_id == 0) ||
            ((entry->match_flags & TachyonWfpPolicyMatchProcessStart) != 0 && entry->process_start_key == 0) ||
            ((entry->match_flags & TachyonWfpPolicyMatchAppIdHash) != 0 && TgAllZero(entry->app_id_hash, 32)) ||
            ((entry->match_flags & TachyonWfpPolicyMatchUserSidHash) != 0 && TgAllZero(entry->user_sid_hash, 32))) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    allocation_size = FIELD_OFFSET(TG_POLICY, entries) + entries_size;
    policy = (TG_POLICY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocation_size, TG_POOL_TAG);
    if (policy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(policy, allocation_size);
    policy->generation = header->generation;
    RtlCopyMemory(policy->lease_nonce, header->lease_nonce, 16);
    policy->entry_count = header->entry_count;
    RtlCopyMemory(policy->entries, entries, entries_size);

    WdfSpinLockAcquire(context->lock);
    if (context->policy != NULL && header->generation <= context->policy->generation) {
        WdfSpinLockRelease(context->lock);
        RtlSecureZeroMemory(policy, allocation_size);
        ExFreePoolWithTag(policy, TG_POOL_TAG);
        return STATUS_REVISION_MISMATCH;
    }
    previous = context->policy;
    context->policy = policy;
    WdfSpinLockRelease(context->lock);
    if (previous != NULL) {
        RtlSecureZeroMemory(previous, FIELD_OFFSET(TG_POLICY, entries) + (SIZE_T)previous->entry_count * sizeof(TACHYON_WFP_POLICY_ENTRY));
        ExFreePoolWithTag(previous, TG_POOL_TAG);
    }
    return STATUS_SUCCESS;
}

NTSTATUS TgDisablePolicy(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size)
{
    const TACHYON_WFP_DISABLE_POLICY* disable = (const TACHYON_WFP_DISABLE_POLICY*)input;
    TG_POLICY* policy;
    if (input_size != sizeof(*disable) || !TgValidateHeader(&disable->header, input_size, TachyonWfpMessageDisablePolicy)) {
        return STATUS_INVALID_PARAMETER;
    }
    WdfSpinLockAcquire(context->lock);
    policy = context->policy;
    if (policy == NULL || disable->generation != policy->generation ||
        RtlCompareMemory(disable->lease_nonce, policy->lease_nonce, 16) != 16) {
        WdfSpinLockRelease(context->lock);
        return STATUS_NOT_FOUND;
    }
    context->policy = NULL;
    WdfSpinLockRelease(context->lock);
    RtlSecureZeroMemory(policy, FIELD_OFFSET(TG_POLICY, entries) + (SIZE_T)policy->entry_count * sizeof(TACHYON_WFP_POLICY_ENTRY));
    ExFreePoolWithTag(policy, TG_POOL_TAG);
    TgFlushAll(context, TRUE);
    return STATUS_SUCCESS;
}

BOOLEAN TgPolicyMatches(TG_DEVICE_CONTEXT* context, const TG_FLOW_CONTEXT* flow)
{
    UINT32 index;
    BOOLEAN matched = FALSE;
    WdfSpinLockAcquire(context->lock);
    if (context->policy == NULL || context->policy->generation != flow->generation ||
        RtlCompareMemory(context->policy->lease_nonce, flow->lease_nonce, 16) != 16) {
        WdfSpinLockRelease(context->lock);
        return FALSE;
    }
    for (index = 0; index < context->policy->entry_count; ++index) {
        const TACHYON_WFP_POLICY_ENTRY* entry = &context->policy->entries[index];
        if (((entry->match_flags & TachyonWfpPolicyMatchPid) == 0 || entry->process_id == flow->process_id) &&
            ((entry->match_flags & TachyonWfpPolicyMatchProcessStart) == 0 || entry->process_start_key == flow->process_start_key) &&
            ((entry->match_flags & TachyonWfpPolicyMatchAppIdHash) == 0 || RtlCompareMemory(entry->app_id_hash, flow->app_id_hash, 32) == 32) &&
            ((entry->match_flags & TachyonWfpPolicyMatchUserSidHash) == 0 || RtlCompareMemory(entry->user_sid_hash, flow->user_sid_hash, 32) == 32)) {
            matched = TRUE;
            break;
        }
    }
    WdfSpinLockRelease(context->lock);
    return matched;
}

NTSTATUS TgCopyNextCapture(TG_DEVICE_CONTEXT* context, WDFREQUEST request, SIZE_T output_size)
{
    TG_PENDING_PACKET* packet = NULL;
    VOID* output;
    NTSTATUS status;
    WdfSpinLockAcquire(context->lock);
    if (!IsListEmpty(&context->capture_queue)) {
        PLIST_ENTRY entry = RemoveHeadList(&context->capture_queue);
        packet = CONTAINING_RECORD(entry, TG_PENDING_PACKET, queue_link);
        InitializeListHead(&packet->queue_link);
        packet->queued = FALSE;
        --context->queue_depth;
        context->queue_bytes -= packet->record_size;
        if (InterlockedCompareExchange(&packet->state, TgPacketDequeued, TgPacketCaptured) != TgPacketCaptured) {
            packet = NULL;
        } else {
            TgPacketReference(packet); /* protects copy against timeout/verdict/flush */
        }
    }
    WdfSpinLockRelease(context->lock);
    if (packet == NULL) {
        status = WdfRequestForwardToIoQueue(request, context->dequeue_queue);
        return NT_SUCCESS(status) ? STATUS_PENDING : status;
    }
    if (output_size < packet->record_size) {
        BOOLEAN claimed;
        WdfSpinLockAcquire(context->lock);
        claimed = InterlockedCompareExchange(&packet->state, TgPacketCompleting, TgPacketDequeued) == TgPacketDequeued;
        if (claimed) TgDetachPendingLocked(context, packet);
        WdfSpinLockRelease(context->lock);
        if (claimed) {
            TgPacketDereference(packet); /* pending-list/base owner */
            TgCompletePacket(context, packet, TachyonWfpVerdictPermitDirect); /* consumes copy reference */
        } else {
            TgPacketDereference(packet);
        }
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = WdfRequestRetrieveOutputBuffer(request, packet->record_size, &output, NULL);
    if (!NT_SUCCESS(status)) {
        BOOLEAN claimed;
        WdfSpinLockAcquire(context->lock);
        claimed = InterlockedCompareExchange(&packet->state, TgPacketCompleting, TgPacketDequeued) == TgPacketDequeued;
        if (claimed) TgDetachPendingLocked(context, packet);
        WdfSpinLockRelease(context->lock);
        if (claimed) {
            TgPacketDereference(packet);
            TgCompletePacket(context, packet, TachyonWfpVerdictPermitDirect);
        } else {
            TgPacketDereference(packet);
        }
        return status;
    }
    RtlCopyMemory(output, packet->record, packet->record_size);
    WdfRequestSetInformation(request, packet->record_size);
    TgPacketDereference(packet);
    return STATUS_SUCCESS;
}

VOID TgServiceCaptureWaiter(TG_DEVICE_CONTEXT* context)
{
    WDFREQUEST request;
    NTSTATUS status = WdfIoQueueRetrieveNextRequest(context->dequeue_queue, &request);
    if (NT_SUCCESS(status)) {
        status = TgCopyNextCapture(context, request, (SIZE_T)TACHYON_WFP_MAX_MESSAGE_SIZE);
        if (status != STATUS_PENDING) {
            WdfRequestComplete(request, status);
        }
    }
}

NTSTATUS TgApplyVerdict(TG_DEVICE_CONTEXT* context, const VOID* input, SIZE_T input_size)
{
    const TACHYON_WFP_VERDICT* verdict = (const TACHYON_WFP_VERDICT*)input;
    TG_PENDING_PACKET* packet = NULL;
    PLIST_ENTRY entry;
    if (input_size < TACHYON_WFP_VERDICT_HEADER_SIZE || !TgValidateHeader(&verdict->header, input_size, TachyonWfpMessageVerdict) ||
        verdict->payload_size != input_size - TACHYON_WFP_VERDICT_HEADER_SIZE || verdict->payload_size != 0 ||
        verdict->reserved != 0 || verdict->reason != 0 ||
        verdict->action < TachyonWfpVerdictTunnel || verdict->action > TachyonWfpVerdictDrop) {
        InterlockedIncrement64((volatile LONG64*)&context->statistics.rejected_frames);
        return STATUS_INVALID_PARAMETER;
    }
    WdfSpinLockAcquire(context->lock);
    for (entry = context->pending_packets.Flink; entry != &context->pending_packets; entry = entry->Flink) {
        TG_PENDING_PACKET* candidate = CONTAINING_RECORD(entry, TG_PENDING_PACKET, pending_link);
        if (TgEqualIdentity(candidate, verdict) && TgBeginCompletionLocked(context, candidate)) {
            packet = candidate;
            break;
        }
    }
    WdfSpinLockRelease(context->lock);
    if (packet == NULL) {
        InterlockedIncrement64((volatile LONG64*)&context->statistics.rejected_frames);
        return STATUS_NOT_FOUND;
    }
    TgReleasePendingOwnerAndComplete(context, packet, verdict->action);
    return STATUS_SUCCESS;
}

VOID TgEvtTimeoutTimer(_In_ WDFTIMER timer)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext((WDFDEVICE)WdfTimerGetParentObject(timer));
    LIST_ENTRY expired;
    PLIST_ENTRY entry;
    UINT64 now = TgNow100ns();
    InitializeListHead(&expired);
    WdfSpinLockAcquire(context->lock);
    entry = context->pending_packets.Flink;
    while (entry != &context->pending_packets) {
        TG_PENDING_PACKET* packet = CONTAINING_RECORD(entry, TG_PENDING_PACKET, pending_link);
        entry = entry->Flink;
        if (packet->deadline_100ns <= now && TgBeginCompletionLocked(context, packet)) {
            /* Move the local completion reference to the detached work list. */
            InsertTailList(&expired, &packet->pending_link);
        }
    }
    WdfSpinLockRelease(context->lock);
    while (!IsListEmpty(&expired)) {
        TG_PENDING_PACKET* packet = CONTAINING_RECORD(RemoveHeadList(&expired), TG_PENDING_PACKET, pending_link);
        InitializeListHead(&packet->pending_link);
        InterlockedIncrement64((volatile LONG64*)&context->statistics.verdict_timeout);
        TgReleasePendingOwnerAndComplete(context, packet, TachyonWfpVerdictPermitDirect);
    }
}

VOID TgFlushAll(TG_DEVICE_CONTEXT* context, BOOLEAN permit_direct)
{
    LIST_ENTRY detached;
    WDFREQUEST request;
    InitializeListHead(&detached);
    WdfSpinLockAcquire(context->lock);
    while (!IsListEmpty(&context->pending_packets)) {
        TG_PENDING_PACKET* packet = CONTAINING_RECORD(context->pending_packets.Flink, TG_PENDING_PACKET, pending_link);
        if (!TgBeginCompletionLocked(context, packet)) {
            TgDetachPendingLocked(context, packet);
            TgPacketDereference(packet);
            continue;
        }
        InsertTailList(&detached, &packet->pending_link); /* local completion reference */
    }
    context->queue_depth = 0;
    context->queue_bytes = 0;
    context->pending_count = 0;
    context->pending_bytes = 0;
    InitializeListHead(&context->capture_queue);
    WdfSpinLockRelease(context->lock);
    while (NT_SUCCESS(WdfIoQueueRetrieveNextRequest(context->dequeue_queue, &request))) {
        WdfRequestComplete(request, STATUS_CANCELLED);
    }
    while (!IsListEmpty(&detached)) {
        TG_PENDING_PACKET* packet = CONTAINING_RECORD(RemoveHeadList(&detached), TG_PENDING_PACKET, pending_link);
        InitializeListHead(&packet->pending_link);
        TgReleasePendingOwnerAndComplete(context, packet,
            permit_direct ? TachyonWfpVerdictPermitDirect : TachyonWfpVerdictDrop);
    }
}
