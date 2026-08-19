// SPDX-License-Identifier: Apache-2.0
#include "tachyon_wfp.h"

static NTSTATUS TgNegotiate(TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* session,
                            WDFREQUEST request, SIZE_T input_size, SIZE_T output_size);
static NTSTATUS TgReadStatistics(TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* session,
                                 WDFREQUEST request, SIZE_T output_size);
static BOOLEAN TgIoctlRequiresNegotiation(ULONG ioctl);

NTSTATUS TgCreateControlDevice(_In_ WDFDRIVER driver, _Out_ WDFDEVICE* device_out)
{
    DECLARE_CONST_UNICODE_STRING(sddl, TG_HELPER_SDDL);
    DECLARE_CONST_UNICODE_STRING(device_name, TG_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symbolic_link, TG_SYMBOLIC_LINK);
    WDFDEVICE_INIT* init;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES file_attributes;
    WDF_FILEOBJECT_CONFIG file_config;
    WDF_IO_QUEUE_CONFIG queue_config;
    WDF_IO_QUEUE_CONFIG manual_config;
    WDF_TIMER_CONFIG timer_config;
    TG_DEVICE_CONTEXT* context;
    NTSTATUS status;

    init = WdfControlDeviceInitAllocate(driver, &sddl);
    if (init == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    WdfDeviceInitSetDeviceType(init, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(init, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetIoType(init, WdfDeviceIoDirect);
    WDF_FILEOBJECT_CONFIG_INIT(&file_config, TgEvtFileCreate, WDF_NO_EVENT_CALLBACK, TgEvtFileCleanup);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&file_attributes, TG_FILE_CONTEXT);
    WdfDeviceInitSetFileObjectConfig(init, &file_config, &file_attributes);
    status = WdfDeviceInitAssignName(init, &device_name);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(init);
        return status;
    }
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, TG_DEVICE_CONTEXT);
    status = WdfDeviceCreate(&init, &attributes, device_out);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = WdfDeviceCreateSymbolicLink(*device_out, &symbolic_link);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    context = TgGetDeviceContext(*device_out);
    RtlZeroMemory(context, sizeof(*context));
    context->device = *device_out;
    context->queue_capacity = TACHYON_WFP_DEFAULT_QUEUE_CAPACITY;
    context->resident_byte_capacity = TACHYON_WFP_DEFAULT_RESIDENT_BYTES;
    context->verdict_timeout_ms = TACHYON_WFP_DEFAULT_VERDICT_TIMEOUT_MS;
    ExInitializeRundownProtection(&context->callback_rundown);
    KeInitializeEvent(&context->flows_drained, NotificationEvent, TRUE);
    KeInitializeEvent(&context->injections_drained, NotificationEvent, TRUE);
    InitializeListHead(&context->capture_queue);
    InitializeListHead(&context->pending_packets);
    InitializeListHead(&context->flows);
    status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->lock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchParallel);
    queue_config.EvtIoDeviceControl = TgEvtIoDeviceControl;
    status = WdfIoQueueCreate(*device_out, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &context->default_queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    WDF_IO_QUEUE_CONFIG_INIT(&manual_config, WdfIoQueueDispatchManual);
    status = WdfIoQueueCreate(*device_out, &manual_config, WDF_NO_OBJECT_ATTRIBUTES, &context->dequeue_queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    WDF_TIMER_CONFIG_INIT_PERIODIC(&timer_config, TgEvtTimeoutTimer, TG_TIMER_PERIOD_MS);
    timer_config.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = *device_out;
    status = WdfTimerCreate(&timer_config, &attributes, &context->timer);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return STATUS_SUCCESS;
}

VOID TgEvtFileCreate(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ WDFFILEOBJECT file_object)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext(device);
    TG_FILE_CONTEXT* file_context = TgGetFileContext(file_object);
    BOOLEAN accepted = FALSE;
    RtlZeroMemory(file_context, sizeof(*file_context));
    ExInitializeRundownProtection(&file_context->io_rundown);
    WdfSpinLockAcquire(context->lock);
    if (InterlockedCompareExchange(&context->stopping, 0, 0) == 0 && context->client_open == 0) {
        ++context->next_session_generation;
        if (context->next_session_generation == 0) ++context->next_session_generation;
        file_context->generation = context->next_session_generation;
        context->session_file = file_object;
        InterlockedExchange64(&context->active_session_generation, 0);
        context->client_open = 1;
        accepted = TRUE;
    }
    WdfSpinLockRelease(context->lock);
    if (!accepted) {
        WdfRequestComplete(request, STATUS_DEVICE_BUSY);
        return;
    }
    WdfRequestComplete(request, STATUS_SUCCESS);
}

VOID TgEvtFileCleanup(_In_ WDFFILEOBJECT file_object)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext(WdfFileObjectGetDevice(file_object));
    TG_FILE_CONTEXT* file_context = TgGetFileContext(file_object);
    InterlockedExchange(&file_context->closing, 1);
    InterlockedExchange(&file_context->negotiated, 0);
    WdfSpinLockAcquire(context->lock);
    if (context->session_file == file_object) {
        InterlockedExchange64(&context->active_session_generation, 0);
    }
    WdfSpinLockRelease(context->lock);
    ExWaitForRundownProtectionRelease(&file_context->io_rundown);
    TgClearPolicy(context);
    WdfSpinLockAcquire(context->lock);
    if (context->session_file == file_object) {
        context->session_file = NULL;
        context->client_open = 0;
    }
    WdfSpinLockRelease(context->lock);
}

VOID TgEvtIoDeviceControl(_In_ WDFQUEUE queue, _In_ WDFREQUEST request, _In_ SIZE_T output_size,
                          _In_ SIZE_T input_size, _In_ ULONG ioctl)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext(WdfIoQueueGetDevice(queue));
    TG_SESSION_TOKEN session;
    VOID* input = NULL;
    NTSTATUS status;

    if (!TgAcquireRequestSession(context, request, TgIoctlRequiresNegotiation(ioctl), &session)) {
        WdfRequestComplete(request, STATUS_INVALID_DEVICE_STATE);
        return;
    }
    switch (ioctl) {
    case IOCTL_TACHYON_WFP_NEGOTIATE:
        status = TgNegotiate(context, &session, request, input_size, output_size);
        break;
    case IOCTL_TACHYON_WFP_SET_POLICY:
    case IOCTL_TACHYON_WFP_DISABLE_POLICY:
    case IOCTL_TACHYON_WFP_VERDICT:
        status = WdfRequestRetrieveInputBuffer(request, TACHYON_WFP_HEADER_SIZE, &input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        if (ioctl == IOCTL_TACHYON_WFP_SET_POLICY) {
            status = TgSetPolicy(context, &session, input, input_size);
        } else if (ioctl == IOCTL_TACHYON_WFP_DISABLE_POLICY) {
            status = TgDisablePolicy(context, &session, input, input_size);
        } else {
            status = TgApplyVerdict(context, &session, input, input_size);
        }
        break;
    case IOCTL_TACHYON_WFP_DEQUEUE:
        status = TgCopyNextCapture(context, &session, request, output_size);
        if (status == STATUS_PENDING) {
            TgReleaseRequestSession(&session);
            return;
        }
        break;
    case IOCTL_TACHYON_WFP_STATISTICS:
        status = TgReadStatistics(context, &session, request, output_size);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    TgReleaseRequestSession(&session);
    WdfRequestComplete(request, status);
}

static NTSTATUS TgNegotiate(TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* session,
                            WDFREQUEST request, SIZE_T input_size, SIZE_T output_size)
{
    TACHYON_WFP_NEGOTIATE_REQUEST* input;
    TACHYON_WFP_NEGOTIATE_RESPONSE* output;
    NTSTATUS status;
    static const UCHAR build_id[16] = TACHYON_WFP_DRIVER_BUILD_ID_INIT;
    static const UCHAR helper_build_id[16] = TACHYON_WFP_HELPER_BUILD_ID_INIT;
    static const UCHAR service_sid_hash[32] = TACHYON_WFP_HELPER_SERVICE_SID_SHA256_INIT;

    if (input_size != TACHYON_WFP_NEGOTIATE_REQUEST_SIZE || output_size < TACHYON_WFP_NEGOTIATE_RESPONSE_SIZE) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    status = WdfRequestRetrieveInputBuffer(request, sizeof(*input), (VOID**)&input, NULL);
    if (!NT_SUCCESS(status) || !TgValidateHeader(&input->header, input_size, TachyonWfpMessageNegotiateRequest)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (input->header.flags != 0 || RtlCompareMemory(input->helper_build_id, helper_build_id, sizeof(helper_build_id)) != sizeof(helper_build_id) ||
        (input->required_capabilities & ~TACHYON_WFP_REQUIRED_CAPABILITIES) != 0 ||
        input->required_capabilities != TACHYON_WFP_REQUIRED_CAPABILITIES ||
        input->requested_queue_capacity == 0 || input->requested_queue_capacity > TACHYON_WFP_DEFAULT_QUEUE_CAPACITY ||
        input->requested_timeout_ms < 25 || input->requested_timeout_ms > 1000) {
        return STATUS_REVISION_MISMATCH;
    }
    if (InterlockedCompareExchange(&session->file_context->negotiated, -1, 0) != 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = WdfRequestRetrieveOutputBuffer(request, sizeof(*output), (VOID**)&output, NULL);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&session->file_context->negotiated, 0);
        return status;
    }
    RtlZeroMemory(output, sizeof(*output));
    output->header.magic = TACHYON_WFP_ABI_MAGIC;
    output->header.header_size = TACHYON_WFP_HEADER_SIZE;
    output->header.abi_major = TACHYON_WFP_ABI_MAJOR;
    output->header.abi_minor = TACHYON_WFP_ABI_MINOR;
    output->header.kind = TachyonWfpMessageNegotiateResponse;
    output->header.total_size = sizeof(*output);
    output->header.request_id = input->header.request_id;
    RtlCopyMemory(output->driver_build_id, build_id, sizeof(build_id));
    output->capabilities = TACHYON_WFP_REQUIRED_CAPABILITIES;
    output->max_message_size = TACHYON_WFP_MAX_MESSAGE_SIZE;
    output->queue_capacity = input->requested_queue_capacity;
    output->verdict_timeout_ms = input->requested_timeout_ms;
    output->fail_policy = TachyonWfpFailOpenDirect;
    RtlCopyMemory(output->service_sid_hash, service_sid_hash, sizeof(service_sid_hash));
    WdfSpinLockAcquire(context->lock);
    if (context->session_file != session->file_object || context->client_open == 0 ||
        session->file_context->generation != session->generation ||
        InterlockedCompareExchange(&session->file_context->closing, 0, 0) != 0) {
        WdfSpinLockRelease(context->lock);
        InterlockedExchange(&session->file_context->negotiated, 0);
        return STATUS_INVALID_DEVICE_STATE;
    }
    context->queue_capacity = input->requested_queue_capacity;
    context->verdict_timeout_ms = input->requested_timeout_ms;
    InterlockedExchange(&session->file_context->negotiated, 1);
    InterlockedExchange64(&context->active_session_generation, (LONG64)session->generation);
    WdfSpinLockRelease(context->lock);
    WdfRequestSetInformation(request, sizeof(*output));
    return STATUS_SUCCESS;
}

static BOOLEAN TgIoctlRequiresNegotiation(ULONG ioctl)
{
    switch (ioctl) {
    case IOCTL_TACHYON_WFP_SET_POLICY:
    case IOCTL_TACHYON_WFP_DISABLE_POLICY:
    case IOCTL_TACHYON_WFP_DEQUEUE:
    case IOCTL_TACHYON_WFP_VERDICT:
    case IOCTL_TACHYON_WFP_STATISTICS:
        return TRUE;
    default:
        return FALSE;
    }
}

BOOLEAN TgAcquireRequestSession(TG_DEVICE_CONTEXT* context, WDFREQUEST request, BOOLEAN require_negotiated,
                                TG_SESSION_TOKEN* token)
{
    WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
    TG_FILE_CONTEXT* file_context;
    BOOLEAN valid;
    RtlZeroMemory(token, sizeof(*token));
    if (file_object == NULL) return FALSE;
    file_context = TgGetFileContext(file_object);
    if (!ExAcquireRundownProtection(&file_context->io_rundown)) return FALSE;
    token->file_context = file_context;
    token->file_object = file_object;
    token->generation = file_context->generation;
    WdfSpinLockAcquire(context->lock);
    valid = context->client_open != 0 && context->session_file == file_object &&
            token->generation != 0 && file_context->generation == token->generation &&
            InterlockedCompareExchange(&file_context->closing, 0, 0) == 0 &&
            (!require_negotiated || TgSessionIsActiveLocked(context, token));
    WdfSpinLockRelease(context->lock);
    if (!valid) TgReleaseRequestSession(token);
    return valid;
}

VOID TgReleaseRequestSession(TG_SESSION_TOKEN* token)
{
    if (token->file_context != NULL) {
        ExReleaseRundownProtection(&token->file_context->io_rundown);
        RtlZeroMemory(token, sizeof(*token));
    }
}

BOOLEAN TgSessionIsActiveLocked(const TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* token)
{
    return token != NULL && token->file_context != NULL && token->generation != 0 &&
           context->client_open != 0 && context->session_file == token->file_object &&
           context->active_session_generation == (LONG64)token->generation &&
           token->file_context->generation == token->generation &&
           InterlockedCompareExchange(&token->file_context->closing, 0, 0) == 0 &&
           InterlockedCompareExchange(&token->file_context->negotiated, 0, 0) == 1;
}

static NTSTATUS TgReadStatistics(TG_DEVICE_CONTEXT* context, const TG_SESSION_TOKEN* session,
                                 WDFREQUEST request, SIZE_T output_size)
{
    TACHYON_WFP_STATISTICS* output;
    NTSTATUS status;
    if (output_size < sizeof(*output)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = WdfRequestRetrieveOutputBuffer(request, sizeof(*output), (VOID**)&output, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    WdfSpinLockAcquire(context->lock);
    if (!TgSessionIsActiveLocked(context, session)) {
        WdfSpinLockRelease(context->lock);
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(output, sizeof(*output));
    output->header.magic = TACHYON_WFP_ABI_MAGIC;
    output->header.header_size = TACHYON_WFP_HEADER_SIZE;
    output->header.abi_major = TACHYON_WFP_ABI_MAJOR;
    output->header.abi_minor = TACHYON_WFP_ABI_MINOR;
    output->header.kind = TachyonWfpMessageStatistics;
    output->header.total_size = TACHYON_WFP_STATISTICS_SIZE;
    output->header.request_id = ++context->next_request_id;
    output->captured = (UINT64)InterlockedCompareExchange64(&context->statistics.captured, 0, 0);
    output->permitted = (UINT64)InterlockedCompareExchange64(&context->statistics.permitted, 0, 0);
    output->dropped = (UINT64)InterlockedCompareExchange64(&context->statistics.dropped, 0, 0);
    output->injected = (UINT64)InterlockedCompareExchange64(&context->statistics.injected, 0, 0);
    output->self_injected = (UINT64)InterlockedCompareExchange64(&context->statistics.self_injected, 0, 0);
    output->queue_overflow = (UINT64)InterlockedCompareExchange64(&context->statistics.queue_overflow, 0, 0);
    output->verdict_timeout = (UINT64)InterlockedCompareExchange64(&context->statistics.verdict_timeout, 0, 0);
    output->rejected_frames = (UINT64)InterlockedCompareExchange64(&context->statistics.rejected_frames, 0, 0);
    output->queue_depth = context->queue_depth;
    output->pending_verdicts = context->pending_count;
    WdfSpinLockRelease(context->lock);
    WdfRequestSetInformation(request, sizeof(*output));
    return STATUS_SUCCESS;
}

BOOLEAN TgValidateHeader(const TACHYON_WFP_MESSAGE_HEADER* header, SIZE_T actual, UINT16 kind)
{
    return header != NULL && actual >= TACHYON_WFP_HEADER_SIZE && actual <= TACHYON_WFP_MAX_MESSAGE_SIZE &&
           header->magic == TACHYON_WFP_ABI_MAGIC && header->header_size == TACHYON_WFP_HEADER_SIZE &&
           header->abi_major == TACHYON_WFP_ABI_MAJOR && header->abi_minor <= TACHYON_WFP_ABI_MINOR &&
           header->kind == kind && header->flags == 0 && header->total_size == actual &&
           header->request_id != 0 && header->reserved == 0;
}

UINT64 TgInterruptTime100ns(VOID)
{
    ULONG64 qpc_timestamp;
    return KeQueryInterruptTimePrecise(&qpc_timestamp);
}
