// SPDX-License-Identifier: Apache-2.0
#include "tachyon_wfp.h"

static NTSTATUS TgNegotiate(TG_DEVICE_CONTEXT* context, WDFREQUEST request, SIZE_T input_size, SIZE_T output_size);
static NTSTATUS TgReadStatistics(TG_DEVICE_CONTEXT* context, WDFREQUEST request, SIZE_T output_size);

NTSTATUS TgCreateControlDevice(_In_ WDFDRIVER driver, _Out_ WDFDEVICE* device_out)
{
    DECLARE_CONST_UNICODE_STRING(sddl, TG_HELPER_SDDL);
    DECLARE_CONST_UNICODE_STRING(device_name, TG_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symbolic_link, TG_SYMBOLIC_LINK);
    WDFDEVICE_INIT* init;
    WDF_OBJECT_ATTRIBUTES attributes;
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
    WdfDeviceInitSetFileObjectConfig(init, &file_config, WDF_NO_OBJECT_ATTRIBUTES);
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
    context->verdict_timeout_ms = TACHYON_WFP_DEFAULT_VERDICT_TIMEOUT_MS;
    InitializeListHead(&context->capture_queue);
    InitializeListHead(&context->pending_packets);
    InitializeListHead(&context->flows);
    context->statistics.header.magic = TACHYON_WFP_ABI_MAGIC;
    context->statistics.header.header_size = TACHYON_WFP_HEADER_SIZE;
    context->statistics.header.abi_major = TACHYON_WFP_ABI_MAJOR;
    context->statistics.header.abi_minor = TACHYON_WFP_ABI_MINOR;
    context->statistics.header.kind = TachyonWfpMessageStatistics;
    context->statistics.header.total_size = TACHYON_WFP_STATISTICS_SIZE;
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
    UNREFERENCED_PARAMETER(file_object);
    if (InterlockedCompareExchange(&context->client_open, 1, 0) != 0) {
        WdfRequestComplete(request, STATUS_DEVICE_BUSY);
        return;
    }
    WdfRequestComplete(request, STATUS_SUCCESS);
}

VOID TgEvtFileCleanup(_In_ WDFFILEOBJECT file_object)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext(WdfFileObjectGetDevice(file_object));
    TgFlushAll(context, TRUE);
    InterlockedExchange(&context->client_open, 0);
}

VOID TgEvtIoDeviceControl(_In_ WDFQUEUE queue, _In_ WDFREQUEST request, _In_ SIZE_T output_size,
                          _In_ SIZE_T input_size, _In_ ULONG ioctl)
{
    TG_DEVICE_CONTEXT* context = TgGetDeviceContext(WdfIoQueueGetDevice(queue));
    VOID* input = NULL;
    NTSTATUS status;

    switch (ioctl) {
    case IOCTL_TACHYON_WFP_NEGOTIATE:
        status = TgNegotiate(context, request, input_size, output_size);
        break;
    case IOCTL_TACHYON_WFP_SET_POLICY:
    case IOCTL_TACHYON_WFP_DISABLE_POLICY:
    case IOCTL_TACHYON_WFP_VERDICT:
        status = WdfRequestRetrieveInputBuffer(request, TACHYON_WFP_HEADER_SIZE, &input, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        if (ioctl == IOCTL_TACHYON_WFP_SET_POLICY) {
            status = TgSetPolicy(context, input, input_size);
        } else if (ioctl == IOCTL_TACHYON_WFP_DISABLE_POLICY) {
            status = TgDisablePolicy(context, input, input_size);
        } else {
            status = TgApplyVerdict(context, input, input_size);
        }
        break;
    case IOCTL_TACHYON_WFP_DEQUEUE:
        status = TgCopyNextCapture(context, request, output_size);
        if (status == STATUS_PENDING) {
            return;
        }
        break;
    case IOCTL_TACHYON_WFP_STATISTICS:
        status = TgReadStatistics(context, request, output_size);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    WdfRequestComplete(request, status);
}

static NTSTATUS TgNegotiate(TG_DEVICE_CONTEXT* context, WDFREQUEST request, SIZE_T input_size, SIZE_T output_size)
{
    TACHYON_WFP_NEGOTIATE_REQUEST* input;
    TACHYON_WFP_NEGOTIATE_RESPONSE* output;
    NTSTATUS status;
    static const UCHAR build_id[16] = {0x4f,0xbb,0x3a,0xa7,0x69,0x1d,0x41,0x02,0xa5,0x52,0x17,0x84,0x64,0x20,0x00,0x02};
    static const UCHAR service_sid_hash[32] = {0x12,0xed,0x2d,0xe9,0xb9,0xc9,0xfa,0xe9,0x9c,0xd7,0xcd,0xb3,0xd5,0x57,0x8a,0x60,0xa8,0xf1,0xef,0xbc,0xa3,0xe5,0xcb,0x99,0xc9,0x21,0x48,0x17,0xc0,0xeb,0x27,0xdc};

    if (input_size != TACHYON_WFP_NEGOTIATE_REQUEST_SIZE || output_size < TACHYON_WFP_NEGOTIATE_RESPONSE_SIZE) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    status = WdfRequestRetrieveInputBuffer(request, sizeof(*input), (VOID**)&input, NULL);
    if (!NT_SUCCESS(status) || !TgValidateHeader(&input->header, input_size, TachyonWfpMessageNegotiateRequest)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (input->required_capabilities != TACHYON_WFP_REQUIRED_CAPABILITIES ||
        input->requested_queue_capacity == 0 || input->requested_queue_capacity > TACHYON_WFP_DEFAULT_QUEUE_CAPACITY ||
        input->requested_timeout_ms < 25 || input->requested_timeout_ms > 1000) {
        return STATUS_REVISION_MISMATCH;
    }
    status = WdfRequestRetrieveOutputBuffer(request, sizeof(*output), (VOID**)&output, NULL);
    if (!NT_SUCCESS(status)) {
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
    context->queue_capacity = input->requested_queue_capacity;
    context->verdict_timeout_ms = input->requested_timeout_ms;
    WdfSpinLockRelease(context->lock);
    WdfRequestSetInformation(request, sizeof(*output));
    WdfTimerStart(context->timer, WDF_REL_TIMEOUT_IN_MS(TG_TIMER_PERIOD_MS));
    return STATUS_SUCCESS;
}

static NTSTATUS TgReadStatistics(TG_DEVICE_CONTEXT* context, WDFREQUEST request, SIZE_T output_size)
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
    context->statistics.queue_depth = context->queue_depth;
    context->statistics.pending_verdicts = context->pending_count;
    context->statistics.header.request_id = ++context->next_request_id;
    RtlCopyMemory(output, &context->statistics, sizeof(*output));
    WdfSpinLockRelease(context->lock);
    WdfRequestSetInformation(request, sizeof(*output));
    return STATUS_SUCCESS;
}

BOOLEAN TgValidateHeader(const TACHYON_WFP_MESSAGE_HEADER* header, SIZE_T actual, UINT16 kind)
{
    return header != NULL && actual >= TACHYON_WFP_HEADER_SIZE && actual <= TACHYON_WFP_MAX_MESSAGE_SIZE &&
           header->magic == TACHYON_WFP_ABI_MAGIC && header->header_size == TACHYON_WFP_HEADER_SIZE &&
           header->abi_major == TACHYON_WFP_ABI_MAJOR && header->abi_minor <= TACHYON_WFP_ABI_MINOR &&
           header->kind == kind && header->total_size == actual && header->request_id != 0 && header->reserved == 0;
}

UINT64 TgNow100ns(VOID)
{
    LARGE_INTEGER value;
    KeQuerySystemTimePrecise(&value);
    return (UINT64)value.QuadPart;
}
