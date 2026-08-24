// SPDX-License-Identifier: Apache-2.0
#include "tachyon_wfp.h"

WDFDEVICE TgControlDevice = NULL;
TG_DEVICE_CONTEXT* volatile TgControlContext = NULL;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver_object, _In_ PUNICODE_STRING registry_path)
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;
    WDFDEVICE device;
    NTSTATUS status;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = TgEvtDriverUnload;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfDriverCreate(driver_object, registry_path, &attributes, &config, &driver);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = TgCreateControlDevice(driver, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    TgControlDevice = device;
    InterlockedExchangePointer((PVOID volatile*)&TgControlContext, TgGetDeviceContext(device));
    status = TgWfpStart(TgGetDeviceContext(device));
    if (!NT_SUCCESS(status)) {
        InterlockedExchangePointer((PVOID volatile*)&TgControlContext, NULL);
        ExWaitForRundownProtectionRelease(&TgGetDeviceContext(device)->callback_rundown);
        TgControlDevice = NULL;
        WdfObjectDelete(device);
        return status;
    }
    WdfTimerStart(TgGetDeviceContext(device)->timer, WDF_REL_TIMEOUT_IN_MS(TG_TIMER_PERIOD_MS));
    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

VOID TgEvtDriverUnload(_In_ WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);
    if (TgControlDevice != NULL) {
        NTSTATUS status = TgWfpStop(TgGetDeviceContext(TgControlDevice));
        if (!NT_SUCCESS(status)) {
            TgFailStopUnload(status);
        }
        TgControlDevice = NULL;
    }
}

DECLSPEC_NORETURN VOID TgFailStopUnload(NTSTATUS status)
{
    KeBugCheckEx(DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS,
                 (ULONG_PTR)TgControlDevice, (ULONG_PTR)status, 0, 0);
}
