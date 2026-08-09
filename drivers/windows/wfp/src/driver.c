// SPDX-License-Identifier: Apache-2.0
#include "tachyon_wfp.h"

WDFDEVICE TgControlDevice = NULL;

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
    status = TgWfpStart(TgGetDeviceContext(device));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    TgControlDevice = device;
    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

VOID TgEvtDriverUnload(_In_ WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);
    if (TgControlDevice != NULL) {
        TgWfpStop(TgGetDeviceContext(TgControlDevice));
        TgControlDevice = NULL;
    }
}
