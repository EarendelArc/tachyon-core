package helper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readWFPDriverSource(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "drivers", "windows", "wfp", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func cFunctionBody(t *testing.T, source, signature string) string {
	t.Helper()
	start := 0
	for {
		relative := strings.Index(source[start:], signature)
		if relative < 0 {
			t.Fatalf("missing C function definition %q", signature)
		}
		start += relative
		open := strings.Index(source[start:], "{")
		semicolon := strings.Index(source[start:], ";")
		if open >= 0 && (semicolon < 0 || open < semicolon) {
			break
		}
		start += len(signature)
	}
	open := strings.Index(source[start:], "{")
	open += start
	depth := 0
	for index := open; index < len(source); index++ {
		switch source[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[open : index+1]
			}
		}
	}
	t.Fatalf("unterminated body for C function %q", signature)
	return ""
}

func TestWFPClassifyChecksActionWriteBeforeAnyDecisionWrite(t *testing.T) {
	source := readWFPDriverSource(t, filepath.Join("src", "wfp.c"))
	for _, signature := range []string{"static VOID TgClassifyFlow(", "static VOID TgClassifyDatagram("} {
		body := cFunctionBody(t, source, signature)
		rights := strings.Index(body, "FWPS_RIGHT_ACTION_WRITE")
		firstWrite := strings.Index(body, "classify_out->actionType")
		if rights < 0 || firstWrite < 0 || rights > firstWrite {
			t.Fatalf("%s writes a decision before checking FWPS_RIGHT_ACTION_WRITE", signature)
		}
		if !strings.Contains(body[:firstWrite], "goto Exit") {
			t.Fatalf("%s does not preserve the upstream decision when write rights are absent", signature)
		}
	}
}

func TestWFPUnloadRetainsResourcesUntilEveryCalloutIsAbsent(t *testing.T) {
	wfp := readWFPDriverSource(t, filepath.Join("src", "wfp.c"))
	driver := readWFPDriverSource(t, filepath.Join("src", "driver.c"))
	stop := cFunctionBody(t, wfp, "NTSTATUS TgWfpStop(")
	lastUnregister := strings.LastIndex(stop, "TgUnregisterCalloutBlocking")
	firstDestroy := strings.Index(stop, "FwpsInjectionHandleDestroy0")
	if lastUnregister < 0 || firstDestroy < 0 || lastUnregister > firstDestroy {
		t.Fatal("WFP resources can be destroyed before all callouts are unregistered")
	}
	for _, required := range []string{"STATUS_DEVICE_BUSY", "STATUS_FWP_IN_USE", "TG_STOP_RETRY_COUNT", "STATUS_FWP_CALLOUT_NOT_FOUND"} {
		if !strings.Contains(wfp, required) {
			t.Fatalf("callout unregister contract missing %q", required)
		}
	}
	if !strings.Contains(driver, "TgFailStopUnload(status)") || strings.Contains(driver, "NT_ASSERT(NT_SUCCESS(status))") {
		t.Fatal("Release unload path does not fail-stop after unsafe teardown failure")
	}
	if !strings.Contains(wfp, "status == STATUS_PENDING") || !strings.Contains(wfp, "TgWaitForDrain(&context->flows_drained)") ||
		strings.Contains(wfp, "KeWaitForSingleObject(&context->flows_drained, Executive, KernelMode, FALSE, NULL)") {
		t.Fatal("flow removal does not preserve asynchronous ownership with a bounded drain")
	}
}

func TestWFPHandleNegotiationAndTimerAreOrderIndependent(t *testing.T) {
	header := readWFPDriverSource(t, filepath.Join("src", "tachyon_wfp.h"))
	device := readWFPDriverSource(t, filepath.Join("src", "device.c"))
	driver := readWFPDriverSource(t, filepath.Join("src", "driver.c"))
	for _, required := range []string{"TG_FILE_CONTEXT", "TgGetFileContext", "TgIoctlRequiresNegotiation", "TgRequestIsNegotiated",
		"IOCTL_TACHYON_WFP_SET_POLICY", "IOCTL_TACHYON_WFP_DEQUEUE", "IOCTL_TACHYON_WFP_VERDICT"} {
		if !strings.Contains(header+device, required) {
			t.Fatalf("per-handle negotiation contract missing %q", required)
		}
	}
	if strings.Contains(cFunctionBody(t, device, "static NTSTATUS TgNegotiate("), "WdfTimerStart") ||
		!strings.Contains(driver, "WdfTimerStart") {
		t.Fatal("timeout timer lifetime still depends on negotiation IOCTL ordering")
	}
}

func TestWFPWireAndRawInjectionContracts(t *testing.T) {
	wfp := readWFPDriverSource(t, filepath.Join("src", "wfp.c"))
	device := readWFPDriverSource(t, filepath.Join("src", "device.c"))
	for _, required := range []string{"RtlUlongByteSwap", "FWPS_METADATA_FIELD_IP_HEADER_SIZE", "NdisRetreatNetBufferDataStart",
		"packet->raw_send ? NULL : &packet->send_params", "KeQueryInterruptTimePrecise"} {
		if !strings.Contains(wfp+device, required) {
			t.Fatalf("wire/raw/clock contract missing %q", required)
		}
	}
	if strings.Contains(device, "KeQuerySystemTime") {
		t.Fatal("verdict deadlines use adjustable wall clock time")
	}
}

func TestWFPPolicyReplacementAndIdentitySemanticsAreExplicit(t *testing.T) {
	queue := readWFPDriverSource(t, filepath.Join("src", "queue.c"))
	wfp := readWFPDriverSource(t, filepath.Join("src", "wfp.c"))
	abi := readWFPDriverSource(t, filepath.Join("include", "tachyon_wfp_abi.h"))
	if !strings.Contains(queue, "TgFlushGeneration(context, previous->generation, TRUE)") {
		t.Fatal("policy replacement does not fail open pending packets from the old generation")
	}
	for _, required := range []string{"TACHYON_WFP_ABI_MAJOR 2u", "TACHYON_WFP_ABI_MINOR 0u",
		"TACHYON_WFP_CAP_USER_SECURITY_DESCRIPTOR", "user_security_descriptor_hash",
		"self-relative security descriptor bytes"} {
		if !strings.Contains(abi, required) {
			t.Fatalf("ABI identity semantics missing %q", required)
		}
	}
	if strings.Contains(abi, "USER_SID") || strings.Contains(abi, "user_sid_hash") {
		t.Fatal("ABI still labels a security descriptor hash as a SID hash")
	}
	if !strings.Contains(wfp, "value.type != FWP_SECURITY_DESCRIPTOR_TYPE") ||
		!strings.Contains(wfp, "value.sd") ||
		strings.Contains(wfp, "incomingValue[user_index].value.byteBlob") {
		t.Fatal("ALE_USER_ID must use the FWP_SECURITY_DESCRIPTOR_TYPE sd union member")
	}
}
