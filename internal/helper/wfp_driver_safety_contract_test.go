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
	for _, required := range []string{"TG_FILE_CONTEXT", "TgGetFileContext", "TgIoctlRequiresNegotiation", "TgAcquireRequestSession",
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

func TestWFPFileCleanupRevokesAndDrainsOneSession(t *testing.T) {
	header := readWFPDriverSource(t, filepath.Join("src", "tachyon_wfp.h"))
	device := readWFPDriverSource(t, filepath.Join("src", "device.c"))
	queue := readWFPDriverSource(t, filepath.Join("src", "queue.c"))
	cleanup := cFunctionBody(t, device, "VOID TgEvtFileCleanup(")
	revoke := strings.Index(cleanup, "active_session_generation, 0")
	wait := strings.Index(cleanup, "ExWaitForRundownProtectionRelease")
	clear := strings.Index(cleanup, "TgClearPolicy")
	reopen := strings.Index(cleanup, "client_open = 0")
	if revoke < 0 || wait < 0 || clear < 0 || reopen < 0 || !(revoke < wait && wait < clear && clear < reopen) {
		t.Fatal("cleanup does not revoke, drain, clear, then admit a successor")
	}
	for _, required := range []string{"EX_RUNDOWN_REF io_rundown", "UINT64 generation", "session_file",
		"ExAcquireRundownProtection", "ExReleaseRundownProtection", "TgSessionIsActiveLocked"} {
		if !strings.Contains(header+device, required) {
			t.Fatalf("session lifetime contract missing %q", required)
		}
	}
	for _, signature := range []string{"NTSTATUS TgSetPolicy(", "NTSTATUS TgDisablePolicy(",
		"NTSTATUS TgCopyNextCapture(", "NTSTATUS TgApplyVerdict("} {
		if !strings.Contains(cFunctionBody(t, queue, signature), "TgSessionIsActiveLocked") {
			t.Fatalf("%s does not revalidate the active session at its commit point", signature)
		}
	}
	copyBody := cFunctionBody(t, queue, "NTSTATUS TgCopyNextCapture(")
	forward := strings.Index(copyBody, "WdfRequestForwardToIoQueue")
	if forward < 0 {
		t.Fatal("DEQUEUE does not forward an empty capture request")
	}
	packetEmpty := strings.LastIndex(copyBody[:forward], "if (packet == NULL)")
	if packetEmpty < 0 ||
		strings.Contains(copyBody[packetEmpty:forward], "WdfSpinLockRelease") ||
		!strings.Contains(copyBody[forward:], "WdfSpinLockRelease(context->lock)") {
		t.Fatal("DEQUEUE forward is not serialized with cleanup revocation")
	}
	dispatch := cFunctionBody(t, device, "VOID TgEvtIoDeviceControl(")
	pending := strings.Index(dispatch, "if (status == STATUS_PENDING)")
	if pending < 0 || !strings.Contains(dispatch[pending:], "TgReleaseRequestSession(&session)") {
		t.Fatal("pending DEQUEUE holds rundown across its manual-queue lifetime")
	}
	service := cFunctionBody(t, queue, "VOID TgServiceCaptureWaiter(")
	if !strings.Contains(service, "TgAcquireRequestSession(context, request, TRUE, &session)") {
		t.Fatal("a serviced pending DEQUEUE does not reacquire and revalidate its session")
	}
}

func TestWFPStatisticsAtomicsUseAlignedPrivateStorage(t *testing.T) {
	header := readWFPDriverSource(t, filepath.Join("src", "tachyon_wfp.h"))
	device := readWFPDriverSource(t, filepath.Join("src", "device.c"))
	queue := readWFPDriverSource(t, filepath.Join("src", "queue.c"))
	wfp := readWFPDriverSource(t, filepath.Join("src", "wfp.c"))
	for _, required := range []string{"DECLSPEC_ALIGN(8) TG_STATISTICS_COUNTERS", "defined(_AMD64_)",
		"defined(_ARM64_)", "_Static_assert(__alignof(TG_STATISTICS_COUNTERS) >= 8",
		"FIELD_OFFSET(TG_DEVICE_CONTEXT, statistics)"} {
		if !strings.Contains(header, required) {
			t.Fatalf("private statistics alignment contract missing %q", required)
		}
	}
	if strings.Contains(header, "TACHYON_WFP_STATISTICS statistics;") {
		t.Fatal("packed ABI statistics remain embedded as atomic storage")
	}
	allSource := device + queue + wfp
	if strings.Contains(allSource, "(volatile LONG64*)&context->statistics") ||
		strings.Contains(allSource, "InterlockedIncrement64(&output->") {
		t.Fatal("an Interlocked operation still targets packed ABI storage")
	}
	for _, required := range []string{"RtlZeroMemory(output, sizeof(*output))",
		"output->captured = (UINT64)InterlockedCompareExchange64(&context->statistics.captured"} {
		if !strings.Contains(device, required) {
			t.Fatalf("statistics snapshot contract missing %q", required)
		}
	}
	readStatistics := cFunctionBody(t, device, "static NTSTATUS TgReadStatistics(")
	validate := strings.Index(readStatistics, "TgSessionIsActiveLocked")
	write := strings.Index(readStatistics, "RtlZeroMemory(output")
	if validate < 0 || write < 0 || validate > write {
		t.Fatal("statistics output is written before the active session is revalidated")
	}
}

func TestWFPHashOutputWidthAndFlowIDTruncationAreExplicit(t *testing.T) {
	header := readWFPDriverSource(t, filepath.Join("src", "tachyon_wfp.h"))
	abi := readWFPDriverSource(t, filepath.Join("include", "tachyon_wfp_abi.h"))
	wfp := readWFPDriverSource(t, filepath.Join("src", "wfp.c"))
	for _, required := range []string{
		"#define TG_FLOW_ID_SIZE 16u",
		"#define TG_SHA256_DIGEST_SIZE 32u",
		"typedef UCHAR TG_SHA256_DIGEST[TG_SHA256_DIGEST_SIZE]",
		"_Static_assert(sizeof(TG_SHA256_DIGEST) == TG_SHA256_DIGEST_SIZE",
		"_Static_assert(sizeof(((TG_FLOW_CONTEXT*)0)->flow_id) == TG_FLOW_ID_SIZE",
		"_Static_assert(sizeof(((TG_FLOW_CONTEXT*)0)->lease_nonce) == 16u",
		"TG_SHA256_DIGEST* output",
	} {
		if !strings.Contains(header, required) {
			t.Fatalf("typed SHA-256/flow layout contract missing %q", required)
		}
	}
	for _, required := range []string{
		"sizeof(((TACHYON_WFP_CAPTURE_RECORD*)0)->flow_id) == 16u",
		"sizeof(((TACHYON_WFP_VERDICT*)0)->flow_id) == 16u",
	} {
		if !strings.Contains(abi, required) {
			t.Fatalf("packed ABI flow ID width contract missing %q", required)
		}
	}

	hashBody := cFunctionBody(t, wfp, "BOOLEAN TgHashBytes(")
	if !strings.Contains(hashBody, "RtlZeroMemory(*output, sizeof(*output))") ||
		!strings.Contains(hashBody, "*output, (ULONG)sizeof(*output)") {
		t.Fatal("TgHashBytes does not derive its 32-byte output width from the typed digest")
	}

	var calls []string
	for _, line := range strings.Split(wfp, "\n") {
		if strings.Contains(line, "TgHashBytes(") && !strings.Contains(line, "BOOLEAN TgHashBytes(") {
			calls = append(calls, strings.TrimSpace(line))
			if strings.Contains(line, "flow_id") || strings.Contains(line, "lease_nonce") {
				t.Fatalf("TgHashBytes targets a narrow or leased field directly: %s", strings.TrimSpace(line))
			}
		}
	}
	if len(calls) != 3 {
		t.Fatalf("expected to audit exactly 3 TgHashBytes calls, found %d: %v", len(calls), calls)
	}
	for _, target := range []string{"&candidate.app_id_hash", "&candidate.user_security_descriptor_hash", "&flow_digest"} {
		if !strings.Contains(strings.Join(calls, "\n"), target) {
			t.Fatalf("typed SHA-256 call target missing %q", target)
		}
	}

	classify := cFunctionBody(t, wfp, "static VOID TgClassifyFlow(")
	leaseCopy := strings.Index(classify, "RtlCopyMemory(candidate.lease_nonce, context->policy->lease_nonce, 16)")
	hash := strings.Index(classify, "TgHashBytes(context, flow_seed, sizeof(flow_seed), &flow_digest)")
	truncate := strings.Index(classify, "RtlCopyMemory(candidate.flow_id, flow_digest, sizeof(candidate.flow_id))")
	wipe := strings.Index(classify, "RtlSecureZeroMemory(flow_digest, sizeof(flow_digest))")
	if leaseCopy < 0 || hash < 0 || truncate < 0 || wipe < 0 || !(leaseCopy < hash && hash < truncate && truncate < wipe) {
		t.Fatal("flow digest truncation or lease isolation ordering is not explicit")
	}
	if strings.Count(classify, "RtlSecureZeroMemory(flow_digest, sizeof(flow_digest))") < 2 {
		t.Fatal("temporary flow digest is not securely cleared on both success and exit paths")
	}
}

func TestWFPDatagramCaptureRevalidatesSessionAndPolicyAtQueueCommit(t *testing.T) {
	header := readWFPDriverSource(t, filepath.Join("src", "tachyon_wfp.h"))
	queue := readWFPDriverSource(t, filepath.Join("src", "queue.c"))
	wfp := readWFPDriverSource(t, filepath.Join("src", "wfp.c"))
	for _, required := range []string{"TG_CAPTURE_SNAPSHOT", "session_generation", "policy_generation",
		"policy_lease_nonce", "TgCaptureSnapshot", "TgCaptureSnapshotIsActiveLocked"} {
		if !strings.Contains(header, required) {
			t.Fatalf("capture snapshot contract missing %q", required)
		}
	}
	snapshotBody := cFunctionBody(t, queue, "BOOLEAN TgCaptureSnapshot(")
	if strings.Contains(snapshotBody, "TG_POLICY*") ||
		!strings.Contains(snapshotBody, "WdfSpinLockAcquire(context->lock)") ||
		!strings.Contains(snapshotBody, "RtlCopyMemory(snapshot->policy_lease_nonce") {
		t.Fatal("capture snapshot retains a policy pointer or reads policy outside the context lock")
	}
	activeBody := cFunctionBody(t, queue, "BOOLEAN TgCaptureSnapshotIsActiveLocked(")
	for _, required := range []string{"active_session_generation", "flow->session_generation",
		"context->policy->generation", "context->policy->lease_nonce", "flow->lease_nonce"} {
		if !strings.Contains(activeBody, required) {
			t.Fatalf("final capture revalidation missing %q", required)
		}
	}
	classify := cFunctionBody(t, wfp, "static VOID TgClassifyDatagram(")
	if strings.Contains(classify, "ExAcquireRundownProtection") || strings.Contains(classify, "TG_POLICY*") {
		t.Fatal("datagram classify holds blocking rundown or a policy pointer")
	}
	initial := strings.Index(classify, "TgCaptureSnapshot(context, flow, &capture_snapshot)")
	clone := strings.Index(classify, "FwpsAllocateCloneNetBufferList0")
	insert := strings.Index(classify, "InsertTailList(&context->capture_queue")
	block := strings.Index(classify, "classify_out->actionType = FWP_ACTION_BLOCK")
	if initial < 0 || clone < 0 || insert < 0 || block < 0 || !(initial < clone && clone < insert && insert < block) {
		t.Fatal("capture snapshot, clone, queue, and BLOCK ordering is not explicit")
	}
	finalLock := strings.LastIndex(classify[:insert], "WdfSpinLockAcquire(context->lock)")
	revalidate := strings.LastIndex(classify[:insert], "TgCaptureSnapshotIsActiveLocked")
	if finalLock < 0 || revalidate < 0 || !(finalLock < revalidate && revalidate < insert) {
		t.Fatal("queue insertion is not linearized after final snapshot revalidation")
	}
	transfer := strings.Index(classify[insert:], "packet = NULL; /* pending/queue lists now own the base reference */")
	if transfer < 0 {
		t.Fatal("packet ownership is not transferred before classify leaves the commit lock")
	}
	transfer += insert
	unlock := strings.Index(classify[transfer:], "WdfSpinLockRelease(context->lock)")
	if unlock >= 0 {
		unlock += transfer
	}
	if unlock < 0 || !(transfer < unlock && unlock < block) {
		t.Fatal("packet ownership transfer is not ordered before unlock and BLOCK")
	}
	for _, required := range []string{"packet->record->generation = capture_snapshot.policy_generation",
		"capture_snapshot.policy_lease_nonce"} {
		if !strings.Contains(classify, required) {
			t.Fatalf("capture record does not use the validated snapshot: missing %q", required)
		}
	}
}

func TestWFPWireAndRawInjectionContracts(t *testing.T) {
	header := readWFPDriverSource(t, filepath.Join("src", "tachyon_wfp.h"))
	wfp := readWFPDriverSource(t, filepath.Join("src", "wfp.c"))
	queue := readWFPDriverSource(t, filepath.Join("src", "queue.c"))
	device := readWFPDriverSource(t, filepath.Join("src", "device.c"))
	for _, required := range []string{"RtlUlongByteSwap", "FWPS_METADATA_FIELD_IP_HEADER_SIZE", "NdisRetreatNetBufferDataStart",
		"packet->clone_retreat_active ? NULL : &packet->send_params", "KeQueryInterruptTimePrecise"} {
		if !strings.Contains(wfp+device, required) {
			t.Fatalf("wire/raw/clock contract missing %q", required)
		}
	}
	for _, required := range []string{"TG_MAX_CONTROL_DATA_SIZE 4096u", "SIZE_T control_data_size",
		"SIZE_T resident_bytes", "NET_BUFFER* clone_retreated_buffer", "ULONG clone_retreat_length",
		"BOOLEAN clone_retreat_active"} {
		if !strings.Contains(header, required) {
			t.Fatalf("packet retreat/resident contract missing %q", required)
		}
	}

	classify := cFunctionBody(t, wfp, "static VOID TgClassifyDatagram(")
	singleNB := strings.Index(classify, "NET_BUFFER_NEXT_NB(clone_buffer) != NULL")
	retreat := strings.Index(classify, "NdisRetreatNetBufferDataStart")
	retreatSucceeded := strings.Index(classify, "if (ndis_status != NDIS_STATUS_SUCCESS) goto Exit")
	recordState := strings.Index(classify, "packet->clone_retreated_buffer = clone_buffer")
	if singleNB < 0 || retreat < 0 || retreatSucceeded < 0 || recordState < 0 ||
		!(singleNB < retreat && retreat < retreatSucceeded && retreatSucceeded < recordState) {
		t.Fatal("raw clone does not reject multi-NB input and record state only after retreat succeeds")
	}
	for _, required := range []string{
		"RtlSizeTAdd(record_size, control_data_size, &resident_bytes)",
		"RtlSizeTAdd(context->queue_bytes, packet->resident_bytes, &queue_bytes_after)",
		"RtlSizeTAdd(context->pending_bytes, packet->resident_bytes, &pending_bytes_after)",
		"packet->record->header.total_size = (UINT32)record_size",
		"context->queue_bytes = queue_bytes_after",
		"context->pending_bytes = pending_bytes_after",
	} {
		if !strings.Contains(classify, required) {
			t.Fatalf("resident budget/wire separation missing %q", required)
		}
	}
	if strings.Contains(queue, "bytes -= packet->record_size") ||
		strings.Count(queue, "bytes -= packet->resident_bytes") != 3 {
		t.Fatal("queue or pending release accounting omits controlData resident bytes")
	}

	release := cFunctionBody(t, wfp, "static VOID TgReleasePacketClone(")
	advance := strings.Index(release, "NdisAdvanceNetBufferDataStart")
	free := strings.Index(release, "FwpsFreeCloneNetBufferList0")
	if advance < 0 || free < 0 || advance > free ||
		!strings.Contains(release, "packet->clone_retreated_buffer = NULL") ||
		!strings.Contains(release, "packet->clone_retreat_length = 0") ||
		!strings.Contains(release, "packet->clone_retreat_active = FALSE") {
		t.Fatal("clone release does not advance an active retreat exactly before free")
	}
	if strings.Count(wfp, "NdisAdvanceNetBufferDataStart(") != 1 ||
		strings.Count(wfp, "FwpsFreeCloneNetBufferList0(") != 1 {
		t.Fatal("clone advance/free bypasses the unified retreat-aware release path")
	}
	for _, signature := range []string{"static VOID NTAPI TgInjectComplete(", "static VOID TgFreePendingPacket("} {
		if !strings.Contains(cFunctionBody(t, wfp, signature), "TgReleasePacketClone(packet)") {
			t.Fatalf("%s bypasses unified clone release", signature)
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
