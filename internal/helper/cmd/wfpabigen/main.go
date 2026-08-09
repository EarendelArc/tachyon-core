package main

import (
	"crypto/sha256"
	"fmt"
	"go/format"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var numericSuffix = regexp.MustCompile(`(?i)(0x[0-9a-f]+|[0-9]+)u?`)

func main() {
	if len(os.Args) != 3 {
		panic("usage: wfpabigen <tachyon_wfp_abi.h> <output.go>")
	}
	source, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	header := string(source)
	number := func(name string) uint64 { return parseNumericDefine(header, name) }
	capabilities := parseCapabilities(header)
	required := parseRequiredCapabilities(header, capabilities)
	messages := parseEnum(header, "TACHYON_WFP_MESSAGE_KIND")
	verdicts := parseEnum(header, "TACHYON_WFP_VERDICT_ACTION")
	ioctls := parseIOCTLs(header)
	buildID := parseByteInitializer(header, "TACHYON_WFP_DRIVER_BUILD_ID_INIT", 16)
	helperBuildID := parseByteInitializer(header, "TACHYON_WFP_HELPER_BUILD_ID_INIT", 16)
	serviceSID := parseStringDefine(header, "TACHYON_WFP_HELPER_SERVICE_SID_ASCII")
	serviceHash := sha256.Sum256([]byte(serviceSID))
	declaredHash := parseByteInitializer(header, "TACHYON_WFP_HELPER_SERVICE_SID_SHA256_INIT", 32)
	if string(serviceHash[:]) != string(declaredHash) {
		panic("Service SID SHA-256 initializer does not match canonical UTF-8 SID")
	}

	var output strings.Builder
	output.WriteString("// Code generated from drivers/windows/wfp/include/tachyon_wfp_abi.h by wfpabigen; DO NOT EDIT.\n\npackage helper\n\nconst (\n")
	fprintf(&output, "\twfpDeviceMagic uint32 = %#x\n", number("TACHYON_WFP_ABI_MAGIC"))
	fprintf(&output, "\twfpDeviceABIMajor uint16 = %d\n", number("TACHYON_WFP_ABI_MAJOR"))
	fprintf(&output, "\twfpDeviceABIMinor uint16 = %d\n", number("TACHYON_WFP_ABI_MINOR"))
	for _, item := range []struct{ goName, cName string }{
		{"wfpMaxMessageSize", "TACHYON_WFP_MAX_MESSAGE_SIZE"},
		{"wfpDeviceHeaderSize", "TACHYON_WFP_HEADER_SIZE"},
		{"wfpNegotiateRequestSize", "TACHYON_WFP_NEGOTIATE_REQUEST_SIZE"},
		{"wfpNegotiateResponseSize", "TACHYON_WFP_NEGOTIATE_RESPONSE_SIZE"},
		{"wfpPolicyHeaderSize", "TACHYON_WFP_POLICY_HEADER_SIZE"},
		{"wfpPolicyEntrySize", "TACHYON_WFP_POLICY_ENTRY_SIZE"},
		{"wfpDisablePolicySize", "TACHYON_WFP_DISABLE_POLICY_SIZE"},
		{"wfpCaptureHeaderSize", "TACHYON_WFP_CAPTURE_HEADER_SIZE"},
		{"wfpVerdictHeaderSize", "TACHYON_WFP_VERDICT_HEADER_SIZE"},
		{"wfpStatisticsSize", "TACHYON_WFP_STATISTICS_SIZE"},
		{"wfpDefaultQueueCapacity", "TACHYON_WFP_DEFAULT_QUEUE_CAPACITY"},
		{"wfpDefaultResidentBytes", "TACHYON_WFP_DEFAULT_RESIDENT_BYTES"},
		{"wfpDefaultVerdictMS", "TACHYON_WFP_DEFAULT_VERDICT_TIMEOUT_MS"},
	} {
		fprintf(&output, "\t%s = %d\n", item.goName, number(item.cName))
	}
	output.WriteString("\n")
	messageNames := map[string]string{
		"TachyonWfpMessageNegotiateRequest": "wfpMessageNegotiateRequest", "TachyonWfpMessageNegotiateResponse": "wfpMessageNegotiateResponse",
		"TachyonWfpMessagePolicy": "wfpMessagePolicy", "TachyonWfpMessageDisablePolicy": "wfpMessageDisablePolicy",
		"TachyonWfpMessageCapture": "wfpMessageCapture", "TachyonWfpMessageVerdict": "wfpMessageVerdict", "TachyonWfpMessageStatistics": "wfpMessageStatistics",
	}
	writeMapped(&output, messages, messageNames, "uint16")
	output.WriteString("\n")
	verdictNames := map[string]string{
		"TachyonWfpVerdictTunnel": "wfpVerdictTunnel", "TachyonWfpVerdictPermitDirect": "wfpVerdictPermitDirect", "TachyonWfpVerdictDrop": "wfpVerdictDrop",
	}
	writeMapped(&output, verdicts, verdictNames, "uint32")
	output.WriteString("\n")
	capNames := map[string]string{
		"TACHYON_WFP_CAP_FLOW_V4": "wfpCapFlowV4", "TACHYON_WFP_CAP_FLOW_V6": "wfpCapFlowV6",
		"TACHYON_WFP_CAP_DATAGRAM_V4": "wfpCapDatagramV4", "TACHYON_WFP_CAP_DATAGRAM_V6": "wfpCapDatagramV6",
		"TACHYON_WFP_CAP_PROCESS_IDENTITY": "wfpCapProcessIdentity", "TACHYON_WFP_CAP_USER_SID": "wfpCapUserSID",
		"TACHYON_WFP_CAP_APP_ID": "wfpCapAppID", "TACHYON_WFP_CAP_INJECT_SEND": "wfpCapInjectSend",
		"TACHYON_WFP_CAP_INJECTION_STATE": "wfpCapInjectionState", "TACHYON_WFP_CAP_BOUNDED_QUEUE": "wfpCapBoundedQueue",
		"TACHYON_WFP_CAP_FAIL_OPEN_TIMEOUT": "wfpCapFailOpenTimeout", "TACHYON_WFP_CAP_POLICY_GENERATION": "wfpCapPolicyGeneration",
	}
	writeMapped(&output, capabilities, capNames, "uint64")
	fprintf(&output, "\twfpRequiredCapabilities uint64 = %#x\n", required)
	output.WriteString("\n")
	ioctlNames := map[string]string{
		"IOCTL_TACHYON_WFP_NEGOTIATE": "ioctlWFPNegotiate", "IOCTL_TACHYON_WFP_SET_POLICY": "ioctlWFPSetPolicy",
		"IOCTL_TACHYON_WFP_DISABLE_POLICY": "ioctlWFPDisablePolicy", "IOCTL_TACHYON_WFP_DEQUEUE": "ioctlWFPDequeue",
		"IOCTL_TACHYON_WFP_VERDICT": "ioctlWFPVerdict", "IOCTL_TACHYON_WFP_STATISTICS": "ioctlWFPStatistics",
	}
	writeMapped(&output, ioctls, ioctlNames, "uint32")
	output.WriteString(")\n\n")
	fprintf(&output, "const wfpHelperServiceSID = %q\n\n", serviceSID)
	fprintf(&output, "var wfpDriverBuildID = %s\n", byteArrayLiteral(buildID))
	fprintf(&output, "var wfpHelperBuildID = %s\n", byteArrayLiteral(helperBuildID))
	fprintf(&output, "var wfpHelperServiceSIDHash = %s\n", byteArrayLiteral(serviceHash[:]))

	formatted, err := format.Source([]byte(output.String()))
	if err != nil {
		panic(fmt.Errorf("format generated ABI: %w", err))
	}
	if err := os.WriteFile(os.Args[2], formatted, 0o644); err != nil {
		panic(err)
	}
}

func fprintf(builder *strings.Builder, format string, values ...any) {
	_, _ = fmt.Fprintf(builder, format, values...)
}

func parseNumericDefine(header, name string) uint64 {
	re := regexp.MustCompile(`(?m)^#define\s+` + regexp.QuoteMeta(name) + `\s+([^\r\n]+)`)
	match := re.FindStringSubmatch(header)
	if match == nil {
		panic("missing numeric define " + name)
	}
	values := numericSuffix.FindAllStringSubmatch(match[1], -1)
	if len(values) == 0 {
		panic("numeric define has no value: " + name)
	}
	result := parseUint(values[0][1])
	if strings.Contains(match[1], "*") {
		for _, value := range values[1:] {
			result *= parseUint(value[1])
		}
	}
	return result
}

func parseCapabilities(header string) map[string]uint64 {
	re := regexp.MustCompile(`(?m)^#define\s+(TACHYON_WFP_CAP_[A-Z0-9_]+)\s+\(UINT64_C\(1\)\s*<<\s*([0-9]+)\)`)
	result := map[string]uint64{}
	for _, match := range re.FindAllStringSubmatch(header, -1) {
		result[match[1]] = uint64(1) << parseUint(match[2])
	}
	return result
}

func parseRequiredCapabilities(header string, capabilities map[string]uint64) uint64 {
	start := strings.Index(header, "#define TACHYON_WFP_REQUIRED_CAPABILITIES")
	if start < 0 {
		panic("missing required capability expression")
	}
	end := strings.Index(header[start:], "\n\nenum ")
	if end < 0 {
		panic("missing required capability expression")
	}
	block := header[start : start+end]
	var required uint64
	for name, value := range capabilities {
		if strings.Contains(block, name) {
			required |= value
		}
	}
	return required
}

func parseEnum(header, name string) map[string]uint64 {
	re := regexp.MustCompile(`(?s)enum\s+` + regexp.QuoteMeta(name) + `\s*\{(.*?)\};`)
	match := re.FindStringSubmatch(header)
	if match == nil {
		panic("missing enum " + name)
	}
	result := map[string]uint64{}
	var current uint64
	for _, raw := range strings.Split(match[1], ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			current = parseUint(strings.TrimSpace(parts[1]))
		}
		result[strings.TrimSpace(parts[0])] = current
		current++
	}
	return result
}

func parseIOCTLs(header string) map[string]uint64 {
	re := regexp.MustCompile(`(?m)^#define\s+(IOCTL_TACHYON_WFP_[A-Z_]+)\s+\\\r?\n\s*CTL_CODE\(FILE_DEVICE_NETWORK,\s*(0x[0-9A-Fa-f]+),\s*(METHOD_[A-Z_]+),\s*([^\)]+)\)`)
	methods := map[string]uint64{"METHOD_BUFFERED": 0, "METHOD_IN_DIRECT": 1, "METHOD_OUT_DIRECT": 2}
	result := map[string]uint64{}
	for _, match := range re.FindAllStringSubmatch(header, -1) {
		access := uint64(0)
		if strings.Contains(match[4], "FILE_READ_DATA") {
			access |= 1
		}
		if strings.Contains(match[4], "FILE_WRITE_DATA") {
			access |= 2
		}
		result[match[1]] = (0x12 << 16) | (access << 14) | (parseUint(match[2]) << 2) | methods[match[3]]
	}
	return result
}

func parseByteInitializer(header, name string, length int) []byte {
	re := regexp.MustCompile(`(?s)#define\s+` + regexp.QuoteMeta(name) + `\s+\\?\s*\{(.*?)\}`)
	match := re.FindStringSubmatch(header)
	if match == nil {
		panic("missing initializer " + name)
	}
	values := regexp.MustCompile(`0x[0-9A-Fa-f]{2}`).FindAllString(match[1], -1)
	if len(values) != length {
		panic(fmt.Sprintf("%s has %d bytes, want %d", name, len(values), length))
	}
	result := make([]byte, length)
	for index, value := range values {
		result[index] = byte(parseUint(value))
	}
	return result
}

func parseStringDefine(header, name string) string {
	re := regexp.MustCompile(`(?s)#define\s+` + regexp.QuoteMeta(name) + `\s+\\?\s*"([^"]+)"`)
	match := re.FindStringSubmatch(header)
	if match == nil {
		panic("missing string define " + name)
	}
	return match[1]
}

func writeMapped(output *strings.Builder, values map[string]uint64, names map[string]string, goType string) {
	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			panic("canonical header is missing " + key)
		}
		fprintf(output, "\t%s %s = %#x\n", names[key], goType, value)
	}
}

func parseUint(value string) uint64 {
	value = strings.TrimSpace(strings.TrimSuffix(value, "u"))
	parsed, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		panic(err)
	}
	return parsed
}

func byteArrayLiteral(value []byte) string {
	parts := make([]string, len(value))
	for index, item := range value {
		parts[index] = fmt.Sprintf("0x%02x", item)
	}
	return fmt.Sprintf("[%d]byte{%s}", len(value), strings.Join(parts, ", "))
}
