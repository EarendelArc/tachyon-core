// Code generated from drivers/windows/wfp/include/tachyon_wfp_abi.h by wfpabigen; DO NOT EDIT.

package helper

const (
	wfpDeviceMagic           uint32 = 0x46574754
	wfpDeviceABIMajor        uint16 = 2
	wfpDeviceABIMinor        uint16 = 0
	wfpMaxMessageSize               = 65536
	wfpDeviceHeaderSize             = 32
	wfpNegotiateRequestSize         = 64
	wfpNegotiateResponseSize        = 104
	wfpPolicyHeaderSize             = 64
	wfpPolicyEntrySize              = 88
	wfpDisablePolicySize            = 64
	wfpCaptureHeaderSize            = 224
	wfpVerdictHeaderSize            = 96
	wfpStatisticsSize               = 104
	wfpDefaultQueueCapacity         = 512
	wfpDefaultResidentBytes         = 8388608
	wfpDefaultVerdictMS             = 250

	wfpMessageCapture           uint16 = 0x5
	wfpMessageDisablePolicy     uint16 = 0x4
	wfpMessageNegotiateRequest  uint16 = 0x1
	wfpMessageNegotiateResponse uint16 = 0x2
	wfpMessagePolicy            uint16 = 0x3
	wfpMessageStatistics        uint16 = 0x7
	wfpMessageVerdict           uint16 = 0x6

	wfpVerdictDrop         uint32 = 0x3
	wfpVerdictPermitDirect uint32 = 0x2
	wfpVerdictTunnel       uint32 = 0x1

	wfpCapAppID                  uint64 = 0x40
	wfpCapBoundedQueue           uint64 = 0x200
	wfpCapDatagramV4             uint64 = 0x4
	wfpCapDatagramV6             uint64 = 0x8
	wfpCapFailOpenTimeout        uint64 = 0x400
	wfpCapFlowV4                 uint64 = 0x1
	wfpCapFlowV6                 uint64 = 0x2
	wfpCapInjectionState         uint64 = 0x100
	wfpCapInjectSend             uint64 = 0x80
	wfpCapPolicyGeneration       uint64 = 0x800
	wfpCapProcessIdentity        uint64 = 0x10
	wfpCapUserSecurityDescriptor uint64 = 0x20
	wfpRequiredCapabilities      uint64 = 0xfff

	ioctlWFPDequeue       uint32 = 0x12640e
	ioctlWFPDisablePolicy uint32 = 0x12a408
	ioctlWFPNegotiate     uint32 = 0x12e400
	ioctlWFPSetPolicy     uint32 = 0x12a405
	ioctlWFPStatistics    uint32 = 0x126414
	ioctlWFPVerdict       uint32 = 0x12a411
)

const wfpHelperServiceSID = "S-1-5-80-1356003462-1404488631-2219046169-124586702-828318184"

var wfpDriverBuildID = [16]byte{0x4f, 0xbb, 0x3a, 0xa7, 0x69, 0x1d, 0x41, 0x02, 0xa5, 0x52, 0x17, 0x84, 0x64, 0x20, 0x00, 0x02}
var wfpHelperBuildID = [16]byte{0x54, 0x47, 0x48, 0x50, 0x2d, 0x41, 0x42, 0x49, 0x2d, 0x32, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x01}
var wfpHelperServiceSIDHash = [32]byte{0xf0, 0xe1, 0x7a, 0x28, 0x5d, 0xbc, 0x50, 0xc3, 0xea, 0x98, 0xb7, 0xf1, 0x42, 0xef, 0x89, 0x30, 0x4b, 0x08, 0xcd, 0x82, 0x1f, 0x42, 0x6f, 0x89, 0x3a, 0x0b, 0x72, 0xc7, 0x24, 0xff, 0x38, 0x6a}
