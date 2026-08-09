//go:build !windows

package helper

func NewPlatformCaptureDevice() CaptureDevice {
	return failedCaptureDevice{reason: "the WFP capture device is available only on Windows"}
}
