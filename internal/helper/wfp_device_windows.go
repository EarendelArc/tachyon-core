//go:build windows

package helper

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsWFPTransport struct {
	mu     sync.RWMutex
	handle windows.Handle
	closed bool
}

func NewPlatformCaptureDevice() CaptureDevice {
	transport, err := openWindowsWFPTransport()
	if err != nil {
		return failedCaptureDevice{reason: fmt.Sprintf("open verified WFP device: %v", err)}
	}
	provider, err := newWFPDeviceProvider(transport)
	if err != nil {
		return failedCaptureDevice{reason: err.Error()}
	}
	return provider
}

func openWindowsWFPTransport() (*windowsWFPTransport, error) {
	path, err := windows.UTF16PtrFromString(`\\.\TachyonWFP`)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	return &windowsWFPTransport{handle: handle}, nil
}

func (transport *windowsWFPTransport) Negotiate(ctx context.Context, input []byte) ([]byte, error) {
	output := make([]byte, wfpNegotiateResponseSize)
	n, err := transport.control(ctx, ioctlWFPNegotiate, input, output)
	if err != nil {
		clear(output)
		return nil, err
	}
	return output[:n], nil
}

func (transport *windowsWFPTransport) SetPolicy(ctx context.Context, input []byte) error {
	_, err := transport.control(ctx, ioctlWFPSetPolicy, input, nil)
	return err
}

func (transport *windowsWFPTransport) DisablePolicy(ctx context.Context, input []byte) error {
	_, err := transport.control(ctx, ioctlWFPDisablePolicy, input, nil)
	return err
}

func (transport *windowsWFPTransport) ReadCapture(ctx context.Context, output []byte) (int, error) {
	return transport.control(ctx, ioctlWFPDequeue, nil, output)
}

func (transport *windowsWFPTransport) WriteVerdict(ctx context.Context, input []byte) error {
	_, err := transport.control(ctx, ioctlWFPVerdict, input, nil)
	return err
}

func (transport *windowsWFPTransport) control(ctx context.Context, code uint32, input, output []byte) (int, error) {
	transport.mu.RLock()
	if transport.closed {
		transport.mu.RUnlock()
		return 0, windows.ERROR_INVALID_HANDLE
	}
	handle := transport.handle
	transport.mu.RUnlock()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := windows.Overlapped{HEvent: event}
	var inPtr, outPtr *byte
	if len(input) != 0 {
		inPtr = &input[0]
	}
	if len(output) != 0 {
		outPtr = &output[0]
	}
	var transferred uint32
	err = windows.DeviceIoControl(handle, code, inPtr, uint32(len(input)), outPtr, uint32(len(output)), &transferred, &overlapped)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	for {
		select {
		case <-ctx.Done():
			_ = windows.CancelIoEx(handle, &overlapped)
			_, _ = windows.WaitForSingleObject(event, windows.INFINITE)
			return 0, ctx.Err()
		default:
		}
		result, waitErr := windows.WaitForSingleObject(event, 25)
		if waitErr != nil {
			return 0, waitErr
		}
		if result == windows.WAIT_OBJECT_0 {
			break
		}
		if result != uint32(windows.WAIT_TIMEOUT) {
			return 0, fmt.Errorf("wait WFP IOCTL: result=%d", result)
		}
	}
	if err := windows.GetOverlappedResult(handle, &overlapped, &transferred, false); err != nil {
		return 0, err
	}
	runtime.KeepAlive(input)
	runtime.KeepAlive(output)
	runtime.KeepAlive(unsafe.Pointer(inPtr))
	return int(transferred), nil
}

func (transport *windowsWFPTransport) Cancel() error {
	transport.mu.RLock()
	defer transport.mu.RUnlock()
	if transport.closed {
		return nil
	}
	err := windows.CancelIoEx(transport.handle, nil)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil
	}
	return err
}

func (transport *windowsWFPTransport) Close() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed {
		return nil
	}
	transport.closed = true
	_ = windows.CancelIoEx(transport.handle, nil)
	return windows.CloseHandle(transport.handle)
}
