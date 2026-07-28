//go:build windows

package capturedudp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	namedPipeClientAccess    = 0x0012019b
	namedPipeBufferSize      = NamedPipeMaxFramePayload + namedPipeFrameHeaderSize
	mandatoryLowRID          = 0x1000
	mandatoryMediumRID       = 0x2000
	mandatoryHighRID         = 0x3000
	mandatorySystemRID       = 0x4000
	overlappedPollIntervalMS = 25
)

var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
)

type windowsPipeConnection struct {
	handle    windows.Handle
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
}

// ServeNamedPipe accepts and serves one verified controller connection. The
// caller owns supervision and may call it again after a clean disconnect.
func ServeNamedPipe(ctx context.Context, registry *Registry, config NamedPipeConfig) error {
	if registry == nil {
		return fmt.Errorf("%w: nil registry", ErrNamedPipeProtocol)
	}
	config, err := config.normalized()
	if err != nil {
		return err
	}
	securityAttributes, allowedSIDs, minimumIntegrity, err := buildNamedPipeSecurity(config)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(config.Name)
	if err != nil {
		return fmt.Errorf("%w: encode pipe name: %v", ErrNamedPipeProtocol, err)
	}
	handle, err := windows.CreateNamedPipe(
		name,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1,
		namedPipeBufferSize,
		namedPipeBufferSize,
		0,
		securityAttributes,
	)
	if err != nil {
		return fmt.Errorf("create captured UDP named pipe: %w", err)
	}
	connection := &windowsPipeConnection{handle: handle}
	defer connection.Close()
	if err := connectNamedPipe(ctx, handle); err != nil {
		return err
	}
	if _, err := verifyNamedPipePeer(handle, allowedSIDs, minimumIntegrity); err != nil {
		return err
	}
	attachment, err := registry.newVerifiedTransportAttachment()
	if err != nil {
		return err
	}
	return serveNamedPipeController(ctx, registry, attachment, connection, config.OperationTimeout)
}

func buildNamedPipeSecurity(config NamedPipeConfig) (*windows.SecurityAttributes, map[string]struct{}, uint32, error) {
	minimumIntegrity := config.MinimumIntegrityRID
	if minimumIntegrity == 0 {
		minimumIntegrity = mandatoryMediumRID
	}
	mandatoryLabel, err := mandatoryLabelForRID(minimumIntegrity)
	if err != nil {
		return nil, nil, 0, err
	}
	allowed := make(map[string]struct{}, len(config.AllowedSIDs))
	var descriptor strings.Builder
	descriptor.WriteString("D:P")
	for _, configuredSID := range config.AllowedSIDs {
		sid, parseErr := windows.StringToSid(configuredSID)
		if parseErr != nil {
			return nil, nil, 0, fmt.Errorf("%w: parse allowed SID: %v", ErrNamedPipeIdentity, parseErr)
		}
		canonical := sid.String()
		if _, exists := allowed[canonical]; exists {
			return nil, nil, 0, fmt.Errorf("%w: duplicate canonical SID", ErrNamedPipeIdentity)
		}
		allowed[canonical] = struct{}{}
		descriptor.WriteString("(A;;0x0012019b;;;")
		descriptor.WriteString(canonical)
		descriptor.WriteByte(')')
	}
	descriptor.WriteString("S:(ML;;NW;;;")
	descriptor.WriteString(mandatoryLabel)
	descriptor.WriteByte(')')
	securityDescriptor, err := windows.SecurityDescriptorFromString(descriptor.String())
	if err != nil {
		return nil, nil, 0, fmt.Errorf("build captured UDP pipe ACL: %w", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
	}
	return attributes, allowed, minimumIntegrity, nil
}

func mandatoryLabelForRID(integrityRID uint32) (string, error) {
	switch {
	case integrityRID >= mandatorySystemRID:
		return "SI", nil
	case integrityRID >= mandatoryHighRID:
		return "HI", nil
	case integrityRID >= mandatoryMediumRID:
		return "ME", nil
	case integrityRID >= mandatoryLowRID:
		return "LW", nil
	default:
		return "", fmt.Errorf("%w: unsupported minimum integrity RID 0x%x", ErrNamedPipeIdentity, integrityRID)
	}
}

type namedPipePeerIdentity struct {
	SID          string
	IntegrityRID uint32
}

func verifyNamedPipePeer(handle windows.Handle, allowedSIDs map[string]struct{}, minimumIntegrity uint32) (identity namedPipePeerIdentity, resultErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := impersonateNamedPipeClient(handle); err != nil {
		return identity, fmt.Errorf("%w: impersonation failed: %v", ErrNamedPipeIdentity, err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("%w: revert impersonation: %v", ErrNamedPipeIdentity, err))
		}
	}()

	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return identity, fmt.Errorf("%w: open impersonation token: %v", ErrNamedPipeIdentity, err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return identity, fmt.Errorf("%w: read token user: %v", ErrNamedPipeIdentity, err)
	}
	identity.SID = user.User.Sid.String()
	if _, allowed := allowedSIDs[identity.SID]; !allowed {
		return identity, fmt.Errorf("%w: peer SID is not allowed", ErrNamedPipeIdentity)
	}
	identity.IntegrityRID, err = tokenIntegrityRID(token)
	if err != nil {
		return identity, fmt.Errorf("%w: read token integrity: %v", ErrNamedPipeIdentity, err)
	}
	if identity.IntegrityRID < minimumIntegrity {
		return identity, fmt.Errorf("%w: peer integrity 0x%x is below 0x%x", ErrNamedPipeIdentity, identity.IntegrityRID, minimumIntegrity)
	}
	return identity, nil
}

func impersonateNamedPipeClient(handle windows.Handle) error {
	result, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(handle))
	if result != 0 {
		return nil
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == 0 {
		return syscall.EINVAL
	}
	return callErr
}

func tokenIntegrityRID(token windows.Token) (uint32, error) {
	var required uint32
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &required)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || required == 0 {
		return 0, err
	}
	buffer := make([]byte, required)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buffer[0], required, &required); err != nil {
		return 0, err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	if label.Label.Sid == nil || label.Label.Sid.SubAuthorityCount() == 0 {
		return 0, ErrNamedPipeIdentity
	}
	return label.Label.Sid.SubAuthority(uint32(label.Label.Sid.SubAuthorityCount() - 1)), nil
}

func connectNamedPipe(ctx context.Context, handle windows.Handle) error {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("create named pipe connect event: %w", err)
	}
	defer windows.CloseHandle(event)
	overlapped := &windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(handle, overlapped)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case errors.Is(err, windows.ERROR_IO_PENDING):
		_, waitErr := waitNamedPipeOverlapped(ctx, handle, overlapped)
		return waitErr
	default:
		return fmt.Errorf("connect captured UDP named pipe: %w", err)
	}
}

func (connection *windowsPipeConnection) ReadFull(ctx context.Context, destination []byte) error {
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	for len(destination) != 0 {
		read, err := connection.read(ctx, destination)
		if err != nil {
			return err
		}
		if read == 0 {
			return io.EOF
		}
		destination = destination[read:]
	}
	return nil
}

func (connection *windowsPipeConnection) WriteFull(ctx context.Context, source []byte) error {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	for len(source) != 0 {
		written, err := connection.write(ctx, source)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		source = source[written:]
	}
	return nil
}

func (connection *windowsPipeConnection) read(ctx context.Context, destination []byte) (int, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := &windows.Overlapped{HEvent: event}
	var read uint32
	err = windows.ReadFile(connection.handle, destination, &read, overlapped)
	if err == nil {
		return int(read), nil
	}
	if isWindowsPipeEOF(err) {
		return 0, io.EOF
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	read, err = waitNamedPipeOverlapped(ctx, connection.handle, overlapped)
	if isWindowsPipeEOF(err) {
		return 0, io.EOF
	}
	return int(read), err
}

func (connection *windowsPipeConnection) write(ctx context.Context, source []byte) (int, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := &windows.Overlapped{HEvent: event}
	var written uint32
	err = windows.WriteFile(connection.handle, source, &written, overlapped)
	if err == nil {
		return int(written), nil
	}
	if isWindowsPipeEOF(err) {
		return 0, io.ErrClosedPipe
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	written, err = waitNamedPipeOverlapped(ctx, connection.handle, overlapped)
	if isWindowsPipeEOF(err) {
		return 0, io.ErrClosedPipe
	}
	return int(written), err
}

func waitNamedPipeOverlapped(ctx context.Context, handle windows.Handle, overlapped *windows.Overlapped) (uint32, error) {
	for {
		select {
		case <-ctx.Done():
			_ = windows.CancelIoEx(handle, overlapped)
			var transferred uint32
			_ = windows.GetOverlappedResult(handle, overlapped, &transferred, true)
			return 0, ctx.Err()
		default:
		}
		result, err := windows.WaitForSingleObject(overlapped.HEvent, overlappedPollIntervalMS)
		if err != nil {
			return 0, err
		}
		switch result {
		case windows.WAIT_OBJECT_0:
			var transferred uint32
			if err := windows.GetOverlappedResult(handle, overlapped, &transferred, false); err != nil {
				return 0, err
			}
			return transferred, nil
		case uint32(windows.WAIT_TIMEOUT):
			continue
		default:
			return 0, fmt.Errorf("unexpected named pipe wait result 0x%x", result)
		}
	}
}

func (connection *windowsPipeConnection) Close() error {
	var result error
	connection.closeOnce.Do(func() {
		_ = windows.CancelIoEx(connection.handle, nil)
		if err := windows.DisconnectNamedPipe(connection.handle); err != nil &&
			!errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
			result = err
		}
		result = errors.Join(result, windows.CloseHandle(connection.handle))
	})
	return result
}

func isWindowsPipeEOF(err error) bool {
	return errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED)
}

var _ namedPipeFrameIO = (*windowsPipeConnection)(nil)
