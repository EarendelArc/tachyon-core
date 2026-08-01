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

	"github.com/tachyon-space/tachyon-core/internal/tgp"
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
	server    bool
	readMu    sync.Mutex
	closeOnce sync.Once
}

type windowsNamedPipeServer struct {
	registry           *Registry
	sender             NamedPipeDatagramSender
	config             NamedPipeConfig
	securityAttributes *windows.SecurityAttributes
	allowedSIDs        map[string]struct{}
	minimumIntegrity   uint32

	mu      sync.Mutex
	active  *windowsPipeConnection
	session *namedPipeControllerSession
	running bool
	closed  bool
}

func NewNamedPipeServer(registry *Registry, config NamedPipeConfig, sender NamedPipeDatagramSender) (NamedPipeServer, error) {
	if registry == nil || sender == nil {
		return nil, fmt.Errorf("%w: nil registry or TGP sender", ErrNamedPipeProtocol)
	}
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	securityAttributes, allowedSIDs, minimumIntegrity, err := buildNamedPipeSecurity(config)
	if err != nil {
		return nil, err
	}
	if err := grantNamedPipeClientIdentityQueryAccess(config.AllowedSIDs); err != nil {
		return nil, err
	}
	server := &windowsNamedPipeServer{
		registry: registry, sender: sender, config: config, securityAttributes: securityAttributes,
		allowedSIDs: allowedSIDs, minimumIntegrity: minimumIntegrity,
	}
	connection, err := server.createConnection()
	if err != nil {
		return nil, err
	}
	server.active = connection
	return server, nil
}

func ServeNamedPipe(ctx context.Context, registry *Registry, config NamedPipeConfig, sender NamedPipeDatagramSender) error {
	server, err := NewNamedPipeServer(registry, config, sender)
	if err != nil {
		return err
	}
	defer server.Close()
	return server.Run(ctx)
}

func (server *windowsNamedPipeServer) createConnection() (*windowsPipeConnection, error) {
	name, err := windows.UTF16PtrFromString(server.config.Name)
	if err != nil {
		return nil, fmt.Errorf("%w: encode pipe name: %v", ErrNamedPipeProtocol, err)
	}
	handle, err := windows.CreateNamedPipe(
		name,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1,
		namedPipeBufferSize,
		namedPipeBufferSize,
		0,
		server.securityAttributes,
	)
	if err != nil {
		return nil, fmt.Errorf("create captured UDP named pipe: %w", err)
	}
	return &windowsPipeConnection{handle: handle, server: true}, nil
}

func (server *windowsNamedPipeServer) Run(ctx context.Context) error {
	server.mu.Lock()
	if server.closed || server.running {
		server.mu.Unlock()
		return ErrClosed
	}
	server.running = true
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		server.running = false
		server.mu.Unlock()
	}()

	for {
		server.mu.Lock()
		connection := server.active
		closed := server.closed
		server.mu.Unlock()
		if closed {
			return nil
		}
		if connection == nil {
			return ErrClosed
		}
		err := server.serveConnection(ctx, connection)
		_ = connection.Close()
		server.mu.Lock()
		if server.active == connection {
			server.active = nil
		}
		closed = server.closed
		server.mu.Unlock()
		if ctx.Err() != nil || closed {
			return nil
		}
		// Authentication, protocol, idle, EOF, and broken read/write failures
		// belong to this connection. Cleanup above is complete before a fresh
		// listener instance is created. Only listener creation is server-fatal.
		_ = err
		next, createErr := server.createConnection()
		if createErr != nil {
			return createErr
		}
		server.mu.Lock()
		if server.closed {
			server.mu.Unlock()
			_ = next.Close()
			return nil
		}
		server.active = next
		server.mu.Unlock()
	}
}

func (server *windowsNamedPipeServer) serveConnection(ctx context.Context, connection *windowsPipeConnection) error {
	if err := connectNamedPipe(ctx, connection.handle); err != nil {
		return err
	}
	if _, err := verifyNamedPipePeer(connection.handle, server.allowedSIDs, server.minimumIntegrity); err != nil {
		return err
	}
	attachment, err := server.registry.newVerifiedTransportAttachment()
	if err != nil {
		return err
	}
	session := newNamedPipeControllerSession(ctx, connection, server.sender, server.config.OperationTimeout)
	server.mu.Lock()
	if server.closed || server.active != connection {
		server.mu.Unlock()
		_ = attachment.Detach()
		return ErrClosed
	}
	server.session = session
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		if server.session == session {
			server.session = nil
		}
		server.mu.Unlock()
	}()
	return serveNamedPipeController(ctx, server.registry, attachment, connection, server.sender, session,
		server.config.OperationTimeout, server.config.IdleTimeout)
}

func (server *windowsNamedPipeServer) DeliverReply(ctx context.Context, datagram tgp.TunnelDatagram) error {
	server.mu.Lock()
	session := server.session
	closed := server.closed
	server.mu.Unlock()
	if closed || session == nil {
		return ErrControllerRevoked
	}
	return session.DeliverReply(ctx, datagram)
}

func (server *windowsNamedPipeServer) Close() error {
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return nil
	}
	server.closed = true
	connection := server.active
	server.mu.Unlock()
	if connection != nil {
		return connection.Close()
	}
	return nil
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
		if !config.AllowInsecureUserSID && !isRestrictedHelperSID(canonical) {
			return nil, nil, 0, fmt.Errorf("%w: ordinary user SID requires allow_insecure_user_sid preview mode", ErrNamedPipeIdentity)
		}
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

func isRestrictedHelperSID(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" || strings.HasPrefix(sid, "S-1-5-80-")
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

type namedPipeIdentityHooks struct {
	impersonate func(windows.Handle) error
	inspect     func(map[string]struct{}, uint32) (namedPipePeerIdentity, error)
	revert      func() error
	failStop    func(error)
}

func verifyNamedPipePeer(handle windows.Handle, allowedSIDs map[string]struct{}, minimumIntegrity uint32) (namedPipePeerIdentity, error) {
	hooks := namedPipeIdentityHooks{
		impersonate: impersonateNamedPipeClient,
		inspect:     inspectImpersonatedNamedPipePeer,
		revert:      windows.RevertToSelf,
		failStop: func(error) {
			_ = windows.TerminateProcess(windows.CurrentProcess(), 0xe001)
		},
	}
	return verifyNamedPipePeerWithHooks(handle, allowedSIDs, minimumIntegrity, hooks)
}

func verifyNamedPipePeerWithHooks(
	handle windows.Handle,
	allowedSIDs map[string]struct{},
	minimumIntegrity uint32,
	hooks namedPipeIdentityHooks,
) (namedPipePeerIdentity, error) {
	runtime.LockOSThread()
	if err := hooks.impersonate(handle); err != nil {
		runtime.UnlockOSThread()
		return namedPipePeerIdentity{}, fmt.Errorf("%w: impersonation failed: %v", ErrNamedPipeIdentity, err)
	}
	identity, inspectErr := hooks.inspect(allowedSIDs, minimumIntegrity)
	if err := hooks.revert(); err != nil {
		failStopErr := fmt.Errorf("%w: revert impersonation: %v", ErrNamedPipeIdentity, err)
		hooks.failStop(failStopErr)
		// Never return an impersonating thread to the scheduler, even if an
		// injected test fail-stop hook returns or process termination fails.
		runtime.Goexit()
	}
	runtime.UnlockOSThread()
	return identity, inspectErr
}

func inspectImpersonatedNamedPipePeer(allowedSIDs map[string]struct{}, minimumIntegrity uint32) (identity namedPipePeerIdentity, resultErr error) {
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return identity, fmt.Errorf("%w: open impersonation token: %v", ErrNamedPipeIdentity, err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return identity, fmt.Errorf("%w: read token user: %v", ErrNamedPipeIdentity, err)
	}
	userSID := user.User.Sid.String()
	identity.SID = userSID
	_, userAllowed := allowedSIDs[userSID]
	matchedSID := ""
	if userAllowed && !strings.HasPrefix(userSID, "S-1-5-80-") {
		matchedSID = userSID
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return identity, fmt.Errorf("%w: read token groups: %v", ErrNamedPipeIdentity, err)
	}
	if matchedSID == "" {
		matchedSID = matchRestrictedHelperGroup(allowedSIDs, groups.AllGroups(), true)
	}
	if matchedSID == "" {
		restrictedMatch, restrictedErr := matchTokenSIDGroups(token, windows.TokenRestrictedSids, allowedSIDs)
		if restrictedErr != nil {
			return identity, fmt.Errorf("%w: read restricted token SIDs: %v", ErrNamedPipeIdentity, restrictedErr)
		}
		matchedSID = restrictedMatch
	}
	if matchedSID == "" {
		return identity, fmt.Errorf("%w: peer SID is not allowed", ErrNamedPipeIdentity)
	}
	identity.SID = matchedSID
	identity.IntegrityRID, err = tokenIntegrityRID(token)
	if err != nil {
		return identity, fmt.Errorf("%w: read token integrity: %v", ErrNamedPipeIdentity, err)
	}
	if err := validateNamedPipeIntegrity(identity.IntegrityRID, minimumIntegrity); err != nil {
		return identity, err
	}
	return identity, nil
}

func validateNamedPipeIntegrity(actual, minimum uint32) error {
	if actual < minimum {
		return fmt.Errorf("%w: peer integrity 0x%x is below 0x%x", ErrNamedPipeIdentity, actual, minimum)
	}
	return nil
}

func matchRestrictedHelperGroup(allowed map[string]struct{}, groups []windows.SIDAndAttributes, requireEnabled bool) string {
	for _, group := range groups {
		if group.Sid == nil || group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 ||
			(requireEnabled && group.Attributes&windows.SE_GROUP_ENABLED == 0) {
			continue
		}
		sid := group.Sid.String()
		if !isRestrictedHelperSID(sid) {
			continue
		}
		if _, ok := allowed[sid]; ok {
			return sid
		}
	}
	return ""
}

func matchTokenSIDGroups(token windows.Token, informationClass uint32, allowed map[string]struct{}) (string, error) {
	var required uint32
	err := windows.GetTokenInformation(token, informationClass, nil, 0, &required)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || required == 0 {
		return "", err
	}
	buffer := make([]byte, required)
	if err := windows.GetTokenInformation(token, informationClass, &buffer[0], required, &required); err != nil {
		return "", err
	}
	groups := (*windows.Tokengroups)(unsafe.Pointer(&buffer[0])).AllGroups()
	match := matchRestrictedHelperGroup(allowed, groups, false)
	runtime.KeepAlive(buffer)
	return match, nil
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
		if connection.server {
			if err := windows.DisconnectNamedPipe(connection.handle); err != nil &&
				!errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
				result = err
			}
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
