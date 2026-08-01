package capturedudp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrNamedPipeRemote    = errors.New("captured UDP named pipe operation was rejected by Core")
	ErrNamedPipeNotReady  = errors.New("captured UDP named pipe client is not connected")
	ErrNamedPipeClientRun = errors.New("captured UDP named pipe client is already running")
)

// NamedPipeClientConfig contains only the unprivileged helper-side connection
// policy. ACLs and peer verification remain server responsibilities.
type NamedPipeClientConfig struct {
	Name                      string
	ServerSIDs                []string
	MinimumServerIntegrityRID uint32
	TrustedServerBinary       string
	TrustedServerSHA256       string
	OperationTimeout          time.Duration
	ReconnectMin              time.Duration
	ReconnectMax              time.Duration
	MaxPending                int
}

func (config NamedPipeClientConfig) normalized() (NamedPipeClientConfig, error) {
	if !validNamedPipeName(config.Name) {
		return NamedPipeClientConfig{}, fmt.Errorf("%w: invalid pipe name", ErrNamedPipeProtocol)
	}
	if len(config.ServerSIDs) == 0 || len(config.ServerSIDs) > 16 {
		return NamedPipeClientConfig{}, fmt.Errorf("%w: server SID allowlist is required", ErrNamedPipeIdentity)
	}
	config.ServerSIDs = append([]string(nil), config.ServerSIDs...)
	seenSIDs := make(map[string]struct{}, len(config.ServerSIDs))
	for index, sid := range config.ServerSIDs {
		sid = normalizeSIDText(sid)
		if sid == "" {
			return NamedPipeClientConfig{}, fmt.Errorf("%w: invalid server SID", ErrNamedPipeIdentity)
		}
		if _, exists := seenSIDs[sid]; exists {
			return NamedPipeClientConfig{}, fmt.Errorf("%w: duplicate server SID", ErrNamedPipeIdentity)
		}
		seenSIDs[sid] = struct{}{}
		config.ServerSIDs[index] = sid
	}
	if config.MinimumServerIntegrityRID == 0 {
		config.MinimumServerIntegrityRID = 0x2000
	}
	if config.TrustedServerBinary == "" || config.TrustedServerSHA256 == "" {
		return NamedPipeClientConfig{}, fmt.Errorf("%w: trusted server binary and immutable SHA-256 are required", ErrNamedPipeIdentity)
	}
	config.TrustedServerSHA256 = normalizeSHA256(config.TrustedServerSHA256)
	if config.TrustedServerSHA256 == "" {
		return NamedPipeClientConfig{}, fmt.Errorf("%w: invalid trusted server SHA-256", ErrNamedPipeIdentity)
	}
	if config.OperationTimeout <= 0 {
		config.OperationTimeout = namedPipeDefaultTimeout
	}
	if config.OperationTimeout > namedPipeMaxTimeout {
		return NamedPipeClientConfig{}, fmt.Errorf("%w: operation timeout exceeds %s", ErrNamedPipeProtocol, namedPipeMaxTimeout)
	}
	if config.ReconnectMin <= 0 {
		config.ReconnectMin = 100 * time.Millisecond
	}
	if config.ReconnectMax <= 0 {
		config.ReconnectMax = 5 * time.Second
	}
	if config.ReconnectMin > config.ReconnectMax || config.ReconnectMax > time.Minute {
		return NamedPipeClientConfig{}, fmt.Errorf("%w: invalid reconnect backoff", ErrNamedPipeProtocol)
	}
	if config.MaxPending <= 0 {
		config.MaxPending = namedPipeWriteQueueSize
	}
	if config.MaxPending > namedPipeWriteQueueSize*4 {
		return NamedPipeClientConfig{}, fmt.Errorf("%w: pending request limit exceeds hard bound", ErrNamedPipeProtocol)
	}
	return config, nil
}

type GenerationTransaction struct {
	Generation uint64
	ID         [16]byte
}

type NamedPipeDelivery struct {
	FlowID     FlowID
	Generation uint64
	LeaseNonce LeaseNonce
	Payload    []byte
}

type NamedPipeClientHealth struct {
	Connected       bool
	Authenticated   bool
	Reconnects      uint64
	Attempt         uint64
	Stage           string
	LastError       string
	BufferedBytes   int
	PendingRequests int
}

// NamedPipeClient is the helper-side protocol client. It has no capture
// privileges and never manufactures packets; delivery is passed to the
// caller's Injector only after the authenticated Core session validates it.
type NamedPipeClient interface {
	Run(context.Context) error
	Close() error
	Health() NamedPipeClientHealth
	Ping(context.Context, []byte) ([]byte, error)
	PrepareGeneration(context.Context, uint64) (GenerationTransaction, error)
	CommitGeneration(context.Context, GenerationTransaction) error
	AbortGeneration(context.Context, GenerationTransaction) error
	DisableGeneration(context.Context, uint64) error
	OpenFlow(context.Context, FlowSpec) (FlowLease, error)
	SendDatagram(context.Context, Datagram) error
	CloseFlow(context.Context, uint64, FlowID, LeaseNonce) error
}

type namedPipeDeliveryHandler func(context.Context, NamedPipeDelivery) error

type namedPipeClient struct {
	config  NamedPipeClientConfig
	onReply namedPipeDeliveryHandler
	open    namedPipeClientOpener

	mu        sync.Mutex
	writeMu   sync.Mutex
	requestMu sync.Mutex
	conn      namedPipeClientConnection
	connected chan struct{}
	pending   map[uint64]chan namedPipeClientResponse
	nextID    uint64
	reconnect uint64
	attempt   uint64
	stage     string
	lastError string
	pipeOpen  bool
	running   bool
	closed    bool
	cancel    context.CancelFunc
}

type namedPipeClientConnection interface {
	namedPipeFrameIO
	Close() error
}

type namedPipeClientOpener func(context.Context, NamedPipeClientConfig) (namedPipeClientConnection, error)

type namedPipeClientResponse struct {
	operation namedPipeMessageType
	status    namedPipeStatus
	data      []byte
	err       error
}

func newNamedPipeClient(config NamedPipeClientConfig, onReply namedPipeDeliveryHandler) (NamedPipeClient, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	return &namedPipeClient{
		config: config, onReply: onReply, pending: make(map[uint64]chan namedPipeClientResponse),
		nextID: 1, open: openNamedPipeClient, stage: "idle",
	}, nil
}

func (client *namedPipeClient) Run(parent context.Context) error {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return ErrClosed
	}
	if client.running {
		client.mu.Unlock()
		return ErrNamedPipeClientRun
	}
	ctx, cancel := context.WithCancel(parent)
	client.cancel = cancel
	client.running = true
	client.mu.Unlock()
	defer func() {
		cancel()
		client.mu.Lock()
		client.running = false
		client.cancel = nil
		client.pipeOpen = false
		client.stage = "stopped"
		client.detachLocked(ErrNamedPipeNotReady)
		client.mu.Unlock()
	}()

	backoff := client.config.ReconnectMin
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		client.mu.Lock()
		client.attempt++
		client.stage = "connecting"
		client.lastError = ""
		client.mu.Unlock()
		connection, err := client.open(ctx, client.config)
		if err == nil {
			client.mu.Lock()
			client.pipeOpen = true
			client.stage = "awaiting_hello"
			client.mu.Unlock()
			err = client.runConnection(ctx, connection)
			_ = connection.Close()
		}
		if ctx.Err() != nil {
			return nil
		}
		client.mu.Lock()
		client.pipeOpen = false
		client.detachLocked(err)
		client.reconnect++
		if err != nil {
			switch client.stage {
			case "connecting":
				client.stage = "connect_failed"
			case "awaiting_hello":
				client.stage = "hello_failed"
			case "authenticating":
				client.stage = "authentication_failed"
			case "authenticated":
				client.stage = "session_failed"
			}
			client.lastError = err.Error()
		}
		client.mu.Unlock()
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if err == nil {
			backoff = client.config.ReconnectMin
		} else {
			backoff = nextNamedPipeReconnectBackoff(backoff, client.config.ReconnectMax)
		}
	}
}

func nextNamedPipeReconnectBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func (client *namedPipeClient) runConnection(ctx context.Context, connection namedPipeClientConnection) error {
	operationCtx, cancel := context.WithTimeout(ctx, client.config.OperationTimeout)
	hello, err := readNamedPipeFrame(operationCtx, connection)
	cancel()
	if err != nil || hello.Type != pipeMessageHello || len(hello.Payload) != SessionTokenSize {
		clear(hello.Payload)
		if err == nil {
			err = ErrNamedPipeProtocol
		}
		return err
	}
	var token SessionToken
	copy(token[:], hello.Payload)
	clear(hello.Payload)
	client.mu.Lock()
	client.stage = "authenticating"
	client.mu.Unlock()
	client.requestMu.Lock()
	authID := client.allocateRequestID()
	auth := appendRequestID(nil, authID)
	auth = append(auth, token[:]...)
	clear(token[:])
	err = client.writeFrame(ctx, connection, namedPipeFrame{Type: pipeMessageAuthenticate, Payload: auth})
	client.requestMu.Unlock()
	if err != nil {
		clear(auth)
		return err
	}
	clear(auth)
	operationCtx, cancel = context.WithTimeout(ctx, client.config.OperationTimeout)
	response, err := readNamedPipeFrame(operationCtx, connection)
	cancel()
	if err != nil {
		clear(response.Payload)
		return err
	}
	responseID, operation, status, data, err := decodePipeResponse(response)
	clear(response.Payload)
	if err != nil || responseID != authID || operation != pipeMessageAuthenticate || status != pipeStatusOK {
		if err == nil {
			err = ErrAuthentication
		}
		return err
	}
	clear(data)

	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return ErrClosed
	}
	client.conn = connection
	client.connected = make(chan struct{})
	close(client.connected)
	client.stage = "authenticated"
	client.lastError = ""
	client.mu.Unlock()
	return client.readConnection(ctx, connection)
}

func (client *namedPipeClient) readConnection(ctx context.Context, connection namedPipeClientConnection) error {
	for {
		frame, err := readNamedPipeFrame(ctx, connection)
		if err != nil {
			clear(frame.Payload)
			return err
		}
		switch frame.Type {
		case pipeMessageResponse:
			requestID, operation, status, data, decodeErr := decodePipeResponse(frame)
			if decodeErr == nil {
				client.resolve(requestID, namedPipeClientResponse{operation: operation, status: status, data: append([]byte(nil), data...)})
			}
			clear(frame.Payload)
			if decodeErr != nil {
				return decodeErr
			}
		case pipeMessagePong:
			if len(frame.Payload) < 8 {
				clear(frame.Payload)
				return ErrNamedPipeProtocol
			}
			requestID := binary.BigEndian.Uint64(frame.Payload[:8])
			client.resolve(requestID, namedPipeClientResponse{operation: pipeMessagePing, status: pipeStatusOK, data: append([]byte(nil), frame.Payload[8:]...)})
			clear(frame.Payload)
		case pipeMessageDelivery:
			delivery, decodeErr := decodeNamedPipeDelivery(frame.Payload)
			clear(frame.Payload)
			if decodeErr != nil {
				return decodeErr
			}
			if client.onReply != nil {
				if err := client.onReply(ctx, delivery); err != nil {
					clear(delivery.Payload)
					return err
				}
			}
			clear(delivery.Payload)
		default:
			clear(frame.Payload)
			return fmt.Errorf("%w: unexpected helper frame %d", ErrNamedPipeProtocol, frame.Type)
		}
	}
}

func (client *namedPipeClient) call(ctx context.Context, operation namedPipeMessageType, body []byte) ([]byte, error) {
	defer clear(body)
	client.requestMu.Lock()
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		client.requestMu.Unlock()
		return nil, ErrClosed
	}
	connection := client.conn
	connected := client.connected
	if connection == nil || connected == nil {
		client.mu.Unlock()
		client.requestMu.Unlock()
		return nil, ErrNamedPipeNotReady
	}
	if len(client.pending) >= client.config.MaxPending {
		client.mu.Unlock()
		client.requestMu.Unlock()
		return nil, ErrOutstandingBudget
	}
	requestID := client.allocateRequestIDLocked()
	response := make(chan namedPipeClientResponse, 1)
	client.pending[requestID] = response
	client.mu.Unlock()

	select {
	case <-connected:
	case <-ctx.Done():
		client.removePending(requestID)
		client.requestMu.Unlock()
		return nil, ctx.Err()
	}
	wire := appendRequestID(nil, requestID)
	wire = append(wire, body...)
	err := client.writeFrame(ctx, connection, namedPipeFrame{Type: operation, Payload: wire})
	clear(wire)
	client.requestMu.Unlock()
	if err != nil {
		client.removePending(requestID)
		return nil, err
	}
	select {
	case result := <-response:
		if result.err != nil {
			clear(result.data)
			return nil, result.err
		}
		if result.operation != operation || result.status != pipeStatusOK {
			clear(result.data)
			return nil, namedPipeStatusError(result.status, operation)
		}
		return result.data, nil
	case <-ctx.Done():
		client.removePending(requestID)
		client.drainResponse(response)
		return nil, ctx.Err()
	}
}

func (client *namedPipeClient) writeFrame(ctx context.Context, connection namedPipeClientConnection, frame namedPipeFrame) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	operationCtx, cancel := context.WithTimeout(ctx, client.config.OperationTimeout)
	defer cancel()
	return writeNamedPipeFrame(operationCtx, connection, frame)
}

func (client *namedPipeClient) resolve(requestID uint64, response namedPipeClientResponse) {
	client.mu.Lock()
	channel := client.pending[requestID]
	delete(client.pending, requestID)
	if channel != nil {
		channel <- response
	} else {
		clear(response.data)
	}
	client.mu.Unlock()
}

func (client *namedPipeClient) removePending(requestID uint64) {
	client.mu.Lock()
	channel := client.pending[requestID]
	delete(client.pending, requestID)
	if channel != nil {
		select {
		case result := <-channel:
			clear(result.data)
		default:
		}
	}
	client.mu.Unlock()
}

func (client *namedPipeClient) drainResponse(channel <-chan namedPipeClientResponse) {
	select {
	case result := <-channel:
		clear(result.data)
	default:
	}
}

func (client *namedPipeClient) detachLocked(err error) {
	client.conn = nil
	if client.connected != nil {
		select {
		case <-client.connected:
		default:
			close(client.connected)
		}
	}
	for requestID, channel := range client.pending {
		delete(client.pending, requestID)
		channel <- namedPipeClientResponse{err: err}
	}
}

func (client *namedPipeClient) allocateRequestID() uint64 {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.allocateRequestIDLocked()
}

func (client *namedPipeClient) allocateRequestIDLocked() uint64 {
	requestID := client.nextID
	client.nextID++
	if client.nextID == 0 {
		client.nextID = 1
	}
	return requestID
}

func (client *namedPipeClient) Close() error {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return nil
	}
	client.closed = true
	cancel := client.cancel
	connection := client.conn
	client.detachLocked(ErrClosed)
	client.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if connection != nil {
		return connection.Close()
	}
	return nil
}

func (client *namedPipeClient) Health() NamedPipeClientHealth {
	client.mu.Lock()
	defer client.mu.Unlock()
	return NamedPipeClientHealth{Connected: client.pipeOpen, Authenticated: client.conn != nil,
		Reconnects: client.reconnect, Attempt: client.attempt, Stage: client.stage,
		LastError: client.lastError, PendingRequests: len(client.pending)}
}

func (client *namedPipeClient) Ping(ctx context.Context, payload []byte) ([]byte, error) {
	if len(payload) > 32 {
		return nil, ErrNamedPipeProtocol
	}
	return client.call(ctx, pipeMessagePing, append([]byte(nil), payload...))
}

func (client *namedPipeClient) PrepareGeneration(ctx context.Context, generation uint64) (GenerationTransaction, error) {
	data, err := client.call(ctx, pipeMessagePrepareGeneration, appendUint64(nil, generation))
	if err != nil {
		return GenerationTransaction{}, err
	}
	defer clear(data)
	if len(data) != 24 {
		return GenerationTransaction{}, ErrNamedPipeProtocol
	}
	var transaction GenerationTransaction
	transaction.Generation = binary.BigEndian.Uint64(data[:8])
	copy(transaction.ID[:], data[8:])
	return transaction, nil
}

func (client *namedPipeClient) transactionCall(ctx context.Context, operation namedPipeMessageType, transaction GenerationTransaction) error {
	body := appendUint64(nil, transaction.Generation)
	body = append(body, transaction.ID[:]...)
	defer clear(body)
	data, err := client.call(ctx, operation, body)
	clear(data)
	return err
}

func (client *namedPipeClient) CommitGeneration(ctx context.Context, transaction GenerationTransaction) error {
	return client.transactionCall(ctx, pipeMessageCommitGeneration, transaction)
}

func (client *namedPipeClient) AbortGeneration(ctx context.Context, transaction GenerationTransaction) error {
	return client.transactionCall(ctx, pipeMessageAbortGeneration, transaction)
}

func (client *namedPipeClient) DisableGeneration(ctx context.Context, generation uint64) error {
	body := appendUint64(nil, generation)
	data, err := client.call(ctx, pipeMessageDisableGeneration, body)
	clear(body)
	clear(data)
	return err
}

func (client *namedPipeClient) OpenFlow(ctx context.Context, spec FlowSpec) (FlowLease, error) {
	requestID := uint64(1)
	client.mu.Lock()
	requestID = client.nextID
	client.mu.Unlock()
	encoded, err := encodePipeFlowSpec(requestID, spec)
	if err != nil {
		return FlowLease{}, err
	}
	defer clear(encoded)
	body := encoded[8:]
	data, err := client.call(ctx, pipeMessageOpenFlow, body)
	if err != nil {
		return FlowLease{}, err
	}
	defer clear(data)
	if len(data) != 48 {
		return FlowLease{}, ErrNamedPipeProtocol
	}
	var lease FlowLease
	copy(lease.FlowID[:], data[:16])
	lease.Generation = binary.BigEndian.Uint64(data[16:24])
	copy(lease.LeaseNonce[:], data[24:40])
	lease.ExpiresAt = time.UnixMilli(int64(binary.BigEndian.Uint64(data[40:48])))
	return lease, nil
}

func (client *namedPipeClient) SendDatagram(ctx context.Context, datagram Datagram) error {
	body := append(bodyForDatagram(nil, datagram), datagram.Payload...)
	defer clear(body)
	data, err := client.call(ctx, pipeMessageDatagram, body)
	clear(data)
	return err
}

func (client *namedPipeClient) CloseFlow(ctx context.Context, generation uint64, id FlowID, nonce LeaseNonce) error {
	body := appendUint64(nil, generation)
	body = append(body, id[:]...)
	body = append(body, nonce[:]...)
	defer clear(body)
	data, err := client.call(ctx, pipeMessageCloseFlow, body)
	clear(data)
	return err
}

func bodyForDatagram(destination []byte, datagram Datagram) []byte {
	destination = append(destination, datagram.FlowID[:]...)
	destination = appendUint64(destination, datagram.Generation)
	destination = append(destination, datagram.LeaseNonce[:]...)
	destination = appendUint64(destination, datagram.Sequence)
	return destination
}

func decodeNamedPipeDelivery(payload []byte) (NamedPipeDelivery, error) {
	if len(payload) < 40 {
		return NamedPipeDelivery{}, ErrNamedPipeProtocol
	}
	var delivery NamedPipeDelivery
	copy(delivery.FlowID[:], payload[:16])
	delivery.Generation = binary.BigEndian.Uint64(payload[16:24])
	copy(delivery.LeaseNonce[:], payload[24:40])
	delivery.Payload = append([]byte(nil), payload[40:]...)
	return delivery, nil
}

func namedPipeStatusError(status namedPipeStatus, operation namedPipeMessageType) error {
	if status == pipeStatusOK {
		return nil
	}
	return fmt.Errorf("%w: operation=%d status=%d", ErrNamedPipeRemote, operation, status)
}

func normalizeSIDText(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "S-1-") {
		return ""
	}
	parts := strings.Split(value[4:], "-")
	if len(parts) == 0 {
		return ""
	}
	for _, part := range parts {
		if part == "" {
			return ""
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return ""
			}
		}
	}
	return value
}

func normalizeSHA256(value string) string {
	value = strings.TrimSpace(value)
	if len(value) != hex.EncodedLen(sha256.Size) {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return strings.ToLower(value)
}
