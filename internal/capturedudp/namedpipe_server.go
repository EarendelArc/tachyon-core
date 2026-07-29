package capturedudp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

type namedPipeControllerSession struct {
	mu               sync.RWMutex
	controller       *Controller
	sender           NamedPipeDatagramSender
	operationTimeout time.Duration
	writer           *namedPipeWriter
}

type namedPipeWriteRequest struct {
	ctx    context.Context
	wire   []byte
	result chan error
}

type namedPipeWriter struct {
	ctx       context.Context
	cancel    context.CancelFunc
	transport namedPipeFrameIO
	timeout   time.Duration
	queue     chan namedPipeWriteRequest
	done      chan struct{}
	stateMu   sync.Mutex
	stateCond *sync.Cond
	closed    bool
}

func newNamedPipeWriter(ctx context.Context, transport namedPipeFrameIO, timeout time.Duration) *namedPipeWriter {
	writerCtx, cancel := context.WithCancel(ctx)
	writer := &namedPipeWriter{
		ctx: writerCtx, cancel: cancel, transport: transport, timeout: timeout,
		queue: make(chan namedPipeWriteRequest, namedPipeWriteQueueSize), done: make(chan struct{}),
	}
	writer.stateCond = sync.NewCond(&writer.stateMu)
	go writer.run()
	return writer
}

func (writer *namedPipeWriter) WriteFrame(ctx context.Context, frame namedPipeFrame) error {
	wire, err := marshalNamedPipeFrame(frame)
	if err != nil {
		return err
	}
	request := namedPipeWriteRequest{ctx: ctx, wire: wire, result: make(chan error, 1)}
	if err := writer.enqueue(ctx, request); err != nil {
		clear(wire)
		return err
	}
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		return normalizeNamedPipeContextError(ctx, ctx.Err())
	case <-writer.done:
		return ErrClosed
	}
}

// enqueue transfers ownership of request.wire to the writer after an atomic,
// non-blocking queue submission. Waiting for capacity happens outside the
// channel send, so Close can always acquire stateMu, mark the writer closed,
// and wake the waiter before draining the queue.
func (writer *namedPipeWriter) enqueue(ctx context.Context, request namedPipeWriteRequest) error {
	wake := func() {
		writer.stateMu.Lock()
		writer.stateCond.Broadcast()
		writer.stateMu.Unlock()
	}
	stopCaller := context.AfterFunc(ctx, wake)
	stopWriter := context.AfterFunc(writer.ctx, wake)
	defer stopCaller()
	defer stopWriter()

	writer.stateMu.Lock()
	defer writer.stateMu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return normalizeNamedPipeContextError(ctx, err)
		}
		if writer.closed || writer.ctx.Err() != nil {
			return ErrClosed
		}
		select {
		case writer.queue <- request:
			return nil
		default:
			writer.stateCond.Wait()
		}
	}
}

func (writer *namedPipeWriter) markClosed() {
	writer.stateMu.Lock()
	writer.closed = true
	writer.stateCond.Broadcast()
	writer.stateMu.Unlock()
}

func (writer *namedPipeWriter) drainQueue() {
	for {
		select {
		case request := <-writer.queue:
			clear(request.wire)
			request.result <- ErrClosed
		default:
			return
		}
	}
}

func (writer *namedPipeWriter) run() {
	defer func() {
		writer.markClosed()
		close(writer.done)
	}()
	for {
		select {
		case request := <-writer.queue:
			writer.stateMu.Lock()
			writer.stateCond.Broadcast()
			writer.stateMu.Unlock()
			if err := request.ctx.Err(); err != nil {
				clear(request.wire)
				request.result <- normalizeNamedPipeContextError(request.ctx, err)
				continue
			}
			writeCtx, cancel := context.WithTimeout(writer.ctx, writer.timeout)
			stopCaller := context.AfterFunc(request.ctx, cancel)
			err := writer.transport.WriteFull(writeCtx, request.wire)
			if request.ctx.Err() != nil {
				err = normalizeNamedPipeContextError(request.ctx, errors.Join(err, request.ctx.Err()))
			} else {
				err = normalizeNamedPipeContextError(writeCtx, err)
			}
			stopCaller()
			cancel()
			clear(request.wire)
			request.result <- err
			if err != nil {
				// A partial or failed frame makes the byte stream unusable. Cancel
				// the connection so its blocked reader exits and the listener can
				// revoke this controller before accepting a replacement.
				writer.cancel()
			}
		case <-writer.ctx.Done():
			writer.markClosed()
			writer.drainQueue()
			return
		}
	}
}

func (writer *namedPipeWriter) Close() {
	writer.stateMu.Lock()
	shouldCancel := false
	if !writer.closed {
		writer.closed = true
		writer.stateCond.Broadcast()
		shouldCancel = true
	}
	writer.stateMu.Unlock()
	if shouldCancel {
		writer.cancel()
	}
	<-writer.done
}

func newNamedPipeControllerSession(ctx context.Context, transport namedPipeFrameIO, sender NamedPipeDatagramSender, operationTimeout time.Duration) *namedPipeControllerSession {
	return &namedPipeControllerSession{
		sender: sender, operationTimeout: operationTimeout,
		writer: newNamedPipeWriter(ctx, transport, operationTimeout),
	}
}

func (session *namedPipeControllerSession) bind(controller *Controller) {
	session.mu.Lock()
	session.controller = controller
	session.mu.Unlock()
}

func (session *namedPipeControllerSession) unbind(controller *Controller) {
	session.mu.Lock()
	if session.controller == controller {
		session.controller = nil
	}
	session.mu.Unlock()
}

func (session *namedPipeControllerSession) DeliverReply(ctx context.Context, datagram tgp.TunnelDatagram) error {
	operationCtx, cancel := context.WithTimeout(ctx, session.operationTimeout)
	defer cancel()
	session.mu.RLock()
	controller := session.controller
	session.mu.RUnlock()
	if controller == nil {
		return ErrControllerRevoked
	}
	delivery, err := controller.ResolveReply(datagram)
	if err != nil {
		return err
	}
	defer delivery.Release()
	payload := make([]byte, 0, len(delivery.FlowID)+8+len(delivery.LeaseNonce)+len(delivery.Payload))
	payload = append(payload, delivery.FlowID[:]...)
	payload = appendUint64(payload, delivery.Generation)
	payload = append(payload, delivery.LeaseNonce[:]...)
	payload = append(payload, delivery.Payload...)
	defer clear(payload)
	return session.writer.WriteFrame(operationCtx, namedPipeFrame{Type: pipeMessageDelivery, Payload: payload})
}

func (session *namedPipeControllerSession) WriteFrame(ctx context.Context, frame namedPipeFrame) error {
	writeCtx, cancel := context.WithTimeout(ctx, session.operationTimeout)
	defer cancel()
	return session.writer.WriteFrame(writeCtx, frame)
}

func (session *namedPipeControllerSession) Close() {
	session.writer.Close()
}

func (session *namedPipeControllerSession) Context() context.Context {
	return session.writer.ctx
}

func serveNamedPipeController(
	ctx context.Context,
	registry *Registry,
	attachment *TransportAttachment,
	transport namedPipeFrameIO,
	sender NamedPipeDatagramSender,
	session *namedPipeControllerSession,
	operationTimeout time.Duration,
	idleTimeout time.Duration,
) (resultErr error) {
	if registry == nil || attachment == nil || transport == nil || sender == nil || session == nil {
		return fmt.Errorf("%w: incomplete server state", ErrNamedPipeProtocol)
	}
	token, err := registry.AttachTransport(attachment)
	if err != nil {
		return err
	}
	var controller *Controller
	connectionCtx := session.Context()
	defer func() {
		session.Close()
		if controller != nil {
			session.unbind(controller)
			resultErr = errors.Join(resultErr, controller.Close())
			return
		}
		resultErr = errors.Join(resultErr, attachment.Detach())
	}()

	helloPayload := append([]byte(nil), token[:]...)
	if err := session.WriteFrame(connectionCtx, namedPipeFrame{Type: pipeMessageHello, Payload: helloPayload}); err != nil {
		clear(helloPayload)
		clear(token[:])
		return err
	}
	clear(helloPayload)

	var lastRequestID uint64
	for {
		frame, err := readNamedPipeFrameWithIdleTimeout(connectionCtx, transport, idleTimeout)
		if err != nil {
			clear(token[:])
			if isNamedPipeEOF(err) {
				return nil
			}
			return err
		}
		requestID, decoder, err := decodeRequest(frame)
		if err != nil {
			clear(frame.Payload)
			clear(token[:])
			return err
		}
		if requestID <= lastRequestID {
			clear(frame.Payload)
			clear(token[:])
			return fmt.Errorf("%w: request IDs must increase", ErrNamedPipeProtocol)
		}
		lastRequestID = requestID

		if controller == nil {
			if frame.Type != pipeMessageAuthenticate {
				clear(frame.Payload)
				clear(token[:])
				_ = session.WriteFrame(connectionCtx, namedPipeResponse(requestID, frame.Type, pipeStatusUnauthorized, nil))
				return ErrAuthentication
			}
			presented, decodeErr := decoder.take(SessionTokenSize)
			if decodeErr == nil {
				decodeErr = decoder.done()
			}
			var presentedToken SessionToken
			if decodeErr == nil {
				copy(presentedToken[:], presented)
				controller, decodeErr = registry.Authenticate(attachment, presentedToken)
				if decodeErr == nil {
					session.bind(controller)
				}
			}
			clear(presentedToken[:])
			clear(frame.Payload)
			clear(token[:])
			status := statusForError(decodeErr)
			if writeErr := session.WriteFrame(connectionCtx,
				namedPipeResponse(requestID, frame.Type, status, nil)); writeErr != nil {
				return writeErr
			}
			if decodeErr != nil {
				return decodeErr
			}
			continue
		}

		operationCtx, operationCancel := context.WithTimeout(connectionCtx, operationTimeout)
		responseData, release, terminal, operationErr := handleNamedPipeOperation(operationCtx, controller, sender, frame.Type, decoder)
		operationCancel()
		clear(frame.Payload)
		response := namedPipeResponse(requestID, frame.Type, statusForError(operationErr), responseData)
		if frame.Type == pipeMessagePing && operationErr == nil {
			pongPayload := appendRequestID(nil, requestID)
			pongPayload = append(pongPayload, responseData...)
			response = namedPipeFrame{Type: pipeMessagePong, Payload: pongPayload}
		}
		clear(responseData)
		writeErr := session.WriteFrame(connectionCtx, response)
		clear(response.Payload)
		if release != nil {
			release()
		}
		if writeErr != nil {
			return writeErr
		}
		if terminal {
			return operationErr
		}
	}
}

func handleNamedPipeOperation(
	ctx context.Context,
	controller *Controller,
	sender NamedPipeDatagramSender,
	messageType namedPipeMessageType,
	decoder *pipeDecoder,
) (data []byte, release func(), terminal bool, err error) {
	switch messageType {
	case pipeMessagePrepareGeneration:
		generation, decodeErr := decoder.uint64()
		if decodeErr != nil || decoder.done() != nil {
			return nil, nil, true, ErrNamedPipeProtocol
		}
		transaction, operationErr := controller.PrepareGeneration(generation)
		if operationErr != nil {
			return nil, nil, false, operationErr
		}
		data = appendUint64(data, transaction.generation)
		data = append(data, transaction.id[:]...)
		return data, nil, false, nil

	case pipeMessageCommitGeneration, pipeMessageAbortGeneration:
		generation, transactionIDValue, decodeErr := decodePipeTransaction(decoder)
		if decodeErr != nil {
			return nil, nil, true, decodeErr
		}
		transaction := Transaction{id: transactionIDValue, generation: generation}
		if messageType == pipeMessageCommitGeneration {
			return nil, nil, false, controller.CommitGeneration(transaction)
		}
		return nil, nil, false, controller.AbortGeneration(transaction)

	case pipeMessageDisableGeneration:
		generation, decodeErr := decoder.uint64()
		if decodeErr != nil || decoder.done() != nil {
			return nil, nil, true, ErrNamedPipeProtocol
		}
		return nil, nil, false, controller.DisableGeneration(generation)

	case pipeMessageOpenFlow:
		spec, decodeErr := decodePipeFlowSpec(decoder)
		if decodeErr != nil {
			return nil, nil, true, decodeErr
		}
		lease, operationErr := controller.OpenFlow(spec)
		if operationErr != nil {
			return nil, nil, false, operationErr
		}
		data = append(data, lease.FlowID[:]...)
		data = appendUint64(data, lease.Generation)
		data = append(data, lease.LeaseNonce[:]...)
		data = appendUint64(data, uint64(lease.ExpiresAt.UnixMilli()))
		return data, nil, false, nil

	case pipeMessageDatagram:
		datagram, decodeErr := decodePipeDatagram(decoder)
		if decodeErr != nil {
			return nil, nil, true, decodeErr
		}
		accepted, operationErr := controller.AcceptDatagram(datagram)
		if operationErr != nil {
			return nil, nil, false, operationErr
		}
		operationErr = sender.SendDatagram(ctx, accepted.Datagram)
		accepted.Release()
		return nil, nil, false, operationErr

	case pipeMessageCloseFlow:
		generation, decodeErr := decoder.uint64()
		if decodeErr != nil {
			return nil, nil, true, decodeErr
		}
		flowIDBytes, decodeErr := decoder.take(len(FlowID{}))
		if decodeErr != nil {
			return nil, nil, true, decodeErr
		}
		nonceBytes, decodeErr := decoder.take(len(LeaseNonce{}))
		if decodeErr != nil || decoder.done() != nil {
			return nil, nil, true, ErrNamedPipeProtocol
		}
		var flowID FlowID
		var nonce LeaseNonce
		copy(flowID[:], flowIDBytes)
		copy(nonce[:], nonceBytes)
		return nil, nil, false, controller.CloseFlow(generation, flowID, nonce)

	case pipeMessageCloseConnection:
		if decoder.done() != nil {
			return nil, nil, true, ErrNamedPipeProtocol
		}
		return nil, nil, true, nil

	case pipeMessagePing:
		payload, decodeErr := decoder.take(len(decoder.payload) - decoder.offset)
		if decodeErr != nil || len(payload) > 32 || decoder.done() != nil {
			return nil, nil, true, ErrNamedPipeProtocol
		}
		return append([]byte(nil), payload...), nil, false, nil

	default:
		return nil, nil, true, ErrNamedPipeProtocol
	}
}

func decodePipeTransaction(decoder *pipeDecoder) (uint64, transactionID, error) {
	generation, err := decoder.uint64()
	if err != nil {
		return 0, transactionID{}, err
	}
	idBytes, err := decoder.take(len(transactionID{}))
	if err != nil || decoder.done() != nil {
		return 0, transactionID{}, ErrNamedPipeProtocol
	}
	var id transactionID
	copy(id[:], idBytes)
	return generation, id, nil
}

func decodePipeFlowSpec(decoder *pipeDecoder) (FlowSpec, error) {
	flowIDBytes, err := decoder.take(len(FlowID{}))
	if err != nil {
		return FlowSpec{}, err
	}
	generation, err := decoder.uint64()
	if err != nil {
		return FlowSpec{}, err
	}
	familyValue, err := decoder.uint8()
	if err != nil {
		return FlowSpec{}, err
	}
	family := AddressFamily(familyValue)
	local, err := decodeAddrPort(decoder, family)
	if err != nil {
		return FlowSpec{}, err
	}
	remote, err := decodeAddrPort(decoder, family)
	if err != nil || decoder.done() != nil {
		return FlowSpec{}, ErrNamedPipeProtocol
	}
	var flowID FlowID
	copy(flowID[:], flowIDBytes)
	return FlowSpec{ID: flowID, Generation: generation, Family: family, Local: local, Remote: remote}, nil
}

func decodePipeDatagram(decoder *pipeDecoder) (Datagram, error) {
	flowIDBytes, err := decoder.take(len(FlowID{}))
	if err != nil {
		return Datagram{}, err
	}
	generation, err := decoder.uint64()
	if err != nil {
		return Datagram{}, err
	}
	nonceBytes, err := decoder.take(len(LeaseNonce{}))
	if err != nil {
		return Datagram{}, err
	}
	sequence, err := decoder.uint64()
	if err != nil {
		return Datagram{}, err
	}
	payload, err := decoder.take(len(decoder.payload) - decoder.offset)
	if err != nil || decoder.done() != nil {
		return Datagram{}, ErrNamedPipeProtocol
	}
	var flowID FlowID
	var nonce LeaseNonce
	copy(flowID[:], flowIDBytes)
	copy(nonce[:], nonceBytes)
	return Datagram{
		FlowID: flowID, Generation: generation, LeaseNonce: nonce,
		Sequence: sequence, Payload: payload,
	}, nil
}

func readNamedPipeFrameWithIdleTimeout(
	ctx context.Context,
	transport namedPipeFrameIO,
	timeout time.Duration,
) (namedPipeFrame, error) {
	if timeout == 0 {
		frame, err := readNamedPipeFrame(ctx, transport)
		return frame, normalizeNamedPipeContextError(ctx, err)
	}
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	frame, err := readNamedPipeFrame(operationContext, transport)
	if err != nil && errors.Is(operationContext.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		return namedPipeFrame{}, errors.Join(ErrNamedPipeIdleTimeout, err)
	}
	return frame, normalizeNamedPipeContextError(operationContext, err)
}

func normalizeNamedPipeContextError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return errors.Join(ErrNamedPipeTimeout, err)
	}
	switch ctx.Err() {
	case context.DeadlineExceeded:
		return errors.Join(ErrNamedPipeTimeout, err)
	case context.Canceled:
		return errors.Join(ErrNamedPipeCanceled, err)
	default:
		return err
	}
}

func encodePipeFlowSpec(requestID uint64, spec FlowSpec) ([]byte, error) {
	payload := appendRequestID(nil, requestID)
	payload = append(payload, spec.ID[:]...)
	payload = appendUint64(payload, spec.Generation)
	payload = append(payload, byte(spec.Family))
	var err error
	payload, err = appendAddrPort(payload, spec.Local, spec.Family)
	if err != nil {
		return nil, err
	}
	payload, err = appendAddrPort(payload, spec.Remote, spec.Family)
	return payload, err
}

func decodePipeResponse(frame namedPipeFrame) (uint64, namedPipeMessageType, namedPipeStatus, []byte, error) {
	if frame.Type != pipeMessageResponse || len(frame.Payload) < 12 {
		return 0, 0, 0, nil, ErrNamedPipeProtocol
	}
	requestID := binary.BigEndian.Uint64(frame.Payload[:8])
	operation := namedPipeMessageType(binary.BigEndian.Uint16(frame.Payload[8:10]))
	status := namedPipeStatus(binary.BigEndian.Uint16(frame.Payload[10:12]))
	if requestID == 0 || !operation.valid() || operation == pipeMessageResponse {
		return 0, 0, 0, nil, ErrNamedPipeProtocol
	}
	return requestID, operation, status, frame.Payload[12:], nil
}
