package capturedudp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestNamedPipeFrameRoundTrip(t *testing.T) {
	messageTypes := []namedPipeMessageType{
		pipeMessageHello, pipeMessageAuthenticate, pipeMessagePrepareGeneration,
		pipeMessageCommitGeneration, pipeMessageAbortGeneration, pipeMessageDisableGeneration,
		pipeMessageOpenFlow, pipeMessageDatagram, pipeMessageDelivery, pipeMessageCloseFlow,
		pipeMessageCloseConnection, pipeMessagePing, pipeMessagePong, pipeMessageResponse,
	}
	for _, messageType := range messageTypes {
		for _, size := range []int{0, 1, 32, NamedPipeMaxFramePayload} {
			t.Run(string(rune(messageType))+"/"+string(rune(size)), func(t *testing.T) {
				payload := bytes.Repeat([]byte{byte(messageType)}, size)
				encoded, err := marshalNamedPipeFrame(namedPipeFrame{Type: messageType, Payload: payload})
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := decodeNamedPipeFrame(encoded)
				if err != nil {
					t.Fatal(err)
				}
				if decoded.Type != messageType || !bytes.Equal(decoded.Payload, payload) {
					t.Fatalf("decoded frame type=%d payload=%d", decoded.Type, len(decoded.Payload))
				}
			})
		}
	}
}

func TestNamedPipeFrameRejectsInvalidHeadersBeforeBodyRead(t *testing.T) {
	valid, err := marshalNamedPipeFrame(namedPipeFrame{Type: pipeMessagePing, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "magic", mutate: func(frame []byte) { frame[0] ^= 0xff }},
		{name: "version", mutate: func(frame []byte) { binary.BigEndian.PutUint16(frame[4:6], NamedPipeProtocolVersion+1) }},
		{name: "type", mutate: func(frame []byte) { binary.BigEndian.PutUint16(frame[6:8], 0x7fff) }},
		{name: "oversize", mutate: func(frame []byte) { binary.BigEndian.PutUint32(frame[8:12], NamedPipeMaxFramePayload+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := append([]byte(nil), valid...)
			test.mutate(encoded)
			transport := &countingFrameIO{reader: bytes.NewReader(encoded[:namedPipeFrameHeaderSize])}
			if _, err := readNamedPipeFrame(context.Background(), transport); !errors.Is(err, ErrNamedPipeProtocol) {
				t.Fatalf("read error = %v", err)
			}
			if transport.readCalls != 1 {
				t.Fatalf("body read calls = %d, want 0", transport.readCalls-1)
			}
		})
	}
}

func TestNamedPipeFrameRejectsTruncatedAndTrailingData(t *testing.T) {
	encoded, err := marshalNamedPipeFrame(namedPipeFrame{Type: pipeMessagePing, Payload: []byte("payload")})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range [][]byte{encoded[:5], encoded[:len(encoded)-1], append(encoded, 0)} {
		if _, err := decodeNamedPipeFrame(candidate); !errors.Is(err, ErrNamedPipeProtocol) {
			t.Fatalf("candidate length %d error = %v", len(candidate), err)
		}
	}
}

func TestNamedPipeControllerFullMappingAndIdle(t *testing.T) {
	registry := testRegistry(t, Limits{})
	attachment, err := registry.newVerifiedTransportAttachment()
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	serverIO := &netFrameIO{Conn: serverConn}
	clientIO := &netFrameIO{Conn: clientConn}
	sender := &fakeNamedPipeDatagramSender{sent: make(chan tgp.TunnelDatagram, 1)}
	session := newNamedPipeControllerSession(serverIO, sender, 100*time.Millisecond)
	serverResult := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		serverResult <- serveNamedPipeController(context.Background(), registry, attachment, serverIO, sender, session, 100*time.Millisecond, 0)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hello, err := readNamedPipeFrame(ctx, clientIO)
	if err != nil || hello.Type != pipeMessageHello || len(hello.Payload) != SessionTokenSize {
		t.Fatalf("hello type=%d length=%d err=%v", hello.Type, len(hello.Payload), err)
	}
	token := append([]byte(nil), hello.Payload...)
	requestID := uint64(1)
	authPayload := appendRequestID(nil, requestID)
	authPayload = append(authPayload, token...)
	clear(token)
	mustPipeStatusOK(t, ctx, clientIO, pipeMessageAuthenticate, requestID, authPayload)

	// The read side has no default idle timeout; operation deadlines apply only
	// to bounded writes and control processing.
	time.Sleep(200 * time.Millisecond)
	requestID++
	pingPayload := appendRequestID(nil, requestID)
	pingPayload = append(pingPayload, "alive"...)
	if err := writeNamedPipeFrame(ctx, clientIO, namedPipeFrame{Type: pipeMessagePing, Payload: pingPayload}); err != nil {
		t.Fatal(err)
	}
	pong, err := readNamedPipeFrame(ctx, clientIO)
	if err != nil || pong.Type != pipeMessagePong || binary.BigEndian.Uint64(pong.Payload[:8]) != requestID || string(pong.Payload[8:]) != "alive" {
		t.Fatalf("pong = %+v err=%v", pong, err)
	}

	requestID++
	prepareData := appendRequestID(nil, requestID)
	prepareData = appendUint64(prepareData, 1)
	transaction := mustPipeResponseData(t, ctx, clientIO, pipeMessagePrepareGeneration, requestID, prepareData)
	requestID++
	abortData := appendRequestID(nil, requestID)
	abortData = append(abortData, transaction...)
	mustPipeStatusOK(t, ctx, clientIO, pipeMessageAbortGeneration, requestID, abortData)

	requestID++
	prepareData = appendRequestID(nil, requestID)
	prepareData = appendUint64(prepareData, 2)
	transaction = mustPipeResponseData(t, ctx, clientIO, pipeMessagePrepareGeneration, requestID, prepareData)
	requestID++
	commitData := appendRequestID(nil, requestID)
	commitData = append(commitData, transaction...)
	mustPipeStatusOK(t, ctx, clientIO, pipeMessageCommitGeneration, requestID, commitData)

	requestID++
	disableData := appendRequestID(nil, requestID)
	disableData = appendUint64(disableData, 2)
	mustPipeStatusOK(t, ctx, clientIO, pipeMessageDisableGeneration, requestID, disableData)

	requestID++
	prepareData = appendRequestID(nil, requestID)
	prepareData = appendUint64(prepareData, 3)
	transaction = mustPipeResponseData(t, ctx, clientIO, pipeMessagePrepareGeneration, requestID, prepareData)
	requestID++
	commitData = appendRequestID(nil, requestID)
	commitData = append(commitData, transaction...)
	mustPipeStatusOK(t, ctx, clientIO, pipeMessageCommitGeneration, requestID, commitData)

	flowSpec := testFlow(1, 3, "10.0.0.2:40000", "203.0.113.9:27015")
	requestID++
	openData, err := encodePipeFlowSpec(requestID, flowSpec)
	if err != nil {
		t.Fatal(err)
	}
	leaseData := mustPipeResponseData(t, ctx, clientIO, pipeMessageOpenFlow, requestID, openData)
	if len(leaseData) != 48 {
		t.Fatalf("lease response length = %d", len(leaseData))
	}
	var lease FlowLease
	copy(lease.FlowID[:], leaseData[:16])
	lease.Generation = binary.BigEndian.Uint64(leaseData[16:24])
	copy(lease.LeaseNonce[:], leaseData[24:40])

	requestID++
	datagramData := appendRequestID(nil, requestID)
	datagramData = append(datagramData, lease.FlowID[:]...)
	datagramData = appendUint64(datagramData, lease.Generation)
	datagramData = append(datagramData, lease.LeaseNonce[:]...)
	datagramData = appendUint64(datagramData, 0)
	datagramData = append(datagramData, "ping"...)
	mustPipeStatusOK(t, ctx, clientIO, pipeMessageDatagram, requestID, datagramData)
	var tunnelDatagram tgp.TunnelDatagram
	select {
	case tunnelDatagram = <-sender.sent:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if string(tunnelDatagram.Payload) != "ping" {
		t.Fatalf("tunnel datagram payload=%q", tunnelDatagram.Payload)
	}
	tunnelDatagram.Payload = []byte("pong")
	deliveryResult := make(chan error, 1)
	go func() { deliveryResult <- session.DeliverReply(ctx, tunnelDatagram) }()
	deliveryFrame, err := readNamedPipeFrame(ctx, clientIO)
	if err != nil || deliveryFrame.Type != pipeMessageDelivery {
		t.Fatalf("delivery frame type=%d err=%v", deliveryFrame.Type, err)
	}
	delivery := deliveryFrame.Payload
	if len(delivery) != 44 || string(delivery[40:]) != "pong" {
		t.Fatalf("delivery length=%d payload=%q", len(delivery), delivery[40:])
	}
	if err := <-deliveryResult; err != nil {
		t.Fatal(err)
	}

	requestID++
	closeFlowData := appendRequestID(nil, requestID)
	closeFlowData = appendUint64(closeFlowData, lease.Generation)
	closeFlowData = append(closeFlowData, lease.FlowID[:]...)
	closeFlowData = append(closeFlowData, lease.LeaseNonce[:]...)
	mustPipeStatusOK(t, ctx, clientIO, pipeMessageCloseFlow, requestID, closeFlowData)
	requestID++
	mustPipeStatusOK(t, ctx, clientIO, pipeMessageCloseConnection, requestID, appendRequestID(nil, requestID))
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	if health := registry.Health(); health.Ready || health.TransportAttached || health.ControllerConnected || health.OpenFlows != 0 {
		t.Fatalf("health after close = %+v", health)
	}
}

func TestNamedPipeSlowReaderTimesOutAndRevokesAttachment(t *testing.T) {
	registry := testRegistry(t, Limits{})
	attachment, err := registry.newVerifiedTransportAttachment()
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	result := make(chan error, 1)
	sender := &fakeNamedPipeDatagramSender{}
	session := newNamedPipeControllerSession(&netFrameIO{Conn: serverConn}, sender, 25*time.Millisecond)
	go func() {
		defer serverConn.Close()
		result <- serveNamedPipeController(context.Background(), registry, attachment, session.transport, sender, session, 25*time.Millisecond, 0)
	}()
	if err := <-result; !errors.Is(err, ErrNamedPipeTimeout) {
		t.Fatalf("slow reader error = %v", err)
	}
	if health := registry.Health(); health.TransportAttached || health.ControllerConnected || health.Ready {
		t.Fatalf("health after slow reader = %+v", health)
	}
}

func FuzzDecodeNamedPipeFrame(f *testing.F) {
	for _, seed := range [][]byte{
		{}, []byte("TCU1"), make([]byte, namedPipeFrameHeaderSize),
		mustNamedPipeFrameSeed(f, pipeMessagePing, []byte("seed")),
		mustNamedPipeFrameSeed(f, pipeMessageDatagram, bytes.Repeat([]byte{1}, 128)),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		frame, err := decodeNamedPipeFrame(encoded)
		if err != nil {
			return
		}
		if len(frame.Payload) > NamedPipeMaxFramePayload || !frame.Type.valid() {
			t.Fatalf("accepted invalid frame type=%d length=%d", frame.Type, len(frame.Payload))
		}
		roundTrip, err := marshalNamedPipeFrame(frame)
		if err != nil || !bytes.Equal(roundTrip, encoded) {
			t.Fatalf("round trip err=%v", err)
		}
	})
}

type countingFrameIO struct {
	reader    io.Reader
	readCalls int
}

func (transport *countingFrameIO) ReadFull(_ context.Context, destination []byte) error {
	transport.readCalls++
	_, err := io.ReadFull(transport.reader, destination)
	return err
}
func (*countingFrameIO) WriteFull(context.Context, []byte) error { return nil }

type netFrameIO struct{ net.Conn }

type fakeNamedPipeDatagramSender struct {
	sent chan tgp.TunnelDatagram
	err  error
}

func (sender *fakeNamedPipeDatagramSender) SendDatagram(_ context.Context, datagram tgp.TunnelDatagram) error {
	if sender.err != nil {
		return sender.err
	}
	if sender.sent != nil {
		sender.sent <- datagram
	}
	return nil
}

func (transport *netFrameIO) ReadFull(ctx context.Context, destination []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = transport.SetReadDeadline(deadline)
	} else {
		_ = transport.SetReadDeadline(time.Time{})
	}
	_, err := io.ReadFull(transport.Conn, destination)
	return err
}

func (transport *netFrameIO) WriteFull(ctx context.Context, source []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = transport.SetWriteDeadline(deadline)
	} else {
		_ = transport.SetWriteDeadline(time.Time{})
	}
	for len(source) != 0 {
		written, err := transport.Write(source)
		if err != nil {
			return err
		}
		source = source[written:]
	}
	return nil
}

func mustPipeStatusOK(t *testing.T, ctx context.Context, transport namedPipeFrameIO, operation namedPipeMessageType, requestID uint64, payload []byte) {
	t.Helper()
	data := mustPipeResponseData(t, ctx, transport, operation, requestID, payload)
	if len(data) != 0 {
		t.Fatalf("operation %d unexpected response data length %d", operation, len(data))
	}
}

func mustPipeResponseData(t *testing.T, ctx context.Context, transport namedPipeFrameIO, operation namedPipeMessageType, requestID uint64, payload []byte) []byte {
	t.Helper()
	if err := writeNamedPipeFrame(ctx, transport, namedPipeFrame{Type: operation, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame, err := readNamedPipeFrame(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	responseID, responseOperation, status, data, err := decodePipeResponse(frame)
	if err != nil {
		t.Fatal(err)
	}
	if responseID != requestID || responseOperation != operation || status != pipeStatusOK {
		t.Fatalf("response id=%d operation=%d status=%d", responseID, responseOperation, status)
	}
	return append([]byte(nil), data...)
}

func mustNamedPipeFrameSeed(tb testing.TB, messageType namedPipeMessageType, payload []byte) []byte {
	tb.Helper()
	encoded, err := marshalNamedPipeFrame(namedPipeFrame{Type: messageType, Payload: payload})
	if err != nil {
		tb.Fatal(err)
	}
	return encoded
}

var _ = netip.AddrPort{}
