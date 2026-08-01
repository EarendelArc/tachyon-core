package capturedudp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNamedPipeClientReportsFailedStageAndUsesBoundedBackoff(t *testing.T) {
	clientValue, err := newNamedPipeClient(NamedPipeClientConfig{
		Name: `\\.\pipe\Tachyon\health`, ServerSIDs: []string{"S-1-5-18"},
		TrustedServerBinary: "trusted.exe", TrustedServerSHA256: strings.Repeat("0", 64),
		ReconnectMin: 5 * time.Millisecond, ReconnectMax: 10 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := clientValue.(*namedPipeClient)
	var attempts atomic.Uint64
	var timestampsMu sync.Mutex
	var timestamps []time.Time
	client.open = func(context.Context, NamedPipeClientConfig) (namedPipeClientConnection, error) {
		attempts.Add(1)
		timestampsMu.Lock()
		timestamps = append(timestamps, time.Now())
		timestampsMu.Unlock()
		return nil, errors.New("server identity query denied")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- client.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		health := client.Health()
		if health.Attempt >= 3 && health.Stage == "connect_failed" {
			if !strings.Contains(health.LastError, "identity query denied") || health.Reconnects < 3 {
				t.Fatalf("unexpected structured health: %+v", health)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("failed connection health was not observed: %+v", health)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	timestampsMu.Lock()
	defer timestampsMu.Unlock()
	if got := attempts.Load(); got < 3 || got > 4 {
		t.Fatalf("dial attempts = %d, want 3..4", got)
	}
	for index := 1; index < len(timestamps); index++ {
		if delay := timestamps[index].Sub(timestamps[index-1]); delay < 4*time.Millisecond {
			t.Fatalf("retry delay %d = %s, want no busy reconnect loop", index, delay)
		}
	}
}

func TestNextNamedPipeReconnectBackoffIsBounded(t *testing.T) {
	maximum := 10 * time.Millisecond
	if got := nextNamedPipeReconnectBackoff(5*time.Millisecond, maximum); got != maximum {
		t.Fatalf("first backoff = %s, want %s", got, maximum)
	}
	if got := nextNamedPipeReconnectBackoff(maximum, maximum); got != maximum {
		t.Fatalf("bounded backoff = %s, want %s", got, maximum)
	}
	if got := nextNamedPipeReconnectBackoff(maximum-1, maximum); got != maximum {
		t.Fatalf("overflow-safe backoff = %s, want %s", got, maximum)
	}
}

type concurrentClientTransport struct {
	client *namedPipeClient
	mu     sync.Mutex
	ids    []uint64
}

func (transport *concurrentClientTransport) ReadFull(context.Context, []byte) error { return io.EOF }

func (transport *concurrentClientTransport) WriteFull(_ context.Context, wire []byte) error {
	frame, err := decodeNamedPipeFrame(wire)
	if err != nil {
		return err
	}
	requestID := binary.BigEndian.Uint64(frame.Payload[:8])
	transport.mu.Lock()
	transport.ids = append(transport.ids, requestID)
	transport.mu.Unlock()
	go transport.client.resolve(requestID, namedPipeClientResponse{
		operation: frame.Type, status: pipeStatusOK,
	})
	return nil
}

func (transport *concurrentClientTransport) Close() error { return nil }

func TestNamedPipeClientSerializesRequestIDAllocationAndWrite(t *testing.T) {
	clientValue, err := newNamedPipeClient(NamedPipeClientConfig{
		Name: `\\.\pipe\Tachyon\concurrency`, ServerSIDs: []string{"S-1-5-18"},
		TrustedServerBinary: "trusted.exe", TrustedServerSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		MaxPending: 64,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := clientValue.(*namedPipeClient)
	transport := &concurrentClientTransport{client: client}
	client.conn = transport
	client.connected = make(chan struct{})
	close(client.connected)

	const calls = 32
	var wait sync.WaitGroup
	wait.Add(calls)
	for index := 0; index < calls; index++ {
		go func() {
			defer wait.Done()
			if _, err := client.Ping(context.Background(), nil); err != nil {
				t.Errorf("concurrent ping: %v", err)
			}
		}()
	}
	wait.Wait()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.ids) != calls {
		t.Fatalf("recorded request IDs = %d, want %d", len(transport.ids), calls)
	}
	for index, requestID := range transport.ids {
		want := uint64(index + 1)
		if requestID != want {
			t.Fatalf("request ID at index %d = %d, want %d", index, requestID, want)
		}
	}
}

func TestNamedPipeClientCancellationReleasesRequestBoundary(t *testing.T) {
	clientValue, err := newNamedPipeClient(NamedPipeClientConfig{
		Name: `\\.\pipe\Tachyon\cancellation`, ServerSIDs: []string{"S-1-5-18"},
		TrustedServerBinary: "trusted.exe", TrustedServerSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := clientValue.(*namedPipeClient)
	transport := &concurrentClientTransport{client: client}
	client.conn = transport
	client.connected = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Ping(ctx, nil); err == nil {
		t.Fatal("canceled ping unexpectedly succeeded")
	}
	close(client.connected)
	if _, err := client.Ping(context.Background(), nil); err != nil {
		t.Fatalf("request boundary remained locked after cancellation: %v", err)
	}
}
