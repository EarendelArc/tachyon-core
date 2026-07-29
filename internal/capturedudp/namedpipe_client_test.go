package capturedudp

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"testing"
)

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
