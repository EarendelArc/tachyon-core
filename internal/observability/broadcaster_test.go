package observability

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBroadcasterServesSSE(t *testing.T) {
	c := NewCollector(&mockPipelineStats{packetsRead: 42}, &mockSessionCounter{count: 0})
	b := NewBroadcaster(BroadcasterOptions{
		Collector:         c,
		Version:           "test",
		TelemetryInterval: 50 * time.Millisecond,
	})
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Start(ctx)

	srv := httptest.NewServer(b)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	// Read the hello event (first event).
	gotHello := false
	timeout := time.After(2 * time.Second)
	for !gotHello {
		select {
		case <-timeout:
			t.Fatal("timed out waiting for hello event")
		default:
		}
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventType := strings.TrimPrefix(line, "event: ")
			if eventType == "hello" {
				gotHello = true
			}
		}
	}
	if !gotHello {
		t.Fatal("did not receive hello event")
	}
}

func TestBroadcasterClientCount(t *testing.T) {
	c := NewCollector(nil, nil)
	b := NewBroadcaster(BroadcasterOptions{Collector: c})
	defer b.Close()

	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", b.ClientCount())
	}

	ch := make(chan Event, 16)
	b.addClient(ch)
	if b.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", b.ClientCount())
	}

	b.removeClient(ch)
	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after remove, got %d", b.ClientCount())
	}
}

func TestBroadcasterBroadcastDropsSlowClients(t *testing.T) {
	c := NewCollector(nil, nil)
	b := NewBroadcaster(BroadcasterOptions{Collector: c})
	defer b.Close()

	ch := make(chan Event, 1)
	b.addClient(ch)

	// Fill the channel.
	b.Broadcast(NewErrorEvent("first", ""))
	// Second broadcast should not block.
	b.Broadcast(NewErrorEvent("second", ""))

	if b.ClientCount() != 1 {
		t.Fatalf("expected 1 client still, got %d", b.ClientCount())
	}
}

func TestBroadcasterClose(t *testing.T) {
	c := NewCollector(nil, nil)
	b := NewBroadcaster(BroadcasterOptions{Collector: c})

	ch := make(chan Event, 16)
	b.addClient(ch)
	b.Close()

	// Channel should be closed after Close.
	_, ok := <-ch
	if ok {
		t.Fatal("expected channel to be closed")
	}
	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after close, got %d", b.ClientCount())
	}
}
