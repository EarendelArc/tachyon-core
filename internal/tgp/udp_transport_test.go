package tgp

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestUDPTransportWriteCancelWithoutDeadlineClearsDeadline(t *testing.T) {
	conn := newBlockingWritePacketConn()
	transport := NewUDPTransport(conn)
	remote := mustMultipathUDPAddr(t, "127.0.0.1:443")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- transport.WritePacket(ctx, []byte("blocked"), remote) }()

	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP write did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled write error = %v, want context.Canceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("UDP write did not respond to cancellation")
	}

	if err := transport.WritePacket(context.Background(), []byte("next"), remote); err != nil {
		t.Fatalf("write after cancellation: %v", err)
	}
	if deadline := conn.currentWriteDeadline(); !deadline.IsZero() {
		t.Fatalf("write deadline leaked into subsequent operation: %v", deadline)
	}
}

func TestUDPTransportLocalCancelWithoutDeadlineAndReuse(t *testing.T) {
	receiver, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := receiver.ReadPacket(ctx)
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled read error = %v, want context.Canceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("local UDP read did not respond to cancellation")
	}

	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
	defer readCancel()
	received := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		packet, _, err := receiver.ReadPacket(readCtx)
		if err != nil {
			readErr <- err
			return
		}
		received <- packet
	}()
	if err := sender.WritePacket(context.Background(), []byte("reused"), receiver.LocalAddr()); err != nil {
		t.Fatalf("write after canceled local operation: %v", err)
	}
	select {
	case packet := <-received:
		if string(packet) != "reused" {
			t.Fatalf("received packet = %q", packet)
		}
	case err := <-readErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("timed out reading reused local UDP transport")
	}
}

func TestUDPTransportRepeatedCancelDoesNotAccumulateGoroutines(t *testing.T) {
	transport, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	baseline := runtime.NumGoroutine()
	for iteration := 0; iteration < 100; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, _, err := transport.ReadPacket(ctx)
			done <- err
		}()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("iteration %d: read error = %v", iteration, err)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("iteration %d: cancellation timed out", iteration)
		}
	}
	runtime.Gosched()
	if got := runtime.NumGoroutine(); got > baseline+2 {
		t.Fatalf("goroutines after repeated cancellation = %d, baseline %d", got, baseline)
	}
}

func TestUDPTransportMapsElapsedContextSocketDeadline(t *testing.T) {
	remote := mustMultipathUDPAddr(t, "127.0.0.1:443")
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			conn := &immediateTimeoutPacketConn{}
			transport := NewUDPTransport(conn)
			ctx := &deadlinePendingContext{
				deadline: time.Now().Add(-time.Millisecond),
				done:     make(chan struct{}),
			}

			var err error
			if operation == "read" {
				_, _, err = transport.ReadPacket(ctx)
			} else {
				err = transport.WritePacket(ctx, []byte("packet"), remote)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s error = %v, want context.DeadlineExceeded", operation, err)
			}
		})
	}
}

func TestUDPTransportDoesNotMapIndependentSocketTimeout(t *testing.T) {
	remote := mustMultipathUDPAddr(t, "127.0.0.1:443")
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "no context deadline", ctx: context.Background()},
		{name: "socket timeout before context deadline", ctx: &deadlinePendingContext{
			deadline: time.Now().Add(time.Hour),
			done:     make(chan struct{}),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := NewUDPTransport(&immediateTimeoutPacketConn{})
			err := transport.WritePacket(tt.ctx, []byte("packet"), remote)
			if err == nil {
				t.Fatal("independent socket timeout unexpectedly succeeded")
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("independent socket timeout was mapped to context deadline: %v", err)
			}
		})
	}
}

type deadlinePendingContext struct {
	deadline time.Time
	done     <-chan struct{}
}

func (c *deadlinePendingContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *deadlinePendingContext) Done() <-chan struct{}       { return c.done }
func (c *deadlinePendingContext) Err() error                  { return nil }
func (c *deadlinePendingContext) Value(any) any               { return nil }

type immediateTimeoutPacketConn struct{}

func (*immediateTimeoutPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: testTimeoutError{}}
}
func (*immediateTimeoutPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, &net.OpError{Op: "write", Net: "udp", Err: testTimeoutError{}}
}
func (*immediateTimeoutPacketConn) Close() error                     { return nil }
func (*immediateTimeoutPacketConn) LocalAddr() net.Addr              { return nil }
func (*immediateTimeoutPacketConn) SetDeadline(time.Time) error      { return nil }
func (*immediateTimeoutPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*immediateTimeoutPacketConn) SetWriteDeadline(time.Time) error { return nil }

type blockingWritePacketConn struct {
	mu            sync.Mutex
	writeDeadline time.Time
	writeStarted  chan struct{}
	interrupt     chan struct{}
	interruptOnce sync.Once
	writes        int
}

func newBlockingWritePacketConn() *blockingWritePacketConn {
	return &blockingWritePacketConn{
		writeStarted: make(chan struct{}),
		interrupt:    make(chan struct{}),
	}
}

func (c *blockingWritePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("read not implemented")
}

func (c *blockingWritePacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	c.writes++
	writeNumber := c.writes
	c.mu.Unlock()
	if writeNumber == 1 {
		close(c.writeStarted)
		<-c.interrupt
		return 0, &net.OpError{Op: "write", Net: "udp", Err: testTimeoutError{}}
	}
	return len(packet), nil
}

func (c *blockingWritePacketConn) Close() error { return nil }
func (c *blockingWritePacketConn) LocalAddr() net.Addr {
	return mustMultipathUDPAddrMust("127.0.0.1:10004")
}
func (c *blockingWritePacketConn) SetDeadline(time.Time) error     { return nil }
func (c *blockingWritePacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *blockingWritePacketConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		c.interruptOnce.Do(func() { close(c.interrupt) })
	}
	return nil
}

func (c *blockingWritePacketConn) currentWriteDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDeadline
}

type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "deadline exceeded" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }
