package multiplex

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestSession_LargeTransferBackpressure verifies that a transfer larger than
// maxQueuedBytesPerStream completes correctly: the demux loop applies
// backpressure (cond.Wait) instead of dropping data, and the reader draining
// the stream wakes the blocked loop without deadlock.
func TestSession_LargeTransferBackpressure(t *testing.T) {
	c1, c2 := net.Pipe()

	client, err := NewClientSession(c1)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	server, err := NewServerSession(c2)
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	defer client.Close()
	defer server.Close()

	// Payload bigger than the per-stream backpressure window (4MB).
	const total = 12 * 1024 * 1024
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var writeErr error
	go func() {
		defer wg.Done()
		stream, err := client.OpenStream([]byte("hello"))
		if err != nil {
			writeErr = err
			return
		}
		defer stream.Close()
		if _, err := stream.Write(payload); err != nil {
			writeErr = err
			return
		}
		_ = stream.(interface{ CloseWrite() error }).CloseWrite()
	}()

	var got []byte
	var readErr error
	go func() {
		defer wg.Done()
		stream, openPayload, err := server.AcceptStream()
		if err != nil {
			readErr = err
			return
		}
		if string(openPayload) != "hello" {
			readErr = io.ErrUnexpectedEOF
			return
		}
		got, readErr = io.ReadAll(stream)
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("transfer deadlocked (backpressure did not release)")
	}

	if writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}
