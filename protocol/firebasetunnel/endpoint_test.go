package firebasetunnel

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestRelayRoundTrip exercises the full chunk relay pipeline end-to-end using
// the fakeFirebaseServer (with SSE). It simulates what handleSession does:
// one side runs runRelay (server), the other side runs runSession (client),
// and bytes must flow both directions correctly.
func TestRelayRoundTrip(t *testing.T) {
	srv := newFakeFirebaseServer()
	defer srv.Close()

	fb := newFirebaseClient(srv.URL, "relay-secret", "", 0, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sessionID := "e2e-relay-test"
	hmacKey := deriveHMACKey("relay-secret")

	// server side: local↔remote pipe; runRelay on remote end
	serverLocal, serverRemote := net.Pipe()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		// runRelay reads c2s from Firebase, writes s2c to Firebase.
		s := &ServerEndpoint{
			fb:             fb,
			pollInterval:   20 * time.Millisecond,
			sessionTimeout: 10 * time.Second,
			logger:         nil,
		}
		s.runRelay(ctx, sessionID, serverRemote, nil, hmacKey)
	}()

	// client side: runSession writes c2s to Firebase, reads s2c from Firebase.
	clientLocal, clientRemote := net.Pipe()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		c := &ClientEndpoint{
			fb:            fb,
			key:           nil,
			hmacKey:       hmacKey,
			batchInterval: 20 * time.Millisecond,
			batchMaxBytes: defaultBatchMaxBytes,
			logger:        nil,
		}
		c.runSession(ctx, sessionID, clientRemote)
	}()

	// Echo goroutine on server's local end: read what server delivers, write it back.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		io.Copy(serverLocal, serverLocal) //nolint:errcheck
	}()

	payload := []byte("hello end-to-end relay")

	// Write from client side.
	if _, err := clientLocal.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// Read from client side (echo comes back via Firebase s2c).
	buf := make([]byte, len(payload))
	clientLocal.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, err := io.ReadFull(clientLocal, buf)
	if err != nil {
		t.Fatalf("client read: %v (got %d bytes)", err, n)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("round-trip mismatch: got %q want %q", buf[:n], payload)
	}

	// Teardown.
	clientLocal.Close()
	serverLocal.Close()
	<-clientDone
	<-serverDone
}

// TestRelayEncryptedRoundTrip is the same as TestRelayRoundTrip but uses PSK encryption.
func TestRelayEncryptedRoundTrip(t *testing.T) {
	srv := newFakeFirebaseServer()
	defer srv.Close()

	fb := newFirebaseClient(srv.URL, "relay-secret", "", 0, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sessionID := "e2e-encrypted-relay-test"
	psk := "e2e-psk"
	key := deriveKey(psk)

	serverLocal, serverRemote := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		s := &ServerEndpoint{
			fb:             fb,
			pollInterval:   20 * time.Millisecond,
			sessionTimeout: 10 * time.Second,
			logger:         nil,
		}
		s.runRelay(ctx, sessionID, serverRemote, &key, nil)
	}()

	clientLocal, clientRemote := net.Pipe()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		c := &ClientEndpoint{
			fb:            fb,
			key:           &key,
			hmacKey:       nil,
			batchInterval: 20 * time.Millisecond,
			batchMaxBytes: defaultBatchMaxBytes,
			logger:        nil,
		}
		c.runSession(ctx, sessionID, clientRemote)
	}()

	go io.Copy(serverLocal, serverLocal) //nolint:errcheck

	payload := []byte("encrypted end-to-end relay")
	if _, err := clientLocal.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, len(payload))
	clientLocal.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, err := io.ReadFull(clientLocal, buf)
	if err != nil {
		t.Fatalf("client read: %v (got %d bytes)", err, n)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("round-trip mismatch: got %q want %q", buf[:n], payload)
	}

	clientLocal.Close()
	serverLocal.Close()
	<-clientDone
	<-serverDone
}
