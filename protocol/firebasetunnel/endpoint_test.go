package firebasetunnel

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestRelayRoundTrip exercises the full chunk relay pipeline end-to-end.
// It uses the relay (server) and session (client) helpers directly against
// the fakeFirebaseServer with SSE support.
func TestRelayRoundTrip(t *testing.T) {
	srv := newFakeFirebaseServer()
	defer srv.Close()

	fb := newFirebaseClient(srv.URL, "relay-secret", "", 0, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sessionID := "e2e-relay-test"
	hmacKey := deriveHMACKey("relay-secret")

	// server side: local↔remote pipe; inbound runRelay on remote end
	serverLocal, serverRemote := net.Pipe()

	inb := &Inbound{
		fb:           fb,
		pollInterval: 20 * time.Millisecond,
		sessionTimeout: 10 * time.Second,
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		inb.runRelay(ctx, sessionID, serverRemote, nil, hmacKey)
	}()

	// client side: outbound runSession writes c2s, reads s2c
	clientLocal, clientRemote := net.Pipe()

	out := &Outbound{
		fb:            fb,
		key:           nil,
		hmacKey:       hmacKey,
		batchInterval: 20 * time.Millisecond,
		batchMaxBytes: defaultBatchMaxBytes,
	}

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		out.runSession(ctx, sessionID, clientRemote)
	}()

	// Echo goroutine on server's local end.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		io.Copy(serverLocal, serverLocal) //nolint:errcheck
	}()

	payload := []byte("hello end-to-end relay")

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

	inb := &Inbound{
		fb:             fb,
		pollInterval:   20 * time.Millisecond,
		sessionTimeout: 10 * time.Second,
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		inb.runRelay(ctx, sessionID, serverRemote, &key, nil)
	}()

	clientLocal, clientRemote := net.Pipe()

	out := &Outbound{
		fb:            fb,
		key:           &key,
		hmacKey:       nil,
		batchInterval: 20 * time.Millisecond,
		batchMaxBytes: defaultBatchMaxBytes,
	}

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		out.runSession(ctx, sessionID, clientRemote)
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
