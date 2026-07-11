package firebasetunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFirebaseServer is a minimal in-memory stand-in for the Firebase RTDB
// REST API, sufficient for exercising chunkSender/chunkReceiver against a
// real *firebaseClient without network access.
type fakeFirebaseServer struct {
	mu        sync.Mutex
	data      map[string]json.RawMessage
	listeners []chan struct{}
}

func newFakeFirebaseServer() *httptest.Server {
	f := &fakeFirebaseServer{data: make(map[string]json.RawMessage)}
	return httptest.NewServer(http.HandlerFunc(f.handle))
}

func (f *fakeFirebaseServer) notifyListeners() {
	for _, ch := range f.listeners {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (f *fakeFirebaseServer) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")

	// SSE streaming endpoint.
	if r.Method == http.MethodGet && r.Header.Get("Accept") == "text/event-stream" {
		notify := make(chan struct{}, 4)
		f.mu.Lock()
		f.listeners = append(f.listeners, notify)
		// Send initial state.
		snapshot, _ := json.Marshal(f.buildSnapshot())
		f.mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		// Firebase SSE format.
		_, _ = w.Write([]byte("event: put\ndata: {\"path\":\"/\",\"data\":" + string(snapshot) + "}\n\n"))
		flusher.Flush()

		for {
			select {
			case <-notify:
				f.mu.Lock()
				snap, _ := json.Marshal(f.buildSnapshot())
				f.mu.Unlock()
				_, _ = w.Write([]byte("event: put\ndata: {\"path\":\"/\",\"data\":" + string(snap) + "}\n\n"))
				flusher.Flush()
			case <-r.Context().Done():
				f.mu.Lock()
				listeners := f.listeners[:0]
				for _, ch := range f.listeners {
					if ch != notify {
						listeners = append(listeners, ch)
					}
				}
				f.listeners = listeners
				f.mu.Unlock()
				return
			}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		if v, ok := f.data[path]; ok {
			w.Write(v)
			return
		}
		w.Write([]byte("null"))
	case http.MethodPut:
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		f.data[path] = json.RawMessage(body)
		f.notifyListeners()
		w.Write([]byte("{}"))
	case http.MethodDelete:
		delete(f.data, path)
		w.Write([]byte("null"))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// buildSnapshot returns the top-level "sessions" map for SSE payloads.
// Must be called with f.mu held.
func (f *fakeFirebaseServer) buildSnapshot() map[string]json.RawMessage {
	out := make(map[string]json.RawMessage)
	for k, v := range f.data {
		out[k] = v
	}
	return out
}

func TestChunkSenderReceiverRoundTrip(t *testing.T) {
	srv := newFakeFirebaseServer()
	defer srv.Close()

	fb := newFirebaseClient(srv.URL, "test-secret", "", 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessionID := "test-session"
	queuePath := "sessions/" + sessionID + "/c2s"
	sender := newChunkSender(ctx, queuePath, sessionID, "c2s", fb, 20*time.Millisecond, 1024, nil, nil, nil)

	payload := []byte("hello firebase tunnel")
	if err := sender.feed(ctx, payload); err != nil {
		t.Fatalf("feed: %v", err)
	}

	// Wait for the flusher to write the chunk.
	time.Sleep(100 * time.Millisecond)

	chunks, err := fetchNewChunks(ctx, fb, queuePath, nil)
	if err != nil {
		t.Fatalf("fetchNewChunks: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}

	receiver, byteRx := newChunkReceiver(nil, nil, sessionID, "c2s")
	if _, err := receiver.ingest(ctx, chunks[0]); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	select {
	case data := <-byteRx:
		if string(data) != string(payload) {
			t.Fatalf("got %q want %q", data, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reassembled bytes")
	}
}

func TestChunkSenderEncrypted(t *testing.T) {
	srv := newFakeFirebaseServer()
	defer srv.Close()

	fb := newFirebaseClient(srv.URL, "test-secret", "", 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessionID := "test-session-2"
	key := deriveKey("shared-psk")
	queuePath := "sessions/" + sessionID + "/c2s"
	sender := newChunkSender(ctx, queuePath, sessionID, "c2s", fb, 20*time.Millisecond, 1024, &key, nil, nil)

	payload := []byte("encrypted payload bytes")
	if err := sender.feed(ctx, payload); err != nil {
		t.Fatalf("feed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	chunks, err := fetchNewChunks(ctx, fb, queuePath, nil)
	if err != nil {
		t.Fatalf("fetchNewChunks: %v", err)
	}
	if len(chunks) != 1 || !chunks[0].Encrypted {
		t.Fatalf("expected 1 encrypted chunk, got %+v", chunks)
	}

	// Wrong key must fail to decrypt.
	wrongKey := deriveKey("wrong-psk")
	receiverWrong, _ := newChunkReceiver(&wrongKey, nil, sessionID, "c2s")
	if _, err := receiverWrong.ingest(ctx, chunks[0]); err == nil {
		t.Fatal("expected ingest failure with wrong key")
	}

	// Correct key must succeed.
	receiver, byteRx := newChunkReceiver(&key, nil, sessionID, "c2s")
	if _, err := receiver.ingest(ctx, chunks[0]); err != nil {
		t.Fatalf("ingest with correct key: %v", err)
	}
	select {
	case data := <-byteRx:
		if string(data) != string(payload) {
			t.Fatalf("got %q want %q", data, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reassembled bytes")
	}
}

func TestChunkSenderHMAC(t *testing.T) {
	srv := newFakeFirebaseServer()
	defer srv.Close()

	fb := newFirebaseClient(srv.URL, "test-secret", "", 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessionID := "test-hmac"
	hmacKey := deriveHMACKey("test-secret")
	queuePath := "sessions/" + sessionID + "/c2s"
	sender := newChunkSender(ctx, queuePath, sessionID, "c2s", fb, 20*time.Millisecond, 1024, nil, hmacKey, nil)

	payload := []byte("hmac protected payload")
	if err := sender.feed(ctx, payload); err != nil {
		t.Fatalf("feed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	chunks, err := fetchNewChunks(ctx, fb, queuePath, nil)
	if err != nil {
		t.Fatalf("fetchNewChunks: %v", err)
	}
	if len(chunks) != 1 || !chunks[0].HasHMAC {
		t.Fatalf("expected 1 HMAC chunk, got %+v", chunks)
	}

	// Wrong HMAC key must fail.
	wrongHMACKey := deriveHMACKey("wrong-secret")
	receiverWrong, _ := newChunkReceiver(nil, wrongHMACKey, sessionID, "c2s")
	if _, err := receiverWrong.ingest(ctx, chunks[0]); err == nil {
		t.Fatal("expected ingest failure with wrong HMAC key")
	}

	// Correct HMAC key must succeed.
	receiver, byteRx := newChunkReceiver(nil, hmacKey, sessionID, "c2s")
	if _, err := receiver.ingest(ctx, chunks[0]); err != nil {
		t.Fatalf("ingest with correct hmac key: %v", err)
	}
	select {
	case data := <-byteRx:
		if string(data) != string(payload) {
			t.Fatalf("got %q want %q", data, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reassembled bytes")
	}
}

func TestChunkAADBinding(t *testing.T) {
	// A chunk encrypted for session A / direction c2s / seq 0 must not decrypt
	// if the receiver uses a different sessionID, direction, or seq.
	key := deriveKey("binding-psk")
	sessionID := "session-a"
	payload := []byte("aad binding test")

	aad := chunkAAD(sessionID, "c2s", 0)
	ct, err := encryptPayloadAAD(key, payload, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Wrong session ID.
	wrongAAD := chunkAAD("session-b", "c2s", 0)
	if _, err := decryptPayloadAAD(key, ct, wrongAAD); err == nil {
		t.Fatal("expected failure with wrong sessionID in AAD")
	}

	// Wrong direction.
	wrongDir := chunkAAD(sessionID, "s2c", 0)
	if _, err := decryptPayloadAAD(key, ct, wrongDir); err == nil {
		t.Fatal("expected failure with wrong direction in AAD")
	}

	// Wrong seq.
	wrongSeq := chunkAAD(sessionID, "c2s", 1)
	if _, err := decryptPayloadAAD(key, ct, wrongSeq); err == nil {
		t.Fatal("expected failure with wrong seq in AAD")
	}

	// Correct AAD must succeed.
	pt, err := decryptPayloadAAD(key, ct, aad)
	if err != nil {
		t.Fatalf("correct AAD failed: %v", err)
	}
	if string(pt) != string(payload) {
		t.Fatalf("got %q want %q", pt, payload)
	}
}

func TestChunkReceiverOutOfOrder(t *testing.T) {
	ctx := context.Background()
	receiver, byteRx := newChunkReceiver(nil, nil, "sid", "c2s")

	c1 := chunk{Seq: 1, Data: encodeRaw([]byte("b"))}
	c0 := chunk{Seq: 0, Data: encodeRaw([]byte("a"))}

	// Deliver seq=1 first; nothing should drain yet.
	if _, err := receiver.ingest(ctx, c1); err != nil {
		t.Fatalf("ingest c1: %v", err)
	}
	select {
	case data := <-byteRx:
		t.Fatalf("unexpected early delivery: %q", data)
	default:
	}

	// Now deliver seq=0; both should drain in order.
	if _, err := receiver.ingest(ctx, c0); err != nil {
		t.Fatalf("ingest c0: %v", err)
	}
	first := <-byteRx
	second := <-byteRx
	if string(first) != "a" || string(second) != "b" {
		t.Fatalf("got %q, %q; want a, b", first, second)
	}
}

func TestChunkReceiverDuplicateIgnored(t *testing.T) {
	ctx := context.Background()
	receiver, byteRx := newChunkReceiver(nil, nil, "sid", "c2s")

	c0 := chunk{Seq: 0, Data: encodeRaw([]byte("a"))}
	if _, err := receiver.ingest(ctx, c0); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	<-byteRx

	// Re-ingesting the same seq must not deliver again.
	if _, err := receiver.ingest(ctx, c0); err != nil {
		t.Fatalf("ingest duplicate: %v", err)
	}
	select {
	case data := <-byteRx:
		t.Fatalf("unexpected duplicate delivery: %q", data)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSenderBackpressure(t *testing.T) {
	srv := newFakeFirebaseServer()
	defer srv.Close()
	fb := newFirebaseClient(srv.URL, "secret", "", 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Long batch interval so nothing flushes during the test.
	sender := newChunkSender(ctx, "sessions/x/c2s", "x", "c2s", fb, time.Hour, 1<<30, nil, nil, nil)

	big := make([]byte, maxPendingBytes)
	if err := sender.feed(ctx, big); err != nil {
		t.Fatalf("first feed should succeed: %v", err)
	}
	if err := sender.feed(ctx, []byte("more")); err == nil {
		t.Fatal("expected backpressure error once pending budget exceeded")
	}
}

func TestChunkSizeCapRejected(t *testing.T) {
	ctx := context.Background()
	receiver, _ := newChunkReceiver(nil, nil, "sid", "c2s")

	// Craft a chunk whose Data field exceeds the encoded size cap.
	oversized := make([]byte, maxChunkBytes+1)
	c := chunk{Seq: 0, Data: base64.StdEncoding.EncodeToString(oversized)}
	if _, err := receiver.ingest(ctx, c); err == nil {
		t.Fatal("expected error for oversized chunk")
	}
}

func encodeRaw(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
