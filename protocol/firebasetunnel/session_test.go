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
	mu   sync.Mutex
	data map[string]json.RawMessage
}

func newFakeFirebaseServer() *httptest.Server {
	f := &fakeFirebaseServer{data: make(map[string]json.RawMessage)}
	return httptest.NewServer(http.HandlerFunc(f.handle))
}

func (f *fakeFirebaseServer) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")
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
		w.Write([]byte("{}"))
	case http.MethodDelete:
		delete(f.data, path)
		w.Write([]byte("null"))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestChunkSenderReceiverRoundTrip(t *testing.T) {
	srv := newFakeFirebaseServer()
	defer srv.Close()

	fb := newFirebaseClient(srv.URL, "test-secret", "", 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	queuePath := "sessions/test/c2s"
	sender := newChunkSender(ctx, queuePath, fb, 20*time.Millisecond, 1024, nil, nil)

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

	receiver, byteRx := newChunkReceiver(nil)
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

	key := deriveKey("shared-psk")
	queuePath := "sessions/test2/c2s"
	sender := newChunkSender(ctx, queuePath, fb, 20*time.Millisecond, 1024, &key, nil)

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
	receiverWrong, _ := newChunkReceiver(&wrongKey)
	if _, err := receiverWrong.ingest(ctx, chunks[0]); err == nil {
		t.Fatal("expected ingest failure with wrong key")
	}

	// Correct key must succeed.
	receiver, byteRx := newChunkReceiver(&key)
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

func TestChunkReceiverOutOfOrder(t *testing.T) {
	ctx := context.Background()
	receiver, byteRx := newChunkReceiver(nil)

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
	receiver, byteRx := newChunkReceiver(nil)

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
	sender := newChunkSender(ctx, "sessions/x/c2s", fb, time.Hour, 1<<30, nil, nil)

	big := make([]byte, maxPendingBytes)
	if err := sender.feed(ctx, big); err != nil {
		t.Fatalf("first feed should succeed: %v", err)
	}
	if err := sender.feed(ctx, []byte("more")); err == nil {
		t.Fatal("expected backpressure error once pending budget exceeded")
	}
}

func encodeRaw(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
