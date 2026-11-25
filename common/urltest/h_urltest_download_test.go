package urltest

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const downloadTestSize = 64 << 10

// downloadHandler answers with downloadTestSize bytes, written by send.
func downloadHandler(t *testing.T, send func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Empty(t, r.Header.Get("Accept-Encoding"), "the body is asked for as it is")
		w.Header().Set("Content-Length", strconv.Itoa(downloadTestSize))
		send(w, r)
	})
}

func whole(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(make([]byte, downloadTestSize)) }

// frozen sends the first 16 KiB and then nothing, keeping the connection: a censor's freeze.
func frozen(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write(make([]byte, 16<<10))
	w.(http.Flusher).Flush()
	<-r.Context().Done()
}

// slow sends the body 4 KiB at a time, a gap of 50ms between them: 800ms for all of it.
func slow(w http.ResponseWriter, r *http.Request) {
	for sent := 0; sent < downloadTestSize; sent += 4 << 10 {
		_, _ = w.Write(make([]byte, 4<<10))
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
	}
}

// reset sends the first 16 KiB and then resets the connection, as some censors do instead.
func reset(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write(make([]byte, 16<<10))
	w.(http.Flusher).Flush()
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	_ = conn.(*net.TCPConn).SetLinger(0)
	_ = conn.Close()
}

// silent answers nothing until the client gives up: a download server unreachable from the exit.
func silent(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

func status(code int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://portal.example/")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(code)
	}
}

func TestH_URLTestDownload(t *testing.T) {
	tests := []struct {
		name         string
		send         func(w http.ResponseWriter, r *http.Request)
		err          string
		inconclusive bool
	}{
		{name: "the whole body arrives", send: whole},
		{name: "a slow body whose bytes keep coming passes", send: slow},
		{name: "a connection frozen after 16 KiB fails", send: frozen, err: "download stalled after 16384 bytes"},
		{name: "a connection reset after 16 KiB fails", send: reset, err: "download stalled after 16384 bytes"},
		{name: "a rate limit tells nothing", send: status(http.StatusTooManyRequests), err: "429", inconclusive: true},
		{name: "a redirect tells nothing", send: status(http.StatusFound), err: "302", inconclusive: true},
		{name: "no answer before the deadline tells nothing", send: silent, err: "deadline", inconclusive: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(downloadHandler(t, test.send))
			t.Cleanup(server.Close)
			dialer := &loopbackDialer{addr: server.Listener.Addr().String()}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := URLTestDownload(ctx, "http://download.example/__down", dialer, 300*time.Millisecond)
			if test.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.err)
			require.Equal(t, test.inconclusive, errors.Is(err, ErrDownloadInconclusive))
		})
	}
}

// The download goes to the host and port of its URL, over TLS for https, checked against the
// root certificates of the context.
func TestH_URLTestDownloadHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(downloadHandler(t, whole))
	t.Cleanup(server.Close)
	dialer := &recordingDialer{loopbackDialer: loopbackDialer{addr: server.Listener.Addr().String()}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := URLTestDownload(ctx, "https://example.com/__down", dialer, time.Second)
	require.ErrorContains(t, err, "certificate")
	require.ErrorIs(t, err, ErrDownloadInconclusive, "no body: it tells nothing of the outbound")
	require.Equal(t, "example.com:443", dialer.destination.String())

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	trusted := service.ContextWith[adapter.CertificateStore](ctx, testCertificateStore{roots})
	require.NoError(t, URLTestDownload(trusted, "https://example.com/__down", dialer, time.Second))

	plain := httptest.NewServer(downloadHandler(t, whole))
	t.Cleanup(plain.Close)
	dialer = &recordingDialer{loopbackDialer: loopbackDialer{addr: plain.Listener.Addr().String()}}
	require.NoError(t, URLTestDownload(ctx, "http://example.com/__down", dialer, time.Second))
	require.Equal(t, "example.com:80", dialer.destination.String())
}

func TestH_URLTestDownloadDialFailureTellsNothing(t *testing.T) {
	dialer := &loopbackDialer{addr: "127.0.0.1:1"}
	err := URLTestDownload(context.Background(), "http://download.example/__down", dialer, time.Second)
	require.ErrorIs(t, err, ErrDownloadInconclusive)
}

func TestH_URLTestDownloadNilDialer(t *testing.T) {
	require.Error(t, URLTestDownload(context.Background(), "http://127.0.0.1/", nil, time.Second))
}

type recordingDialer struct {
	loopbackDialer
	destination M.Socksaddr
}

func (d *recordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.destination = destination
	return d.loopbackDialer.DialContext(ctx, network, destination)
}

type testCertificateStore struct{ pool *x509.CertPool }

func (s testCertificateStore) Name() string                                   { return "test" }
func (s testCertificateStore) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (s testCertificateStore) Close() error                                   { return nil }
func (s testCertificateStore) Pool() *x509.CertPool                           { return s.pool }
func (s testCertificateStore) ExclusiveAnchors() bool                         { return true }
