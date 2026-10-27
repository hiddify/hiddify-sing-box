package xhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func hDialerClient(t *testing.T, httpVersion string) *DefaultDialerClient {
	t.Helper()
	options := hOptions(t, `{"mode":"packet-up","path":"/xh"}`)
	return &DefaultDialerClient{
		options:       &options.V2RayXHTTPBaseOptions,
		client:        &http.Client{Timeout: 5 * time.Second},
		httpVersion:   httpVersion,
		uploadRawPool: &sync.Pool{},
	}
}

func hRefusedURL(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	listener.Close()
	return "http://" + address + "/xh/session"
}

// A stream that cannot even connect is reported to the caller instead of
// coming back as a dead reader with no error.
func TestH_XHTTPOpenStreamReportsDialError(t *testing.T) {
	client := hDialerClient(t, "2")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, _, _, err := client.OpenStream(ctx, hRefusedURL(t), "session", nil, false)
	require.Error(t, err)
	if reader != nil {
		reader.Close()
	}
	require.True(t, client.IsClosed())
}

// On HTTP/2 and HTTP/3 a rejected upload (non-200) is an error, as in Xray.
func TestH_XHTTPPostPacketReportsBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	client := hDialerClient(t, "2")
	err := client.PostPacket(context.Background(), server.URL+"/xh/session/0", "session", "0", strings.NewReader("data"), 4)
	require.ErrorContains(t, err, "403")
}

// IsClosed may be read while a stream fails on another goroutine (run with -race).
func TestH_XHTTPClosedFlagRace(t *testing.T) {
	client := hDialerClient(t, "2")
	url := hRefusedURL(t)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(2)
		go func() {
			defer wait.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reader, _, _, _ := client.OpenStream(ctx, url, "session", nil, false)
			if reader != nil {
				reader.Close()
			}
		}()
		go func() {
			defer wait.Done()
			_ = client.IsClosed()
		}()
	}
	wait.Wait()
	_ = option.V2RayXHTTPBaseOptions{}
}
