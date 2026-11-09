package xhttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A multiplexer (sing-mux) dials with a short context and cancels it once the dial returns. The
// connection must keep working after that: its lifetime ends with Close, not with the dial context.
func TestH_XHTTPConnOutlivesDialContext(t *testing.T) {
	for _, testCase := range []struct {
		name string
		mode string
		alpn []string
	}{
		{"packet-up h1", "packet-up", nil},
		{"packet-up h2", "packet-up", []string{"h2"}},
		{"stream-up h2", "stream-up", []string{"h2"}},
		{"stream-one h2", "stream-one", []string{"h2"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			content := `{"mode":"` + testCase.mode + `","path":"/xh"}`
			var serverTLS tls.ServerConfig
			var clientTLS tls.Config
			if testCase.alpn != nil {
				serverTLS, clientTLS = hNewTLSPair(t, testCase.alpn)
			}
			addr := hStartServer(t, hOptions(t, content), serverTLS)
			transport, err := NewClient(context.Background(), N.SystemDialer, addr, hOptions(t, content), clientTLS)
			require.NoError(t, err)
			defer transport.Close()

			dialCtx, cancelDial := context.WithTimeout(context.Background(), 4*time.Second)
			conn, err := transport.DialContext(dialCtx)
			cancelDial() // what sing-mux does right after a successful dial
			require.NoError(t, err)
			defer conn.Close()

			payload := []byte("after the dial context is gone")
			_, err = conn.Write(payload)
			require.NoError(t, err)
			received := make([]byte, len(payload))
			readErr := make(chan error, 1)
			go func() { // splitConn has no read deadline
				_, err := io.ReadFull(conn, received)
				readErr <- err
			}()
			select {
			case err = <-readErr:
			case <-time.After(4 * time.Second):
				t.Fatal("no echo")
			}
			require.NoError(t, err)
			require.True(t, bytes.Equal(payload, received))
		})
	}
}

// When the dial context ends before the HTTP connection is up, OpenStream returns its error,
// never a nil error with nil addresses: sing-mux panics on a net.Conn with a nil address.
func TestH_XHTTPOpenStreamDialContextEndsFirst(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	client := hDialerClient(t, "1.1")
	client.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-release // a peer that never answers
			return nil, net.ErrClosed
		},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	reader, remoteAddr, localAddr, err := client.OpenStream(ctx, "http://192.0.2.1/xh/session", "session", nil, false)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, reader)
	require.Nil(t, remoteAddr)
	require.Nil(t, localAddr)
}

// Through the whole client: a stalled dial gives DialContext an error, not a conn without addresses.
func TestH_XHTTPDialContextStalledPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	var accepted []net.Conn
	var access sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			access.Lock()
			accepted = append(accepted, conn) // accepted, never answered: TLS stalls
			access.Unlock()
		}
	}()
	defer func() {
		access.Lock()
		defer access.Unlock()
		for _, conn := range accepted {
			conn.Close()
		}
	}()

	_, clientTLS := hNewTLSPair(t, []string{"h2"})
	content := `{"mode":"packet-up","path":"/xh"}`
	addr := M.SocksaddrFromNet(listener.Addr())
	transport, err := NewClient(context.Background(), N.SystemDialer, addr, hOptions(t, content), clientTLS)
	require.NoError(t, err)
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	conn, err := transport.DialContext(ctx)
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err)
	require.Nil(t, conn)
}
