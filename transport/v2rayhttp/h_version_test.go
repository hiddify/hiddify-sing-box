package v2rayhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

type hEchoHandler struct {
	conns chan net.Conn
}

func (h *hEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.conns != nil {
		select {
		case h.conns <- conn:
		default:
		}
	}
	buffer := make([]byte, 1024)
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	n, err := conn.Read(buffer)
	if err == nil {
		conn.Write(buffer[:n])
	}
	conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func hNewTLSPair(t *testing.T, serverALPN []string, clientALPN []string) (tls.ServerConfig, tls.Config) {
	t.Helper()
	keyPEM, certPEM, err := tls.GenerateCertificate(nil, nil, time.Now, "example.com", time.Now().Add(time.Hour))
	require.NoError(t, err)
	ctx := context.Background()
	serverConfig, err := tls.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:     true,
		ALPN:        serverALPN,
		Certificate: []string{string(certPEM)},
		Key:         []string{string(keyPEM)},
	})
	require.NoError(t, err)
	require.NoError(t, serverConfig.Start())
	t.Cleanup(func() { serverConfig.Close() })
	clientConfig, err := tls.NewClient(ctx, logger.NOP(), "example.com", option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "example.com",
		ALPN:        clientALPN,
		Certificate: []string{string(certPEM)},
	})
	require.NoError(t, err)
	return serverConfig, clientConfig
}

func hNewClient(t *testing.T, options option.V2RayHTTPOptions, tlsConfig tls.Config) *Client {
	t.Helper()
	transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), options, tlsConfig)
	require.NoError(t, err)
	return transport.(*Client)
}

func TestH_HTTPClientVersionSelection(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		client := hNewClient(t, option.V2RayHTTPOptions{}, nil)
		require.False(t, client.http2)
		require.False(t, client.MultiplexEnabled())
		require.Equal(t, "http", client.requestURL.Scheme)
		require.IsType(t, &http.Transport{}, client.transport.Load())
	})
	t.Run("plain version 2 stays http1", func(t *testing.T) {
		client := hNewClient(t, option.V2RayHTTPOptions{Version: 2}, nil)
		require.False(t, client.http2)
	})
	for _, version := range []int{0, 2} {
		_, clientTLS := hNewTLSPair(t, nil, nil)
		client := hNewClient(t, option.V2RayHTTPOptions{Version: version}, clientTLS)
		require.True(t, client.http2, "version %d", version)
		require.True(t, client.MultiplexEnabled())
		require.Equal(t, "https", client.requestURL.Scheme)
		require.IsType(t, &http2.Transport{}, client.transport.Load())
		require.Equal(t, []string{http2.NextProtoTLS}, clientTLS.NextProtos())
	}
	t.Run("tls version 1", func(t *testing.T) {
		_, clientTLS := hNewTLSPair(t, nil, nil)
		client := hNewClient(t, option.V2RayHTTPOptions{Version: 1}, clientTLS)
		require.False(t, client.http2)
		require.False(t, client.MultiplexEnabled())
		require.Equal(t, "https", client.requestURL.Scheme)
		require.IsType(t, &http.Transport{}, client.transport.Load())
		require.Equal(t, []string{"http/1.1"}, clientTLS.NextProtos())
		_, isTLSDialer := client.dialer.(tls.Dialer)
		require.True(t, isTLSDialer, "version 1 over TLS must wrap the dialer with TLS")
	})
	t.Run("tls version 1 keeps explicit alpn", func(t *testing.T) {
		_, clientTLS := hNewTLSPair(t, nil, []string{"custom"})
		hNewClient(t, option.V2RayHTTPOptions{Version: 1}, clientTLS)
		require.Equal(t, []string{"custom"}, clientTLS.NextProtos())
	})
}

func TestH_HTTPClientHeaders(t *testing.T) {
	client := hNewClient(t, option.V2RayHTTPOptions{
		Path: "tunnel",
		Headers: badoption.HTTPHeader{
			"Host":    {"front.example.com"},
			"X-Extra": {"1"},
		},
	}, nil)
	require.Equal(t, "front.example.com", client.requestURL.Host)
	require.Equal(t, "/tunnel", client.requestURL.Path)
	require.Empty(t, client.headers.Get("Host"))
	require.Equal(t, "1", client.headers.Get("X-Extra"))
	require.Equal(t, C.DefaultBrowserAgent, client.headers.Get("User-Agent"))
	require.Equal(t, http.MethodPut, client.method)

	client = hNewClient(t, option.V2RayHTTPOptions{
		Headers: badoption.HTTPHeader{"User-Agent": {"custom-agent"}},
	}, nil)
	require.Equal(t, "custom-agent", client.headers.Get("User-Agent"))
	require.Equal(t, "127.0.0.1:443", client.requestURL.Host)
}

func hServeOnce(t *testing.T, server *Server) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		server.Serve(listener)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, server.Close())
	listener.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestH_HTTPServerVersionALPN(t *testing.T) {
	cases := []struct {
		name     string
		version  int
		preset   []string
		expected []string
	}{
		{"default", 0, nil, []string{http2.NextProtoTLS, "http/1.1"}},
		{"version 2", 2, nil, []string{http2.NextProtoTLS, "http/1.1"}},
		{"version 1", 1, nil, []string{"http/1.1"}},
		{"version 1 keeps explicit alpn", 1, []string{"custom"}, []string{"custom"}},
		{"default prepends h2", 0, []string{"http/1.1"}, []string{http2.NextProtoTLS, "http/1.1"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			serverTLS, _ := hNewTLSPair(t, testCase.preset, nil)
			server, err := NewServer(context.Background(), logger.NOP(), option.V2RayHTTPOptions{Version: testCase.version}, serverTLS, &hEchoHandler{})
			require.NoError(t, err)
			require.Equal(t, testCase.version, server.version)
			hServeOnce(t, server)
			require.Equal(t, testCase.expected, serverTLS.NextProtos())
		})
	}
}

func hStartServer(t *testing.T, options option.V2RayHTTPOptions, serverTLS tls.ServerConfig, handler *hEchoHandler) M.Socksaddr {
	t.Helper()
	server, err := NewServer(context.Background(), logger.NOP(), options, serverTLS, handler)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Close()
		listener.Close()
	})
	return M.SocksaddrFromNet(listener.Addr())
}

func hEcho(t *testing.T, transport *Client) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := transport.DialContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload := []byte("v2ray http version payload")
	_, err = conn.Write(payload)
	if err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, reply)
		readDone <- err
	}()
	select {
	case err = <-readDone:
	case <-time.After(4 * time.Second):
		conn.Close()
		return context.DeadlineExceeded
	}
	if err != nil {
		return err
	}
	require.Equal(t, payload, reply)
	return nil
}

func TestH_HTTPVersion1OverTLSUsesHTTP1(t *testing.T) {
	serverTLS, clientTLS := hNewTLSPair(t, nil, nil)
	handler := &hEchoHandler{conns: make(chan net.Conn, 1)}
	addr := hStartServer(t, option.V2RayHTTPOptions{Version: 1}, serverTLS, handler)
	transport, err := NewClient(context.Background(), N.SystemDialer, addr, option.V2RayHTTPOptions{Version: 1}, clientTLS)
	require.NoError(t, err)
	defer transport.Close()
	require.NoError(t, hEcho(t, transport.(*Client)))
	select {
	case conn := <-handler.conns:
		_, isH2 := conn.(*HTTP2ConnWrapper)
		require.False(t, isH2, "server must take the HTTP/1.1 hijack path")
	case <-time.After(time.Second):
		t.Fatal("handler not invoked")
	}
}

func TestH_HTTPVersion2OverTLSUsesH2(t *testing.T) {
	serverTLS, clientTLS := hNewTLSPair(t, nil, nil)
	handler := &hEchoHandler{conns: make(chan net.Conn, 1)}
	addr := hStartServer(t, option.V2RayHTTPOptions{}, serverTLS, handler)
	transport, err := NewClient(context.Background(), N.SystemDialer, addr, option.V2RayHTTPOptions{Version: 2}, clientTLS)
	require.NoError(t, err)
	defer transport.Close()
	require.NoError(t, hEcho(t, transport.(*Client)))
	select {
	case conn := <-handler.conns:
		require.IsType(t, &HTTP2ConnWrapper{}, conn)
	case <-time.After(time.Second):
		t.Fatal("handler not invoked")
	}
}

func TestH_HTTPVersionMismatchFails(t *testing.T) {
	serverTLS, clientTLS := hNewTLSPair(t, nil, nil)
	addr := hStartServer(t, option.V2RayHTTPOptions{Version: 1}, serverTLS, &hEchoHandler{})
	transport, err := NewClient(context.Background(), N.SystemDialer, addr, option.V2RayHTTPOptions{Version: 2}, clientTLS)
	require.NoError(t, err)
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := transport.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()
	readDone := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err = <-readDone:
		require.Error(t, err)
	case <-time.After(4 * time.Second):
		t.Fatal("h2-only client against http/1.1-only server must fail the handshake")
	}
}
