package v2rayraw

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type echoHandler struct {
	conns chan net.Conn
}

func (h *echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.conns != nil {
		h.conns <- conn
	}
	defer conn.Close()
	io.Copy(conn, conn)
}

func newTLSPair(t *testing.T) (tls.ServerConfig, tls.Config) {
	t.Helper()
	keyPEM, certPEM, err := tls.GenerateCertificate(nil, nil, time.Now, "example.com", time.Now().Add(time.Hour))
	require.NoError(t, err)
	ctx := context.Background()
	serverConfig, err := tls.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:     true,
		Certificate: []string{string(certPEM)},
		Key:         []string{string(keyPEM)},
	})
	require.NoError(t, err)
	require.NoError(t, serverConfig.Start())
	t.Cleanup(func() { serverConfig.Close() })
	clientConfig, err := tls.NewClient(ctx, logger.NOP(), "example.com", option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "example.com",
		Certificate: []string{string(certPEM)},
	})
	require.NoError(t, err)
	return serverConfig, clientConfig
}

func startRawServer(t *testing.T, serverTLS tls.ServerConfig, handler *echoHandler) M.Socksaddr {
	t.Helper()
	server, err := NewServer(context.Background(), logger.NOP(), option.V2RayRawOptions{}, serverTLS, handler)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		listener.Close()
		server.Close()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Error("Serve did not return after listener close")
		}
	})
	return M.SocksaddrFromNet(listener.Addr())
}

func rawEcho(t *testing.T, client *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	payload := []byte("raw passthrough payload \x00\x01\x02")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)
}

func TestH_RawPlainRoundTrip(t *testing.T) {
	handler := &echoHandler{conns: make(chan net.Conn, 1)}
	addr := startRawServer(t, nil, handler)
	client, err := NewClient(context.Background(), N.SystemDialer, addr, option.V2RayRawOptions{}, nil)
	require.NoError(t, err)
	defer client.Close()
	rawEcho(t, client)
	select {
	case conn := <-handler.conns:
		_, isTCP := conn.(*net.TCPConn)
		require.True(t, isTCP, "plain raw server must hand the unwrapped TCP conn to the handler")
	case <-time.After(time.Second):
		t.Fatal("handler not invoked")
	}
}

func TestH_RawNoFraming(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 5)
		_, err = io.ReadFull(conn, buf)
		if err == nil {
			received <- buf
		}
	}()
	client, err := NewClient(context.Background(), N.SystemDialer, M.SocksaddrFromNet(listener.Addr()), option.V2RayRawOptions{}, nil)
	require.NoError(t, err)
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	select {
	case got := <-received:
		require.Equal(t, []byte("hello"), got)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestH_RawTLSRoundTrip(t *testing.T) {
	serverTLS, clientTLS := newTLSPair(t)
	addr := startRawServer(t, serverTLS, &echoHandler{})
	client, err := NewClient(context.Background(), N.SystemDialer, addr, option.V2RayRawOptions{}, clientTLS)
	require.NoError(t, err)
	rawEcho(t, client)
}

func TestH_RawTLSClientPlainServerFails(t *testing.T) {
	_, clientTLS := newTLSPair(t)
	addr := startRawServer(t, nil, &echoHandler{})
	client, err := NewClient(context.Background(), N.SystemDialer, addr, option.V2RayRawOptions{}, clientTLS)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err == nil {
		conn.Close()
	}
	require.Error(t, err)
}

func TestH_RawServerMeta(t *testing.T) {
	server, err := NewServer(context.Background(), logger.NOP(), option.V2RayRawOptions{}, nil, &echoHandler{})
	require.NoError(t, err)
	require.Equal(t, []string{N.NetworkTCP}, server.Network())
	require.ErrorIs(t, server.ServePacket(nil), os.ErrInvalid)
	require.NoError(t, server.Close())
}
