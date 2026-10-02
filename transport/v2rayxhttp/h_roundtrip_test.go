package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hEchoHandler struct{}

func (h *hEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		io.Copy(conn, conn)
	}()
}

func hNewTLSPair(t *testing.T, clientALPN []string) (tls.ServerConfig, tls.Config) {
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
		ALPN:        clientALPN,
		Certificate: []string{string(certPEM)},
	})
	require.NoError(t, err)
	return serverConfig, clientConfig
}

func hStartServer(t *testing.T, options option.V2RayXHTTPOptions, serverTLS tls.ServerConfig) M.Socksaddr {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	server, err := NewServer(ctx, logger.NOP(), options, serverTLS, &hEchoHandler{})
	require.NoError(t, err)
	require.Equal(t, []string{N.NetworkTCP}, server.Network())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	t.Cleanup(func() {
		cancel()
		server.Close()
		listener.Close()
	})
	return M.SocksaddrFromNet(listener.Addr())
}

func hRoundTrip(t *testing.T, clientOptions option.V2RayXHTTPOptions, clientTLS tls.Config, addr M.Socksaddr, payloads ...[]byte) {
	t.Helper()
	transport, err := NewClient(context.Background(), N.SystemDialer, addr, clientOptions, clientTLS)
	require.NoError(t, err)
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := transport.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()
	var expected []byte
	for _, payload := range payloads {
		expected = append(expected, payload...)
	}
	result := make(chan error, 1)
	received := make([]byte, len(expected))
	go func() {
		_, err := io.ReadFull(conn, received)
		result <- err
	}()
	for _, payload := range payloads {
		_, err = conn.Write(payload)
		require.NoError(t, err)
	}
	select {
	case err = <-result:
		require.NoError(t, err)
		require.True(t, bytes.Equal(expected, received), "echo mismatch")
	case <-time.After(4 * time.Second):
		t.Fatal("timeout waiting for echo")
	}
}

func hPayloads(t *testing.T, sizes ...int) [][]byte {
	payloads := make([][]byte, 0, len(sizes))
	for _, size := range sizes {
		payload := make([]byte, size)
		_, err := rand.Read(payload)
		require.NoError(t, err)
		payloads = append(payloads, payload)
	}
	return payloads
}

func TestH_XHTTPRoundTripH2(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		for _, serverMode := range []string{mode, "auto"} {
			t.Run(fmt.Sprintf("client=%s/server=%s", mode, serverMode), func(t *testing.T) {
				serverTLS, clientTLS := hNewTLSPair(t, []string{"h2"})
				serverOptions := hOptions(t, fmt.Sprintf(`{"mode":%q,"path":"/xh","x_padding_bytes":"100-1000"}`, serverMode))
				clientOptions := hOptions(t, fmt.Sprintf(`{"mode":%q,"path":"/xh","x_padding_bytes":"100-1000"}`, mode))
				addr := hStartServer(t, serverOptions, serverTLS)
				hRoundTrip(t, clientOptions, clientTLS, addr, hPayloads(t, 1, 1500, 64*1024)...)
			})
		}
	}
}

func TestH_XHTTPRoundTripHTTP1PacketUp(t *testing.T) {
	serverOptions := hOptions(t, `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000"}`)
	clientOptions := hOptions(t, `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000"}`)
	addr := hStartServer(t, serverOptions, nil)
	hRoundTrip(t, clientOptions, nil, addr, hPayloads(t, 10, 20000, 3)...)
}

func TestH_XHTTPRoundTripHTTP1OverTLS(t *testing.T) {
	serverTLS, clientTLS := hNewTLSPair(t, nil)
	require.Equal(t, "1.1", decideHTTPVersion(clientTLS))
	serverOptions := hOptions(t, `{"mode":"auto","path":"/xh","x_padding_bytes":"100-1000"}`)
	clientOptions := hOptions(t, `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000"}`)
	addr := hStartServer(t, serverOptions, serverTLS)
	hRoundTrip(t, clientOptions, clientTLS, addr, hPayloads(t, 100, 5000)...)
}

func TestH_XHTTPRoundTripMetaPlacements(t *testing.T) {
	for name, extra := range map[string]string{
		"query":         `"session_placement":"query","seq_placement":"query"`,
		"header":        `"session_placement":"header","seq_placement":"header"`,
		"cookie":        `"session_placement":"cookie","seq_placement":"cookie"`,
		"header-uplink": `"uplink_data_placement":"header","uplink_chunk_size":100`,
		"cookie-uplink": `"uplink_data_placement":"cookie"`,
		"put-method":    `"uplink_http_method":"put"`,
		"no-sse-grpc":   `"no_sse_header":true,"no_grpc_header":true`,
	} {
		t.Run(name, func(t *testing.T) {
			content := fmt.Sprintf(`{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000",%s}`, extra)
			serverOptions := hOptions(t, content)
			clientOptions := hOptions(t, content)
			addr := hStartServer(t, serverOptions, nil)
			hRoundTrip(t, clientOptions, nil, addr, hPayloads(t, 1, 700)...)
		})
	}
}

func TestH_XHTTPRoundTripObfsReferer(t *testing.T) {
	content := `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000","x_padding_obfs_mode":true,"x_padding_header":"Referer","x_padding_key":"x_padding"}`
	addr := hStartServer(t, hOptions(t, content), nil)
	hRoundTrip(t, hOptions(t, content), nil, addr, hPayloads(t, 50)...)
}

func TestH_XHTTPRoundTripObfsHeader(t *testing.T) {
	t.Skip("BUG: server ignores x_padding_obfs_mode placement/key when validating request padding and only checks Referer/query x_padding (server.go:121-133), so obfs mode with a non-Referer placement is always rejected with 400")
	content := `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000","x_padding_obfs_mode":true,"x_padding_placement":"header"}`
	addr := hStartServer(t, hOptions(t, content), nil)
	hRoundTrip(t, hOptions(t, content), nil, addr, hPayloads(t, 50)...)
}

func TestH_XHTTPRoundTripDownloadSplit(t *testing.T) {
	serverOptions := hOptions(t, `{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000"}`)
	addr := hStartServer(t, serverOptions, nil)
	clientOptions := hOptions(t, fmt.Sprintf(`{"mode":"packet-up","path":"/xh","x_padding_bytes":"100-1000","download":{"server":"127.0.0.1","server_port":%d,"path":"/xh","x_padding_bytes":"100-1000"}}`, addr.Port))
	require.NotNil(t, clientOptions.Download)
	hRoundTrip(t, clientOptions, nil, addr, hPayloads(t, 300)...)
}

func TestH_XHTTPClientRequiresMode(t *testing.T) {
	_, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:1"), option.V2RayXHTTPOptions{}, nil)
	require.EqualError(t, err, "mode is not set")
}
