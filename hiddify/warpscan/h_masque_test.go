package warpscan

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/stretchr/testify/require"
)

func hClientConfig(nextProtos ...string) aTLS.Config {
	return &hClient{config: &stdtls.Config{InsecureSkipVerify: true, ServerName: "example.com", NextProtos: nextProtos}}
}

// hClient is the smallest aTLS.Config the probe needs.
type hClient struct {
	config *stdtls.Config
}

func (c *hClient) ServerName() string                        { return c.config.ServerName }
func (c *hClient) SetServerName(name string)                 { c.config.ServerName = name }
func (c *hClient) NextProtos() []string                      { return c.config.NextProtos }
func (c *hClient) SetNextProtos(nextProto []string)          { c.config.NextProtos = nextProto }
func (c *hClient) STDConfig() (*stdtls.Config, error)        { return c.config, nil }
func (c *hClient) Client(conn net.Conn) (aTLS.Conn, error)   { return stdtls.Client(conn, c.config), nil }
func (c *hClient) Clone() aTLS.Config                        { return &hClient{config: c.config.Clone()} }
func (c *hClient) HandshakeTimeout() time.Duration           { return 0 }
func (c *hClient) SetHandshakeTimeout(timeout time.Duration) {}

func TestH_MASQUEProbeQUIC(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.StartTLS()
	defer server.Close()
	serverConfig := server.TLS.Clone()
	serverConfig.NextProtos = []string{"h3"}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverConfig, &quic.Config{})
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				time.Sleep(time.Second)
				conn.CloseWithError(0, "")
			}()
		}
	}()
	probe := MASQUEProbe(N.SystemDialer, hClientConfig("h3"), false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rtt, err := probe(ctx, netip.MustParseAddrPort(listener.Addr().String()))
	require.NoError(t, err)
	require.Greater(t, rtt, time.Duration(0))

	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer silent.Close()
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer shortCancel()
	_, err = probe(shortCtx, netip.MustParseAddrPort(silent.LocalAddr().String()))
	require.Error(t, err)
}

func TestH_MASQUEProbeHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	probe := MASQUEProbe(N.SystemDialer, hClientConfig("h3"), true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := probe(ctx, netip.MustParseAddrPort(server.Listener.Addr().String()))
	require.NoError(t, err)

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := closed.Addr().String()
	closed.Close()
	_, err = probe(ctx, netip.MustParseAddrPort(address))
	require.Error(t, err)
}
