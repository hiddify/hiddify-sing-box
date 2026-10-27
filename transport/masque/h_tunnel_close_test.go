//go:build with_gvisor

package masque

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/stretchr/testify/require"
)

type hCountingLogger struct {
	logger.ContextLogger
	readErrors atomic.Int32
}

func (l *hCountingLogger) ErrorContext(ctx context.Context, args ...any) {
	for _, arg := range args {
		if err, isErr := arg.(error); isErr && strings.Contains(err.Error(), "failed to read from TUN device") {
			l.readErrors.Add(1)
		}
	}
}

// Closing the tunnel ends its loops: the TUN read loop spun on the closed device, logging an
// error per iteration, until the box context ended.
func TestH_TunnelCloseStopsLoops(t *testing.T) {
	counting := &hCountingLogger{ContextLogger: log.NewNOPFactory().NewLogger("masque")}
	tunnel, err := NewTunnel(context.Background(), counting, TunnelOptions{
		Dialer:         N.SystemDialer,
		Address:        []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")},
		Endpoint:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		ReconnectDelay: time.Second,
		TLSConfig:      &hTLSClient{config: &stdtls.Config{InsecureSkipVerify: true, ServerName: "example.com", NextProtos: []string{"h3"}}},
	})
	require.NoError(t, err)
	require.NoError(t, tunnel.Start(false))
	require.NoError(t, tunnel.Start(true))
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, tunnel.Close())
	time.Sleep(300 * time.Millisecond)
	require.LessOrEqual(t, counting.readErrors.Load(), int32(1), "the read loop kept running after close")
}

// hTLSClient is the smallest TLS configuration the tunnel needs.
type hTLSClient struct {
	config *stdtls.Config
}

func (c *hTLSClient) ServerName() string                 { return c.config.ServerName }
func (c *hTLSClient) SetServerName(name string)          { c.config.ServerName = name }
func (c *hTLSClient) NextProtos() []string               { return c.config.NextProtos }
func (c *hTLSClient) SetNextProtos(nextProto []string)   { c.config.NextProtos = nextProto }
func (c *hTLSClient) STDConfig() (*stdtls.Config, error) { return c.config, nil }
func (c *hTLSClient) Client(conn net.Conn) (aTLS.Conn, error) {
	return stdtls.Client(conn, c.config), nil
}
func (c *hTLSClient) Clone() aTLS.Config                        { return &hTLSClient{config: c.config.Clone()} }
func (c *hTLSClient) HandshakeTimeout() time.Duration           { return 0 }
func (c *hTLSClient) SetHandshakeTimeout(timeout time.Duration) {}
