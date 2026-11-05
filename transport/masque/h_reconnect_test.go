//go:build with_gvisor

package masque

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Without a reconnect delay, a detour that failed at once was dialed again at once: the tunnel
// spun on several cores, logging each attempt, for as long as the detour stayed broken.
func TestH_TunnelBacksOffWithoutReconnectDelay(t *testing.T) {
	failing := &hFailingDialer{}
	tunnel, err := NewTunnel(context.Background(), log.NewNOPFactory().NewLogger("masque"), TunnelOptions{
		Dialer:     failing,
		Address:    []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")},
		Endpoint:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		H2Endpoint: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		Mode:       ModeHTTP2,
		TLSConfig:  &hTLSClient{config: &stdtls.Config{InsecureSkipVerify: true, ServerName: "example.com", NextProtos: []string{"h2"}}},
	})
	require.NoError(t, err)
	require.NoError(t, tunnel.Start(false))
	require.NoError(t, tunnel.Start(true))
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, tunnel.Close())
	require.LessOrEqual(t, failing.dials.Load(), int32(2), "the tunnel redialed a failing detour without waiting")
}

func TestH_ReconnectBackoff(t *testing.T) {
	t.Parallel()
	require.Equal(t, 3*time.Second, reconnectBackoff(3*time.Second, 5), "a configured delay is kept")
	require.Equal(t, time.Second, reconnectBackoff(0, 1))
	require.Equal(t, 2*time.Second, reconnectBackoff(0, 2))
	require.Equal(t, 8*time.Second, reconnectBackoff(0, 4))
	require.Equal(t, 32*time.Second, reconnectBackoff(0, 6))
	require.Equal(t, reconnectBackoffMax, reconnectBackoff(0, 7))
	require.Equal(t, reconnectBackoffMax, reconnectBackoff(0, 1000))
}
