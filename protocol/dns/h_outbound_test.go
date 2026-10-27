package dns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

// When a DNS packet session ends, onClose must run: the router tracks the connection by it, and
// a legacy RoutePacketConnection caller waits for it.
func TestH_DNSOutboundPacketConnectionCallsOnClose(t *testing.T) {
	out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "dns-out", option.StubOptions{})
	require.NoError(t, err)
	handler := out.(adapter.PacketConnectionHandler)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	closed := make(chan error, 1)
	go handler.NewPacketConnection(context.Background(), bufio.NewPacketConn(udpConn), adapter.InboundContext{}, func(err error) {
		closed <- err
	})
	time.Sleep(100 * time.Millisecond)
	udpConn.Close()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("onClose was not called when the DNS packet session ended")
	}
}
