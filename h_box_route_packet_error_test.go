package box_test

import (
	"context"
	"net"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A packet connection that fails to route (here an unknown inbound detour) must return, as
// RouteConnection does, instead of waiting for a close that never comes until shutdown.
func TestH_RoutePacketConnectionReturnsOnRouteError(t *testing.T) {
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	router, isRouter := instance.Router().(interface {
		RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error
	})
	require.True(t, isRouter)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer udpConn.Close()
	result := make(chan error, 1)
	go func() {
		result <- router.RoutePacketConnection(ctx, bufio.NewPacketConn(udpConn), adapter.InboundContext{
			Inbound:       "in",
			InboundDetour: "missing",
			Network:       N.NetworkUDP,
			Destination:   M.ParseSocksaddr("1.1.1.1:53"),
		})
	}()
	select {
	case <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("RoutePacketConnection did not return after a routing error")
	}
}
