//go:build with_cloudflared

package cloudflare

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type hPreMatchRouter struct {
	adapter.Router
	result   adapter.PreMatchResult
	metadata adapter.InboundContext
}

func (r *hPreMatchRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	r.metadata = metadata
	return r.result
}

type hPortOutbound struct {
	adapter.Outbound
	tun.Port
}

type hPlainOutbound struct {
	adapter.Outbound
}

func hHandler(router adapter.Router) *icmpRouterHandler {
	return &icmpRouterHandler{router: router, logger: log.NewNOPFactory().NewLogger("cf"), tag: "cf-in"}
}

func TestH_RouteICMPFlowMetadata(t *testing.T) {
	router := &hPreMatchRouter{}
	source := netip.MustParseAddr("10.0.0.1")
	_, err := hHandler(router).RouteICMPFlow(source, netip.MustParseAddr("1.1.1.1"))
	require.Error(t, err)
	require.Equal(t, "cf-in", router.metadata.Inbound)
	require.Equal(t, C.TypeCloudflared, router.metadata.InboundType)
	require.Equal(t, N.NetworkICMP, router.metadata.Network)
	require.Equal(t, uint8(4), router.metadata.IPVersion)
	require.Equal(t, source, router.metadata.Source.Addr)
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), router.metadata.Destination.Addr)
	require.Equal(t, router.metadata.Destination, router.metadata.OriginDestination)

	_, err = hHandler(router).RouteICMPFlow(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2606:4700::1111"))
	require.Error(t, err)
	require.Equal(t, uint8(6), router.metadata.IPVersion)
}

func TestH_RouteICMPFlowActions(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.1")
	destination := netip.MustParseAddr("8.8.8.8")
	port := &hPortOutbound{}

	result, err := hHandler(&hPreMatchRouter{result: adapter.PreMatchResult{Action: adapter.PreMatchFlow, Outbound: port}}).RouteICMPFlow(source, destination)
	require.NoError(t, err)
	require.Same(t, port, result)

	_, err = hHandler(&hPreMatchRouter{result: adapter.PreMatchResult{Action: adapter.PreMatchFlow, Outbound: &hPlainOutbound{}}}).RouteICMPFlow(source, destination)
	require.ErrorContains(t, err, "does not support ICMP flow routing")

	_, err = hHandler(&hPreMatchRouter{result: adapter.PreMatchResult{Action: adapter.PreMatchReject}}).RouteICMPFlow(source, destination)
	require.ErrorContains(t, err, "rejected")

	_, err = hHandler(&hPreMatchRouter{result: adapter.PreMatchResult{Action: adapter.PreMatchBypass}}).RouteICMPFlow(source, destination)
	require.ErrorContains(t, err, "bypassed")

	for _, action := range []adapter.PreMatchAction{adapter.PreMatchContinue, adapter.PreMatchDrop} {
		_, err = hHandler(&hPreMatchRouter{result: adapter.PreMatchResult{Action: action}}).RouteICMPFlow(source, destination)
		require.ErrorContains(t, err, "no route for ICMP connection")
	}
}
