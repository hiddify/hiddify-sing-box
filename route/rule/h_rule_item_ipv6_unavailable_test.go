package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type hIPv6Capability map[string]bool

func (c hIPv6Capability) OutboundIPv6(tag string) (bool, bool) {
	supported, known := c[tag]
	return supported, known
}

// The item matches an IPv6 destination only while the named outbound is known not to carry
// IPv6; IPv4 destinations, an outbound with IPv6 and one not probed yet never match.
func TestH_IPv6UnavailableItem(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.IPv6Capability](ctx, hIPv6Capability{"with6": true, "without6": false})
	v6 := &adapter.InboundContext{Destination: M.ParseSocksaddr("[2001:db8::1]:443")}
	v4 := &adapter.InboundContext{Destination: M.ParseSocksaddr("192.0.2.1:443")}
	byVersion := &adapter.InboundContext{IPVersion: 6}

	without := NewIPv6UnavailableItem(ctx, "without6")
	require.True(t, without.Match(v6))
	require.True(t, without.Match(byVersion))
	require.False(t, without.Match(v4))
	require.Equal(t, "ipv6_unavailable_via=without6", without.String())

	require.False(t, NewIPv6UnavailableItem(ctx, "with6").Match(v6))
	require.False(t, NewIPv6UnavailableItem(ctx, "unknown").Match(v6))
	require.False(t, NewIPv6UnavailableItem(service.ContextWithDefaultRegistry(context.Background()), "without6").Match(v6), "no monitoring: never matches")
}
