package mieru

import (
	"context"
	"net/netip"
	"testing"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

type hDNSRouter struct {
	adapter.DNSRouter
	asked []string
}

func (r *hDNSRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.asked = append(r.asked, domain)
	return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:192.0.2.1")}, nil
}

// mieru's UDP transport resolves its server itself, and without a resolver a server given by
// name failed with "look up IP address of ... is not supported".
func TestH_MieruResolverResolvesUDPServer(t *testing.T) {
	t.Parallel()
	router := &hDNSRouter{}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), router)
	resolver := newMieruResolver(ctx, N.SystemDialer)
	require.NotNil(t, resolver)

	addr, err := mierucommon.ResolveUDPAddr(ctx, resolver, "udp", "server.example:443")
	require.NoError(t, err)
	require.Equal(t, 443, addr.Port)
	require.Equal(t, []string{"server.example"}, router.asked)

	v4, err := resolver.LookupIP(ctx, "ip4", "server.example")
	require.NoError(t, err)
	require.Len(t, v4, 1)
	require.Equal(t, "192.0.2.1", v4[0].String())

	v6, err := resolver.LookupIP(ctx, "ip6", "server.example")
	require.NoError(t, err)
	require.Len(t, v6, 1)
	require.Equal(t, "2001:db8::1", v6[0].String())
}

func TestH_MieruResolverWithoutDNSRouter(t *testing.T) {
	t.Parallel()
	require.Nil(t, newMieruResolver(context.Background(), N.SystemDialer))
}
