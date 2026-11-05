package mieru

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
)

// mieruResolver looks up the server for mieru's UDP transport, which resolves the name itself
// before it dials; without it a UDP server given by name never connects. It asks sing-box's DNS
// with the outbound's domain resolver, as the dialer would for a TCP server.
type mieruResolver struct {
	router  adapter.DNSRouter
	options adapter.DNSQueryOptions
}

var _ mierucommon.DNSResolver = (*mieruResolver)(nil)

func newMieruResolver(ctx context.Context, outboundDialer N.Dialer) mierucommon.DNSResolver {
	router := service.FromContext[adapter.DNSRouter](ctx)
	if router == nil {
		return nil
	}
	resolver := &mieruResolver{router: router}
	if resolveDialer, ok := outboundDialer.(dialer.ResolveDialer); ok {
		resolver.options = resolveDialer.QueryOptions()
	}
	return resolver
}

func (r *mieruResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	addresses, err := r.router.Lookup(ctx, host, r.options)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, address := range addresses {
		address = address.Unmap()
		if network == "ip4" && !address.Is4() || network == "ip6" && !address.Is6() {
			continue
		}
		ips = append(ips, address.AsSlice())
	}
	if len(ips) == 0 {
		return nil, E.New("no ", network, " address for ", host)
	}
	return ips, nil
}
