package box

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// H: lazy outbounds and endpoints. An outbound, or a client endpoint, with "lazy": true is created
// as a stand-in that keeps its options and creates the real one when it is first used
// (adapter/outbound/h_lazy.go).

// lazyOutbound is the type and options to create for an outbound: its own, or those of the
// stand-in when it is lazy.
func lazyOutbound(ctx context.Context, outbound option.Outbound) (string, any) {
	if !outbound.Lazy || !canBeLazy(outbound.Type) {
		return outbound.Type, outbound.Options
	}
	var dependencies []string
	if content, err := json.MarshalContext(ctx, &outbound); err == nil {
		dependencies = outboundDependencies(content)
	}
	return C.TypeHLazy, &option.HLazyOptions{Type: outbound.Type, Options: outbound.Options, Dependencies: dependencies}
}

// canBeLazy leaves out what is not a proxy with connections of its own: the groups, which the
// box and the monitoring know by their kind, and the outbounds that cost nothing to keep.
func canBeLazy(outboundType string) bool {
	switch outboundType {
	case C.TypeSelector, C.TypeURLTest, C.TypeBalancer, C.TypeFallback, C.TypeBond,
		C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeBridge, C.TypeHInvalidConfig, C.TypeHLazy, C.TypeCustom:
		return false
	}
	return true
}

// lazyEndpoint is the type and options to create for an endpoint: its own, or those of the
// stand-in when it is lazy and can be (lazyEndpointOptions). An endpoint a DNS server resolves
// through is lazy too: the server holds it (adapter.HoldEndpoint), so it runs as without lazy.
func lazyEndpoint(ctx context.Context, endpoint option.Endpoint) (string, any) {
	if !endpoint.Lazy {
		return endpoint.Type, endpoint.Options
	}
	options, canBe := lazyEndpointOptions(endpoint.Type, endpoint.Options)
	if !canBe {
		return endpoint.Type, endpoint.Options
	}
	var dependencies []string
	if content, err := json.MarshalContext(ctx, &endpoint); err == nil {
		dependencies = outboundDependencies(content)
	}
	return C.TypeHLazy, &option.HLazyOptions{Type: endpoint.Type, Options: options, HeldOptions: endpoint.Options, Dependencies: dependencies}
}

// lazyEndpointOptions are the options a lazy endpoint creates its real one from, and whether the
// endpoint can be lazy at all. Only a client can: an endpoint in server mode (a WireGuard that
// listens, an OpenVPN or MASQUE server, a tunnel, a Tailscale node, which peers reach) is there for
// what comes in, which nothing would create it for. A client that connects in the background is
// made on demand, so that the first dial waits for its tunnel instead of failing: the real one is
// created right before that dial.
func lazyEndpointOptions(endpointType string, options any) (any, bool) {
	switch options := options.(type) {
	case *option.WireGuardEndpointOptions:
		return options, options.ListenPort == 0
	case *option.AwgEndpointOptions:
		return options, options.ListenPort == 0
	case *option.WARPEndpointOptions:
		return options, options.ListenPort == 0
	case *option.OpenVPNClientEndpointOptions:
		onDemand := *options
		onDemand.OnDemand = true
		return &onDemand, true
	case *option.OpenConnectEndpointOptions:
		onDemand := *options
		onDemand.OnDemand = true
		return &onDemand, true
	case *option.MASQUEClientEndpointOptions:
		onDemand := *options
		onDemand.OnDemand = true
		return &onDemand, true
	}
	switch endpointType {
	case C.TypeOpenVPNServer, C.TypeMASQUEServer, C.TypeTunnelServer, C.TypeTunnelClient, C.TypeTailscale,
		C.TypeHInvalidConfig, C.TypeHLazy:
		return nil, false
	}
	return options, options != nil
}
