package warp

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	wg "github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/json/badoption"
)

func createWARPWireGuardEndpoint(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.WARPEndpointOptions,
	config *C.WARPConfig,
	peerAddr string,
	peerPort uint16,
	peerPublicKey string,
) (adapter.Endpoint, error) {
	return wg.NewEndpoint(ctx, router, logger, tag, option.WireGuardEndpointOptions{
		System:                     options.System,
		Name:                       options.Name,
		ListenPort:                 options.ListenPort,
		UDPTimeout:                 options.UDPTimeout,
		Workers:                    options.Workers,
		PreallocatedBuffersPerPool: options.PreallocatedBuffersPerPool,
		DisablePauses:              options.DisablePauses,
		Noise:                      options.Noise,
		DialerOptions:              options.DialerOptions,
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix(config.Interface.Addresses.V4 + "/32"),
			netip.MustParsePrefix(config.Interface.Addresses.V6 + "/128"),
		},
		PrivateKey: config.PrivateKey,
		Peers: []option.WireGuardPeer{
			{
				Address:   peerAddr,
				Port:      peerPort,
				PublicKey: peerPublicKey,
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
			},
		},
		MTU: options.MTU,
	})
}
