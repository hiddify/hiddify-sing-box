package warp

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	wg "github.com/sagernet/sing-box/protocol/wireguard"
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
	addresses, err := warpInterfaceAddresses(config) //H: a config without addresses crashed the process
	if err != nil {                                  //H
		return nil, err //H
	} //H
	return wg.NewEndpoint(ctx, router, logger, tag, option.WireGuardEndpointOptions{
		System:        options.System,
		Name:          options.Name,
		ListenPort:    options.ListenPort,
		UDPTimeout:    options.UDPTimeout,
		Workers:       options.Workers,
		Noise:         options.Noise,
		AWG:           options.AWG,
		DialerOptions: options.DialerOptions,
		Address:       addresses, //H
		PrivateKey:    config.PrivateKey,
		Peers: []option.WireGuardPeer{
			{
				Address:   peerAddr,
				Port:      peerPort,
				PublicKey: peerPublicKey,
				AllowedIPs: option.LegacyListable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
			},
		},
		MTU: options.MTU,
	})
}
