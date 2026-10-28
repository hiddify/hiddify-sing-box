//go:build with_awg

package warp

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/awg"
	"github.com/sagernet/sing/common/json/badoption"
)

func createWARPAwgEndpoint(
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
	return awg.NewEndpoint(ctx, router, logger, tag, option.AwgEndpointOptions{
		UseIntegratedTun: options.System,
		PrivateKey:       config.PrivateKey,
		Address:          addresses, //H
		MTU:              options.MTU,
		ListenPort:       options.ListenPort,
		Awg:              *options.AWG,
		Peers: []option.AwgPeerOptions{
			{
				Address:                     peerAddr,
				Port:                        peerPort,
				PublicKey:                   peerPublicKey,
				PersistentKeepaliveInterval: warpKeepalive, //H: keeps the handshake fresh, so IsReady can tell a dead path
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
			},
		},
		DialerOptions: options.DialerOptions,
	})
}
