package wireguard

import (
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterWarpEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WireGuardWarpEndpointOptions](registry, C.TypeWARP, NewWarpEndpoint)
}

type WarpEndpoint struct {
	endpoint.Adapter
	endpoint adapter.Endpoint
	ctx      context.Context
	router   adapter.Router
	logger   log.ContextLogger
	tag      string
	options  option.WireGuardWarpEndpointOptions
}

func NewWarpEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardWarpEndpointOptions) (adapter.Endpoint, error) {
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile != nil {
		if options.Profile.Detour != "" {
			dependencies = append(dependencies, options.Profile.Detour)
		}
	}
	return &WarpEndpoint{
		Adapter: endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		tag:     tag,
		options: options,
	}, nil
}

func (w *WarpEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	cacheFile := service.FromContext[adapter.CacheFile](w.ctx)
	var profile *cloudflare.CloudflareProfile
	var err error
	if !w.options.Profile.Recreate {
		if cacheFile != nil {
			savedProfile := cacheFile.LoadCloudflareProfile(w.tag)
			if savedProfile != nil {
				err := json.Unmarshal(savedProfile.Content, &profile)
				if err != nil {
					return err
				}
			}
		}
	}
	if profile == nil {
		opts := make([]cloudflare.CloudflareApiOption, 0, 1)
		if w.options.Profile != nil {
			if w.options.Profile.Detour != "" {
				detour, ok := service.FromContext[adapter.OutboundManager](w.ctx).Outbound(w.options.Profile.Detour)
				if !ok {
					return E.New("outbound detour not found: ", w.options.Profile.Detour)
				}
				opts = append(opts, cloudflare.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
					return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
				}))
			}
		}
		api := cloudflare.NewCloudeflareApi(opts...)
		profile, err = api.CreateProfile(w.ctx)
		if err != nil {
			return err
		}
		if cacheFile != nil {
			content, err := json.Marshal(profile)
			if err != nil {
				return err
			}
			cacheFile.SaveCloudflareProfile(w.tag, &adapter.SavedBinary{
				LastUpdated: time.Now(),
				Content:     content,
				LastEtag:    "",
			})
		}
	}
	peer := profile.Config.Peers[0]
	hostParts := strings.Split(peer.Endpoint.Host, ":")
	w.endpoint, err = NewEndpoint(
		w.ctx,
		w.router,
		w.logger,
		w.tag,
		option.WireGuardEndpointOptions{
			System:        w.options.System,
			Name:          w.options.Name,
			ListenPort:    w.options.ListenPort,
			UDPTimeout:    w.options.UDPTimeout,
			Workers:       w.options.Workers,
			Amnezia:       w.options.Amnezia,
			DialerOptions: w.options.DialerOptions,

			Address: badoption.Listable[netip.Prefix]{
				netip.MustParsePrefix(profile.Config.Interface.Addresses.V4 + "/32"),
				netip.MustParsePrefix(profile.Config.Interface.Addresses.V6 + "/128"),
			},
			PrivateKey: profile.Config.PrivateKey,
			Peers: []option.WireGuardPeer{
				{
					Address:   hostParts[0],
					Port:      uint16(peer.Endpoint.Ports[rand.Intn(len(peer.Endpoint.Ports))]),
					PublicKey: peer.PublicKey,
					AllowedIPs: badoption.Listable[netip.Prefix]{
						netip.MustParsePrefix("0.0.0.0/0"),
						netip.MustParsePrefix("::/0"),
					},
				},
			},
			MTU: 1280,
		},
	)
	if err != nil {
		return err
	}
	if err := w.endpoint.Start(adapter.StartStateStart); err != nil {
		return err
	}
	if err := w.endpoint.Start(adapter.StartStatePostStart); err != nil {
		return err
	}
	return nil
}

func (w *WarpEndpoint) Close() error {
	if w.endpoint == nil {
		return E.New("endpoint not initialized")
	}
	return w.endpoint.Close()
}

func (w *WarpEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if w.endpoint == nil {
		return nil, E.New("endpoint not initialized")
	}
	return w.endpoint.DialContext(ctx, network, destination)
}

func (w *WarpEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if w.endpoint == nil {
		return nil, E.New("endpoint not initialized")
	}
	return w.endpoint.ListenPacket(ctx, destination)
}
