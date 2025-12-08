package wireguard

import (
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func RegisterWARPEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WireGuardWARPEndpointOptions](registry, C.TypeWARP, NewWARPEndpoint)
}

type WARPEndpoint struct {
	endpoint.Adapter
	endpoint     adapter.Endpoint
	startHandler func()

	mtx sync.Mutex
}

func NewWARPEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardWARPEndpointOptions) (adapter.Endpoint, error) {
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	warpEndpoint := &WARPEndpoint{
		Adapter: endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
	}
	warpEndpoint.mtx.Lock()
	warpEndpoint.startHandler = func() {
		defer warpEndpoint.mtx.Unlock()
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var config *C.WARPConfig
		var err error
		if !options.Profile.Recreate && cacheFile != nil && cacheFile.StoreWARPConfig() {
			savedProfile := cacheFile.LoadWARPConfig(tag)
			if savedProfile != nil {
				if err = json.Unmarshal(savedProfile.Content, &config); err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
			}
		}
		if config == nil {
			var privateKey wgtypes.Key
			if options.Profile.PrivateKey != "" {
				privateKey, err = wgtypes.ParseKey(options.Profile.PrivateKey)
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
			} else {
				privateKey, err = wgtypes.GeneratePrivateKey()
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
			}
			opts := make([]cloudflare.CloudflareApiOption, 0, 1)
			if options.Profile.Detour != "" {
				detour, ok := service.FromContext[adapter.OutboundManager](ctx).Outbound(options.Profile.Detour)
				if !ok {
					logger.ErrorContext(ctx, E.New("outbound detour not found: ", options.Profile.Detour))
					return
				}
				opts = append(opts, cloudflare.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
					return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
				}))
			}
			api := cloudflare.NewCloudflareApi(opts...)
			var profile *cloudflare.CloudflareProfile
			if options.Profile.AuthToken != "" && options.Profile.ID != "" {
				profile, err = api.GetProfile(ctx, options.Profile.AuthToken, options.Profile.ID)
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
			} else {
				profile, err = api.CreateProfile(ctx, privateKey.PublicKey().String())
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
			}
			config = &C.WARPConfig{
				PrivateKey: privateKey.String(),
				Interface:  profile.Config.Interface,
				Peers:      profile.Config.Peers,
			}
			if cacheFile != nil && cacheFile.StoreWARPConfig() {
				content, err := json.Marshal(config)
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
				cacheFile.SaveWARPConfig(tag, &adapter.SavedBinary{
					LastUpdated: time.Now(),
					Content:     content,
					LastEtag:    "",
				})
			}
		}
		peer := config.Peers[0]
		hostParts := strings.Split(peer.Endpoint.Host, ":")
		warpEndpoint.endpoint, err = NewEndpoint(
			ctx,
			router,
			logger,
			tag,
			option.WireGuardEndpointOptions{
				System:                     options.System,
				Name:                       options.Name,
				ListenPort:                 options.ListenPort,
				UDPTimeout:                 options.UDPTimeout,
				Workers:                    options.Workers,
				PreallocatedBuffersPerPool: options.PreallocatedBuffersPerPool,
				DisablePauses:              options.DisablePauses,
				Amnezia:                    options.Amnezia,
				DialerOptions:              options.DialerOptions,

				Address: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix(config.Interface.Addresses.V4 + "/32"),
					netip.MustParsePrefix(config.Interface.Addresses.V6 + "/128"),
				},
				PrivateKey: config.PrivateKey,
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
			logger.ErrorContext(ctx, err)
			return
		}
		if err = warpEndpoint.endpoint.Start(adapter.StartStateStart); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		if err = warpEndpoint.endpoint.Start(adapter.StartStatePostStart); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
	}
	return warpEndpoint, nil
}

func (w *WARPEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	go w.startHandler()
	return nil
}

func (w *WARPEndpoint) Close() error {
	return common.Close(w.endpoint)
}

func (w *WARPEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if ok := w.isEndpointInitialized(); !ok {
		return nil, E.New("endpoint not initialized")
	}
	return w.endpoint.DialContext(ctx, network, destination)
}

func (w *WARPEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if ok := w.isEndpointInitialized(); !ok {
		return nil, E.New("endpoint not initialized")
	}
	return w.endpoint.ListenPacket(ctx, destination)
}

func (w *WARPEndpoint) isEndpointInitialized() bool {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return w.endpoint != nil
}
