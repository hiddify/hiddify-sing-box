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
	uniqueId := options.UniqueIdentifier
	if uniqueId == "" {
		uniqueId = tag
	}
	warpEndpoint.mtx.Lock()
	warpEndpoint.startHandler = func() {
		defer warpEndpoint.mtx.Unlock()
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var config *C.WARPConfig
		var err error
		if !options.Profile.Recreate && cacheFile != nil && cacheFile.StoreWARPConfig() {
			savedProfile := cacheFile.LoadBinary(uniqueId)
			if savedProfile != nil {
				if err = json.Unmarshal(savedProfile.Content, &config); err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
			}
		}
		if config == nil && options.WARPConfig != nil {
			config = options.WARPConfig
		}
		if config == nil || config.PrivateKey == "" {
			profile, err := GetWarpProfile(ctx, &options.Profile)
			if err != nil {
				logger.ErrorContext(ctx, err)
				return
			}
			config = &profile.Config

			if cacheFile != nil && cacheFile.StoreWARPConfig() {
				content, err := json.Marshal(config)
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
				cacheFile.SaveBinary(uniqueId, &adapter.SavedBinary{
					LastUpdated: time.Now(),
					Content:     content,
					LastEtag:    "",
				})
			}
		}
		peer := config.Peers[0]
		hostParts := strings.Split(peer.Endpoint.Host, ":")
		peerAddr := hostParts[0]
		perrPort := uint16(peer.Endpoint.Ports[rand.Intn(len(peer.Endpoint.Ports))])
		if options.ServerOptions.Server != "" {
			peerAddr = options.ServerOptions.Server
		}
		if options.ServerOptions.ServerPort != 0 {
			perrPort = options.ServerOptions.ServerPort
		}
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
						Port:      perrPort,
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
func GetWarpProfile(ctx context.Context, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	var dialer N.Dialer
	outmanager := service.FromContext[adapter.OutboundManager](ctx)
	if profile.Detour != "" && outmanager != nil {
		var ok bool
		dialer, ok = outmanager.Outbound(profile.Detour)
		if !ok {
			return nil, E.New("outbound detour not found: ", profile.Detour)
		}

	}
	cf, err := GetWarpProfileDialer(ctx, dialer, profile)
	if err == nil || outmanager == nil {
		return cf, nil
	}

	for _, dialer := range outmanager.Outbounds() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if cf, err := GetWarpProfileDialer(ctx, dialer, profile); err == nil {
			return cf, nil
		}
	}
	return nil, err

}
func GetWarpProfileDialer(ctx context.Context, dialer N.Dialer, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	api := cloudflare.NewCloudflareApiDetour(dialer)
	if profile.AuthToken != "" && profile.ID != "" {
		return api.GetProfile(ctx, profile.AuthToken, profile.ID)

	} else {
		return api.CreateProfileLicense(ctx, profile.PrivateKey, profile.License)
	}
}
func (w *WARPEndpoint) IsReady() bool {
	if ok := w.isEndpointInitialized(); !ok {
		return false
	}
	return w.endpoint.IsReady()
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
