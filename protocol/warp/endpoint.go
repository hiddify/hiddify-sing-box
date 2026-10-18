package warp

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
	"github.com/sagernet/sing-box/protocol/wireguard"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WARPEndpointOptions](registry, C.TypeWARP, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx          context.Context
	logger       log.ContextLogger
	options      option.WARPEndpointOptions
	endpoint     adapter.Endpoint
	startHandler func(scope *adapter.Scope)

	await chan struct{}
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WARPEndpointOptions) (adapter.Endpoint, error) {
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	endpoint := &Endpoint{
		Adapter: endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:     ctx,
		logger:  logger,
		options: options,
		await:   make(chan struct{}),
	}
	endpoint.startHandler = func(scope *adapter.Scope) {
		defer close(endpoint.await)
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var config *Config
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
			config, err = endpoint.createConfig()
			if err != nil {
				logger.ErrorContext(ctx, err)
				return
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
		peerAddress := strings.Split(peer.Endpoint.Host, ":")[0]
		peerPort := uint16(peer.Endpoint.Ports[rand.Intn(len(peer.Endpoint.Ports))])
		if options.Address != "" {
			peerAddress = options.Address
			if options.Port != 0 {
				peerPort = options.Port
			}
		}
		var amnezia *option.WireGuardAmnezia
		if options.Amnezia != nil {
			amnezia = &option.WireGuardAmnezia{
				JC:                     options.Amnezia.JC,
				JMin:                   options.Amnezia.JMin,
				JMax:                   options.Amnezia.JMax,
				I1:                     options.Amnezia.I1,
				I2:                     options.Amnezia.I2,
				I3:                     options.Amnezia.I3,
				I4:                     options.Amnezia.I4,
				I5:                     options.Amnezia.I5,
				ContentPaddingAddition: options.Amnezia.ContentPaddingAddition,
				RekeyAfterTime:         options.Amnezia.RekeyAfterTime,
				RekeyTimeout:           options.Amnezia.RekeyTimeout,
				RejectAfterTime:        options.Amnezia.RejectAfterTime,
				KeepaliveTimeout:       options.Amnezia.KeepaliveTimeout,
				MaxHandshakeAttempts:   options.Amnezia.MaxHandshakeAttempts,
			}
		}
		endpoint.endpoint, err = wireguard.NewEndpoint(
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
				Amnezia:                    amnezia,
				DialerOptions:              options.DialerOptions,

				Address: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix(config.Interface.Addresses.V4 + "/32"),
					netip.MustParsePrefix(config.Interface.Addresses.V6 + "/128"),
				},
				PrivateKey: config.PrivateKey,
				Peers: []option.WireGuardPeer{
					{
						Address:   peerAddress,
						Port:      peerPort,
						PublicKey: peer.PublicKey,
						AllowedIPs: badoption.Listable[netip.Prefix]{
							netip.MustParsePrefix("0.0.0.0/0"),
							netip.MustParsePrefix("::/0"),
						},
						PersistentKeepaliveInterval: options.PersistentKeepaliveInterval,
					},
				},
				MTU: 1280,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStatePostStart} {
			err = scope.Start("endpoint/"+endpoint.endpoint.Type()+"["+endpoint.endpoint.Tag()+"]", endpoint.endpoint, stage)
			if err != nil {
				logger.ErrorContext(ctx, err)
				return
			}
		}
	}
	return endpoint, nil
}

func (w *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	endpointScope := adapter.NewScope(w.ctx, w.logger)
	scope.Add(func() error {
		select {
		case <-w.await:
		case <-w.ctx.Done():
		}
		return endpointScope.Close()
	})
	go w.startHandler(endpointScope)
	return nil
}

func (w *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := w.isEndpointInitialized(ctx); err != nil {
		return nil, err
	}
	return w.endpoint.DialContext(ctx, network, destination)
}

func (w *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := w.isEndpointInitialized(ctx); err != nil {
		return nil, err
	}
	return w.endpoint.ListenPacket(ctx, destination)
}

func (w *Endpoint) isEndpointInitialized(ctx context.Context) error {
	select {
	case <-w.await:
	case <-ctx.Done():
		return ctx.Err()
	}
	if w.endpoint == nil {
		return E.New("endpoint not initialized")
	}
	return nil
}

func (w *Endpoint) createConfig() (*Config, error) {
	opts := make([]cloudflare.CloudflareApiOption, 0, 1)
	if w.options.Profile.Detour != "" {
		detour, ok := service.FromContext[adapter.OutboundManager](w.ctx).Outbound(w.options.Profile.Detour)
		if !ok {
			return nil, E.New("outbound detour not found: ", w.options.Profile.Detour)
		}
		opts = append(opts, cloudflare.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
		}))
	}
	var privateKey wgtypes.Key
	var err error
	if w.options.Profile.PrivateKey != "" {
		privateKey, err = wgtypes.ParseKey(w.options.Profile.PrivateKey)
		if err != nil {
			return nil, err
		}
	} else {
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
	}
	api := cloudflare.NewCloudflareApi(opts...)
	var profile *cloudflare.CloudflareProfile
	if w.options.Profile.AuthToken != "" && w.options.Profile.ID != "" {
		profile, err = api.GetProfile(w.ctx, w.options.Profile.AuthToken, w.options.Profile.ID)
		if err != nil {
			return nil, err
		}
	} else {
		profile, err = api.CreateProfile(w.ctx, privateKey.PublicKey().String())
		if err != nil {
			return nil, err
		}
	}
	if w.options.Profile.LicenseKey != "" && profile.Account.License != w.options.Profile.LicenseKey {
		if _, err = api.UpdateAccount(w.ctx, profile.Token, profile.ID, w.options.Profile.LicenseKey); err != nil {
			return nil, E.New("failed to apply license key: ", err)
		}
	}
	return &Config{
		PrivateKey: privateKey.String(),
		Interface:  profile.Config.Interface,
		Peers:      profile.Config.Peers,
	}, nil
}
