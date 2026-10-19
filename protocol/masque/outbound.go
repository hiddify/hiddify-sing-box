package masque

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MASQUEOutboundOptions](registry, C.TypeMASQUE, NewOutbound)
}

type tunnelClient interface {
	N.Dialer
	Close() error
}

type Outbound struct {
	outbound.Adapter
	ctx          context.Context
	dnsRouter    adapter.DNSRouter
	logger       logger.ContextLogger
	options      option.MASQUEOutboundOptions
	client       tunnelClient
	startHandler func()

	await chan struct{}
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEOutboundOptions) (adapter.Outbound, error) {
	networks := []string{N.NetworkTCP, N.NetworkUDP}
	if options.UseL4Proxy {
		networks = []string{N.NetworkTCP}
	}
	outbound := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeMASQUE, tag, networks, options.DialerOptions),
		ctx:       ctx,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		logger:    logger,
		options:   options,
		await:     make(chan struct{}),
	}
	outbound.startHandler = func() {
		defer close(outbound.await)
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var appConfig *Config
		var err error
		if !options.Profile.Recreate && cacheFile != nil && cacheFile.StoreMASQUEConfig() {
			savedProfile := cacheFile.LoadMASQUEConfig(tag)
			if savedProfile != nil {
				if err = json.Unmarshal(savedProfile.Content, &appConfig); err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
			}
		}
		if appConfig == nil {
			appConfig, err = outbound.createConfig()
			if err != nil {
				logger.ErrorContext(ctx, err)
				return
			}
			if cacheFile != nil && cacheFile.StoreMASQUEConfig() {
				content, err := json.Marshal(appConfig)
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
				cacheFile.SaveMASQUEConfig(tag, &adapter.SavedBinary{
					LastUpdated: time.Now(),
					Content:     content,
					LastEtag:    "",
				})
			}
		}
		privKey, err := appConfig.GetEcPrivateKey()
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to get private key: ", err))
			return
		}
		peerPubKey, err := appConfig.GetEcEndpointPublicKey()
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to get public key: ", err))
			return
		}
		cert, err := masque.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to generate cert: ", err))
			return
		}
		serverName := cloudflare.ConnectSNI
		if options.UseL4Proxy {
			serverName = cloudflare.L4ConnectSNI
		}
		if options.TLS != nil && options.TLS.ServerName != "" {
			serverName = options.TLS.ServerName
		}
		tlsConfig, err := tls.NewMASQUEClient(ctx, logger, serverName, cert, privKey, peerPubKey, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			logger.ErrorContext(ctx, E.New("failed to prepare TLS config: ", err))
			return
		}
		useHTTP2 := options.UseHTTP2 && !options.UseL4Proxy
		var endpoint net.Addr
		if options.Address != "" {
			endpointPort := options.Port
			if endpointPort == 0 {
				endpointPort = 443
			}
			endpointIP := net.ParseIP(options.Address)
			if endpointIP == nil {
				logger.ErrorContext(ctx, E.New("invalid endpoint address: ", options.Address))
				return
			}
			if useHTTP2 {
				endpoint = &net.TCPAddr{IP: endpointIP, Port: int(endpointPort)}
			} else {
				endpoint = &net.UDPAddr{IP: endpointIP, Port: int(endpointPort)}
			}
		} else {
			endpoint, err = appConfig.SelectEndpointFromConfig(useHTTP2, options.UseIPv6, 443)
			if err != nil {
				logger.ErrorContext(ctx, E.New("failed to select endpoint: ", err))
				return
			}
		}
		var udpTimeout time.Duration
		if options.UDPTimeout != 0 {
			udpTimeout = time.Duration(options.UDPTimeout)
		} else {
			udpTimeout = C.UDPTimeout
		}
		var udpKeepalivePeriod time.Duration
		if options.UDPKeepalivePeriod != 0 {
			udpKeepalivePeriod = time.Duration(options.UDPKeepalivePeriod)
		} else {
			udpKeepalivePeriod = time.Second * 30
		}
		outboundDialer, err := dialer.NewWithOptions(dialer.Options{
			Context:          ctx,
			Options:          options.DialerOptions,
			RemoteIsDomain:   false,
			ResolverOnDetour: true,
		})
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		congestionControl, err := congestion.NewCongestionControl(
			options.CongestionController,
			options.CWND,
			ntp.TimeFuncFromContext(ctx),
		)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		if options.UseL4Proxy {
			outbound.client = masque.NewL4Client(logger, masque.L4ClientOptions{
				Dialer:               outboundDialer,
				TLSConfig:            tlsConfig,
				Endpoint:             endpoint,
				UDPKeepalivePeriod:   udpKeepalivePeriod,
				UDPInitialPacketSize: options.UDPInitialPacketSize,
				HandshakeTimeout:     time.Duration(options.HandshakeTimeout),
				CongestionControl:    congestionControl,
			})
			return
		}
		tunnel, err := masque.NewTunnel(
			ctx,
			logger,
			masque.TunnelOptions{
				System: options.System,
				Name:   options.Name,
				CreateDialer: func(interfaceName string) N.Dialer {
					return common.Must1(dialer.NewDefault(ctx, option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							BindInterface: interfaceName,
						},
					}))
				},
				Dialer: outboundDialer,
				Address: []netip.Prefix{
					netip.MustParsePrefix(appConfig.IPv4 + "/32"),
					netip.MustParsePrefix(appConfig.IPv6 + "/128"),
				},
				AllowedAddress:       options.AllowedIPs,
				Endpoint:             endpoint,
				TLSConfig:            tlsConfig,
				UseHTTP2:             options.UseHTTP2,
				UDPTimeout:           udpTimeout,
				UDPKeepalivePeriod:   udpKeepalivePeriod,
				UDPInitialPacketSize: options.UDPInitialPacketSize,
				ReconnectDelay:       options.ReconnectDelay.Build(),
				HandshakeTimeout:     time.Duration(options.HandshakeTimeout),
				CongestionControl:    congestionControl,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		outbound.client = tunnel
		if err = tunnel.Start(false); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
		if err = tunnel.Start(true); err != nil {
			logger.ErrorContext(ctx, err)
			return
		}
	}
	return outbound, nil
}

func (w *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	scope.Add(func() error {
		if err := w.isTunnelInitialized(w.ctx); err != nil {
			return err
		}
		return w.client.Close()
	})
	go w.startHandler()
	return nil
}

func (w *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := w.isTunnelInitialized(ctx); err != nil {
		return nil, err
	}
	switch network {
	case N.NetworkTCP:
		w.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsDomain() {
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, w.client, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return w.client.DialContext(ctx, network, destination)
}

func (w *Outbound) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	if err := w.isTunnelInitialized(ctx); err != nil {
		return nil, netip.Addr{}, err
	}
	w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsDomain() {
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return N.ListenSerial(ctx, w.client, destination, destinationAddresses)
	}
	packetConn, err := w.client.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return packetConn, destination.Addr, nil
	}
	return packetConn, netip.Addr{}, nil
}

func (w *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := w.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (w *Outbound) isTunnelInitialized(ctx context.Context) error {
	select {
	case <-w.await:
	case <-ctx.Done():
		return ctx.Err()
	}
	if w.client == nil {
		return E.New("tunnel not initialized")
	}
	return nil
}

func (w *Outbound) createConfig() (*Config, error) {
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
	api := cloudflare.NewCloudflareApi(opts...)
	var profile *cloudflare.CloudflareProfile
	var err error
	if w.options.Profile.AuthToken != "" && w.options.Profile.ID != "" {
		profile, err = api.GetProfile(w.ctx, w.options.Profile.AuthToken, w.options.Profile.ID)
		if err != nil {
			return nil, err
		}
	} else {
		wgPrivateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		profile, err = api.CreateProfile(w.ctx, wgPrivateKey.PublicKey().String())
		if err != nil {
			return nil, err
		}
	}
	if w.options.Profile.LicenseKey != "" && profile.Account.License != w.options.Profile.LicenseKey {
		if _, err = api.UpdateAccount(w.ctx, profile.Token, profile.ID, w.options.Profile.LicenseKey); err != nil {
			return nil, E.New("failed to apply license key: ", err)
		}
	}
	privateKey, publicKey, err := masque.GenerateEcKeyPair()
	if err != nil {
		return nil, E.New("failed to generate key pair: ", err)
	}
	updatedProfile, err := api.EnrollKey(w.ctx, profile.Token, profile.ID, cloudflare.KeyTypeMasque, cloudflare.TunTypeMasque, base64.StdEncoding.EncodeToString(publicKey))
	if err != nil {
		return nil, err
	}
	return &Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privateKey),
		EndpointV4:     updatedProfile.Config.Peers[0].Endpoint.V4[:len(updatedProfile.Config.Peers[0].Endpoint.V4)-2],
		EndpointV6:     updatedProfile.Config.Peers[0].Endpoint.V6[1 : len(updatedProfile.Config.Peers[0].Endpoint.V6)-3],
		EndpointH2V4:   cloudflare.DefaultEndpointH2V4,
		EndpointH2V6:   cloudflare.DefaultEndpointH2V6,
		EndpointPubKey: updatedProfile.Config.Peers[0].PublicKey,
		License:        updatedProfile.Account.License,
		ID:             updatedProfile.ID,
		AccessToken:    profile.Token,
		IPv4:           updatedProfile.Config.Interface.Addresses.V4,
		IPv6:           updatedProfile.Config.Interface.Addresses.V6,
	}, nil
}
