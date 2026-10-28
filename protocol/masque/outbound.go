package masque

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// The registration of a WARP device is retried with a backoff between these.
const (
	registerRetryMin = time.Second
	registerRetryMax = 30 * time.Second
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MASQUEOutboundOptions](registry, C.TypeMASQUE, NewOutbound)
}

// Outbound is a MASQUE tunnel to Cloudflare WARP. It registers a device itself, unless the warp
// endpoint passes the one it registered (NewWARPOutbound). A self-hosted MASQUE server is
// reached with masque-client.
type Outbound struct {
	outbound.Adapter
	ctx          context.Context
	dnsRouter    adapter.DNSRouter
	logger       logger.ContextLogger
	options      option.MASQUEOutboundOptions
	tunnel       *masque.Tunnel
	startHandler func()
	scanner      *masqueScanner //H

	warpConfig  *Config     // the device of the warp endpoint, which registered it
	peer        M.Socksaddr // the endpoint of the warp endpoint's server and server_port
	profileKey  string
	scanStatus  warpscan.Status
	done        chan struct{}
	tracker     adapter.StatusTracker
	registering atomic.Bool // a device is being registered
	doneOnce    sync.Once
	closeOnce   sync.Once

	await chan struct{}
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEOutboundOptions) (adapter.Outbound, error) {
	return newWARPOutbound(ctx, logger, tag, options, nil, M.Socksaddr{}, "")
}

// NewWARPOutbound creates a MASQUE tunnel to WARP for the warp endpoint, with the device it
// registered and the endpoint it chose (unset for the profile's). profileKey names the scanner
// scores.
func NewWARPOutbound(ctx context.Context, logger log.ContextLogger, tag string, options option.MASQUEOutboundOptions, config *Config, peer M.Socksaddr, profileKey string) (*Outbound, error) {
	if config == nil {
		return nil, E.New("missing WARP MASQUE config")
	}
	return newWARPOutbound(ctx, logger, tag, options, config, peer, profileKey)
}

func newWARPOutbound(ctx context.Context, logger log.ContextLogger, tag string, options option.MASQUEOutboundOptions, config *Config, peer M.Socksaddr, profileKey string) (*Outbound, error) {
	if _, err := tunnelMode(options); err != nil { // a wrong vhttp fails the config, not the start
		return nil, err
	}
	if profileKey == "" {
		profileKey = options.UniqueIdentifier //H: unique_identifier, so renaming the outbound keeps the device
	}
	if profileKey == "" {
		profileKey = tag
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeMASQUE, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:        ctx,
		dnsRouter:  service.FromContext[adapter.DNSRouter](ctx),
		logger:     logger,
		options:    options,
		warpConfig: config,
		peer:       peer,
		profileKey: profileKey,
		done:       make(chan struct{}),
		await:      make(chan struct{}),
	}
	outbound.startHandler = func() {
		defer close(outbound.await)
		appConfig := outbound.warpConfig
		if appConfig == nil {
			var ok bool
			appConfig, ok = outbound.loadOrRegister()
			if !ok {
				return
			}
		}
		if err := outbound.startTunnel(appConfig); err != nil {
			logger.ErrorContext(ctx, err)
		}
		if outbound.isClosed() { // closed while the tunnel was set up
			outbound.closeTunnel()
		}
	}
	return outbound, nil
}

// loadOrRegister returns the saved device, or registers one, retrying until it works or the
// outbound closes.
func (w *Outbound) loadOrRegister() (*Config, bool) {
	cacheFile := service.FromContext[adapter.CacheFile](w.ctx)
	if !w.options.Profile.Recreate && cacheFile != nil && cacheFile.StoreMASQUEConfig() {
		if savedProfile := cacheFile.LoadBinary(w.profileKey); savedProfile != nil {
			var appConfig *Config
			if err := json.Unmarshal(savedProfile.Content, &appConfig); err == nil {
				return appConfig, true
			} else {
				w.logger.ErrorContext(w.ctx, E.Cause(err, "load WARP MASQUE device, registering a new one"))
			}
		}
	}
	w.registering.Store(true)
	defer w.registering.Store(false)
	backoff := registerRetryMin
	for {
		appConfig, err := w.createConfig()
		if err == nil {
			if cacheFile != nil && cacheFile.StoreMASQUEConfig() {
				if content, err := json.Marshal(appConfig); err != nil {
					w.logger.ErrorContext(w.ctx, err)
				} else {
					cacheFile.SaveBinary(w.profileKey, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content})
				}
			}
			return appConfig, true
		}
		w.logger.ErrorContext(w.ctx, E.Cause(err, "register WARP MASQUE device"))
		select {
		case <-w.ctx.Done():
			return nil, false
		case <-w.done:
			return nil, false
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, registerRetryMax)
	}
}

// startTunnel starts the tunnel to WARP with the device in appConfig.
func (w *Outbound) startTunnel(appConfig *Config) error {
	ctx, logger, options := w.ctx, w.logger, w.options
	privKey, err := appConfig.GetEcPrivateKey()
	if err != nil {
		return E.New("failed to get private key: ", err)
	}
	peerPubKey, err := appConfig.GetEcEndpointPublicKey()
	if err != nil {
		return E.New("failed to get public key: ", err)
	}
	cert, err := masque.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return E.New("failed to generate cert: ", err)
	}
	serverName := options.ServerName //H
	if serverName == "" {
		serverName = defaultServerName
	}
	mode, err := tunnelMode(options)
	if err != nil {
		return err
	}
	tlsConfig, err := tls.NewMASQUEClient(ctx, logger, serverName, cert, privKey, peerPubKey, options.MASQUEOutboundTLSOptions) //H
	if err != nil {
		return E.New("failed to prepare TLS config: ", err)
	}
	udpTimeout := C.UDPTimeout
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	}
	udpKeepalivePeriod := 30 * time.Second
	if options.UDPKeepalivePeriod != 0 {
		udpKeepalivePeriod = time.Duration(options.UDPKeepalivePeriod)
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   false,
		ResolverOnDetour: true,
	})
	if err != nil {
		return err
	}
	addresses, err := appConfig.Addresses()
	if err != nil {
		return err
	}
	var scanner *masqueScanner
	var scan func(http2 bool) (net.Addr, error)
	if options.Scanner != nil && options.Scanner.Enabled && !hasPeer(w.peer) { //H: look for endpoints that answer
		scanner, err = newMASQUEScanner(ctx, logger, w.profileKey, options, outboundDialer, tlsConfig, &w.scanStatus)
		if err != nil {
			logger.WarnContext(ctx, "WARP scanner: ", err)
			scanner = nil
		} else {
			scan = func(http2 bool) (net.Addr, error) { return scanner.Scan(http2, nil) }
		}
	}
	peer := w.peer
	if peer.IsFqdn() { // the warp endpoint's server is a domain
		addresses, err := w.dnsRouter.Lookup(ctx, peer.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return E.Cause(err, "resolve WARP server ", peer.Fqdn)
		}
		peer = M.SocksaddrFrom(addresses[0], peer.Port)
	}
	endpoint, h2Endpoint, mode, err := selectEndpoints(ctx, logger, appConfig, mode, options.UseIPv6, peer, scan)
	if err != nil {
		return E.New("failed to select endpoint: ", err)
	}
	tunnel, err := masque.NewTunnel(ctx, logger, masque.TunnelOptions{
		Dialer:               outboundDialer,
		Address:              addresses,
		Endpoint:             endpoint,
		TLSConfig:            tlsConfig,
		UseHTTP2:             mode == masque.ModeHTTP2,
		Mode:                 mode,
		H2Endpoint:           h2Endpoint,
		UDPTimeout:           udpTimeout,
		UDPKeepalivePeriod:   udpKeepalivePeriod,
		UDPInitialPacketSize: options.UDPInitialPacketSize,
		MTU:                  options.MTU,
		ReconnectDelay:       options.ReconnectDelay.Build(),
	})
	if err != nil {
		return err
	}
	if scanner != nil { //H: scores and failover
		tunnel.SetFailover(scanner.OnConnected, scanner.NextEndpoint)
		w.scanner = scanner
	}
	w.tunnel = tunnel
	if err = tunnel.Start(false); err != nil {
		return err
	}
	// the tunnel connects, and reconnects, by itself
	if err = tunnel.Start(true); err != nil {
		return err
	}
	w.followDetour()
	return nil
}

// followDetour reconnects the tunnel when a group detour moves to another member: the tunnel
// keeps its connection on the member it was opened through.
func (w *Outbound) followDetour() {
	if w.options.Detour == "" {
		return
	}
	outboundManager := service.FromContext[adapter.OutboundManager](w.ctx)
	if outboundManager == nil {
		return
	}
	detour, loaded := outboundManager.Outbound(w.options.Detour)
	if !loaded {
		return
	}
	network := N.NetworkUDP
	if mode, _ := tunnelMode(w.options); mode == masque.ModeHTTP2 {
		network = N.NetworkTCP
	}
	monitoring.FollowDetour(w.ctx, w.done, detour, network, func(from string, to string) {
		w.logger.InfoContext(w.ctx, "detour moved from ", from, " to ", to, ", reconnecting")
		w.tunnel.ResetConnection()
	})
}

func (w *Outbound) isClosed() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

// Status is registering while a device is registered; ready while the tunnel has a connection
// to the server, not once it is set up;
// searching while the scanner looks for an endpoint; reconnecting after it was ready; failed
// when the tunnel could not be set up. //H
func (w *Outbound) Status() adapter.Status {
	select {
	case <-w.await:
	default:
		if w.registering.Load() {
			return adapter.StatusRegistering
		}
		if w.scanStatus.IsScanning() {
			return adapter.StatusSearching
		}
		return adapter.StatusConnecting
	}
	if w.tunnel == nil {
		return adapter.StatusFailed
	}
	if !w.tunnel.IsConnected() && w.scanStatus.IsScanning() {
		return adapter.StatusSearching
	}
	return w.tracker.Status(w.tunnel.IsConnected())
}

// DisplayType names the tunnel and the scanner status. //H
func (w *Outbound) DisplayType() string {
	return C.DisplayWARPMASQUE + w.scanStatus.String()
}

// ScanStatus is the status of the scanner, for the warp endpoint's display type. //H
func (w *Outbound) ScanStatus() *warpscan.Status {
	return &w.scanStatus
}

func (w *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(w.Close) // H: closed with the box
	}
	if stage != adapter.StartStatePostStart {
		return nil
	}
	go w.startHandler()
	return nil
}

func (w *Outbound) Close() error {
	w.doneOnce.Do(func() { close(w.done) }) // ends a registration in progress
	select {
	case <-w.await:
		return w.closeTunnel()
	default:
		return nil // not started, or the start handler closes the tunnel once set up
	}
}

func (w *Outbound) closeTunnel() error {
	var err error
	w.closeOnce.Do(func() {
		if w.tunnel != nil {
			err = w.tunnel.Close()
		}
	})
	return err
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
		return N.DialSerial(ctx, w.tunnel, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return w.tunnel.DialContext(ctx, network, destination)
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
		return N.ListenSerial(ctx, w.tunnel, destination, destinationAddresses)
	}
	packetConn, err := w.tunnel.ListenPacket(ctx, destination)
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
	if w.tunnel == nil {
		return E.New("tunnel not initialized")
	}
	return nil
}

// InterfaceUpdated reconnects the tunnel on the new network, after naming it for the scores. //H
func (w *Outbound) InterfaceUpdated(ctx context.Context) {
	select {
	case <-w.await:
	default:
		return
	}
	if w.tunnel == nil {
		return
	}
	go func() {
		if w.scanner != nil {
			w.scanner.DetectNetwork()
		}
		w.tunnel.ResetConnection()
	}()
}

// hasPeer reports whether the warp endpoint fixed the server, its port, or both.
func hasPeer(peer M.Socksaddr) bool {
	return peer.IsValid() || peer.Port != 0
}
