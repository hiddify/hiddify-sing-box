package psiphon

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	defaultPropagationChannelID     = "FFFFFFFFFFFFFFFF"
	defaultSponsorID                = "FFFFFFFFFFFFFFFF"
	defaultNetworkID                = "test"
	defaultClientPlatform           = "Android_4.0.4_com.example.exampleClientLibraryApp"
	defaultRemoteServerListURL      = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	defaultRemoteServerListFilename = "remote_server_list"
	defaultSignaturePublicKey       = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
	defaultDataDirectory            = "data/psiphon"
	defaultEstablishTunnelTimeout   = time.Minute
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PsiphonOutboundOptions](registry, C.TypePsiphon, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	dialer    N.Dialer

	ctx context.Context

	mu          sync.RWMutex
	reconnectCh chan struct{}
	psiphon     *Psiphon
}

type tunnelOwner struct{ notify func() }

func (tunnelOwner) SignalSeededNewSLOK() {}
func (o tunnelOwner) SignalTunnelFailure(*psiphon.Tunnel) {
	if o.notify != nil {
		o.notify()
	}
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.PsiphonOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(options.EstablishTunnelTimeout)
	if timeout <= 0 {
		timeout = defaultEstablishTunnelTimeout
	}
	config := buildConfig(options, timeout)
	psiphon, err := NewPsiphon(ctx, logger, config)
	if err != nil {

		return nil, err
	}
	outbound := &Outbound{
		Adapter:     outbound.NewAdapterWithDialerOptions(C.TypePsiphon, tag, []string{N.NetworkTCP}, options.DialerOptions),
		dialer:      outboundDialer,
		psiphon:     psiphon,
		logger:      logger,
		ctx:         ctx,
		dnsRouter:   service.FromContext[adapter.DNSRouter](ctx),
		reconnectCh: make(chan struct{}, 1),
	}

	return outbound, nil

}
func (h *Outbound) PreStart() error {
	return h.psiphon.PreStart()
}
func (h *Outbound) Start() error {

	go h.run()
	return nil
}

//	func (h *Outbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
//		// return h.psiphon.Dial(dst, innerConn)
//	}
func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	// h.logger.Debug("diallign outboud ", h.Tag(), " to ", destination)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		// h.mu.RLock()
		// current := h.tunnel
		// h.mu.RUnlock()
		// if current == nil || !current.IsActivated() {
		// 	return nil, E.New("psiphon tunnel is not established")
		// }
	case N.NetworkUDP:
		return nil, E.New("UDP is not supported by psiphon outbound")
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	dst := destination.String()
	// if destination.IsFqdn() {
	// 	destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
	// 	if err != nil || len(destinationAddresses) == 0 {
	// 		return nil, err
	// 	}
	// 	dst = fmt.Sprintf("%s:%d", destinationAddresses[0].String(), destination.Port)
	// 	// return N.DialSerial(ctx, h.client, network, destination, destinationAddresses)
	// }
	h.logger.Debug("dialed destination ", destination, "(", dst, ") through outbound ", h.Tag(), ", now dialing through psiphon tunnel")

	// innerConn, err := h.dialer.DialContext(ctx, "tcp", destination)
	// if err != nil {
	// 	return nil, E.New(err, "failed to dial destination ", destination, " through outbound ", h.Tag())
	// }
	return h.psiphon.Dial(dst, nil)

	// dialConf := psiphon.DialConfig{
	// 	// CustomDialer: *h.dialer,
	// 	ResolveIP: func(context.Context, string) ([]net.IP, error) {
	// 		if !destination.IsFqdn() {
	// 			return []net.IP{netipAddrToIP(destination.Addr)}, nil
	// 		}
	// 		res, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
	// 		if err != nil {
	// 			return nil, err
	// 		}

	// 		ips := make([]net.IP, 0, len(res))
	// 		for _, r := range res {
	// 			ips = append(ips, netipAddrToIP(r))
	// 		}
	// 		return ips, nil

	// 		// return []net.IP{
	// 		// 	net.IPv4(1, 1, 1, 1),
	// 		// }, nil
	// 		// return nil, E.New("psiphon outbound does not support custom DNS resolution")
	// 	},
	// }
	// return psiphon.DialTCP(ctx, destination.String(), &dialConf)

}
func netipAddrToIP(a netip.Addr) net.IP {
	if !a.IsValid() {
		return nil
	}

	if a.Is4() {
		ip := a.As4()
		return net.IP(ip[:])
	}

	ip := a.As16()
	return net.IP(ip[:])
}
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("UDP is not supported by psiphon outbound")
}

func (h *Outbound) Close() error {

	h.psiphon.Close()

	return nil
}

func buildConfig(options option.PsiphonOutboundOptions, timeout time.Duration) *psiphon.Config {
	dataDir := options.DataDirectory
	if dataDir == "" {
		dataDir = defaultDataDirectory
	}
	allowDefaultDNS := true
	if options.AllowDefaultDNSResolverWithBindToDevice != nil {
		allowDefaultDNS = *options.AllowDefaultDNSResolverWithBindToDevice
	}
	remoteListFilename := options.RemoteServerListDownloadFilename
	if remoteListFilename == "" {
		remoteListFilename = defaultRemoteServerListFilename
	}
	remoteListURL := options.RemoteServerListURL
	if remoteListURL == "" {
		remoteListURL = defaultRemoteServerListURL
	}
	signatureKey := options.RemoteServerListSignaturePublicKey
	if signatureKey == "" {
		signatureKey = defaultSignaturePublicKey
	}
	propagationChannelID := options.PropagationChannelID
	if propagationChannelID == "" {
		propagationChannelID = defaultPropagationChannelID
	}
	sponsorID := options.SponsorID
	if sponsorID == "" {
		sponsorID = defaultSponsorID
	}
	networkID := options.NetworkID
	if networkID == "" {
		networkID = defaultNetworkID
	}
	clientPlatform := options.ClientPlatform
	if clientPlatform == "" {
		clientPlatform = defaultClientPlatform
	}
	establishTimeoutSeconds := durationToSecondsPtr(timeout)
	config := &psiphon.Config{
		DataRootDirectory:                            dataDir,
		EgressRegion:                                 options.EgressRegion,
		PropagationChannelId:                         propagationChannelID,
		RemoteServerListDownloadFilename:             remoteListFilename,
		RemoteServerListSignaturePublicKey:           signatureKey,
		RemoteServerListUrl:                          remoteListURL,
		SponsorId:                                    sponsorID,
		NetworkID:                                    networkID,
		ClientPlatform:                               clientPlatform,
		ClientVersion:                                options.ClientVersion,
		AllowDefaultDNSResolverWithBindToDevice:      allowDefaultDNS,
		EstablishTunnelTimeoutSeconds:                establishTimeoutSeconds,
		DisableLocalHTTPProxy:                        true,
		DisableLocalSocksProxy:                       true,
		MigrateDataStoreDirectory:                    dataDir,
		MigrateObfuscatedServerListDownloadDirectory: dataDir,
		MigrateRemoteServerListDownloadFilename:      filepath.Join(dataDir, "server_list_compressed"),
	}
	if options.UpstreamProxyURL != "" {
		config.UpstreamProxyURL = options.UpstreamProxyURL
	}
	return config
}

func durationToSecondsPtr(duration time.Duration) *int {
	seconds := int(duration / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return &seconds
}

func (h *Outbound) run() {
	h.connectOnce()
	// defer h.closeDataStore()
	// for {
	// 	if h.ctx.Err() != nil {
	// 		return
	// 	}
	// 	if h.psiphon.IsConnected() {
	// 		h.logger.Debug("psiphon tunnel is active")
	// 		select {
	// 		case <-h.ctx.Done():
	// 			return
	// 		case <-h.reconnectCh:
	// 			h.resetTunnel()
	// 		}
	// 		continue
	// 	}
	// 	h.logger.Debug("psiphon tunnel is not active, trying to connect")
	// 	if err := h.connectOnce(); err != nil {
	// 		h.logger.Warn("psiphon connect failed: ", err)
	// 		select {
	// 		case <-h.ctx.Done():
	// 			return
	// 		case <-time.After(5 * time.Second):
	// 		}
	// 		continue
	// 	}
	// }
}

func (p *Outbound) DisplayType() string {
	str := "⚠️ Connecting..."
	if p.psiphon.IsConnected() {
		str = "✔️ Connected"
	}
	return C.ProxyDisplayName(p.Type()) + " " + str
}

func (h *Outbound) connectOnce() error {

	err := h.psiphon.Start()
	if err != nil {
		return err
	}
	monitoring.Get(h.ctx).TestNow(h.Tag())
	// return h.connectOnce()
	return nil
}

// func (h *Outbound) connectOnce() error {
// 	ti := time.Now().Add(h.timeout)
// 	tunnel, err := psiphon.ConnectTunnel(h.ctx, h.config, ti, &psiphon.DialParameters{

// 	})
// 	if err != nil {
// 		return err
// 	}
// 	owner := tunnelOwner{notify: h.requestReconnect}
// 	if err = tunnel.Activate(h.ctx, owner, false); err != nil {
// 		tunnel.Close(true)
// 		return err
// 	}
// 	h.mu.Lock()
// 	h.tunnel = tunnel
// 	h.mu.Unlock()
// 	return nil
// }

func (h *Outbound) requestReconnect() {
	select {
	case h.reconnectCh <- struct{}{}:
	default:
	}
}
func (h *Outbound) IsReady() bool {
	return h.psiphon.IsConnected()
}
