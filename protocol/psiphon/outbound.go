package psiphon

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/proxybridge"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/secret"
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
	defaultRemoteServerListURL      = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	defaultRemoteServerListFilename = "remote_server_list"
	defaultSignaturePublicKey       = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
	defaultDataDirectory            = "data/psiphon"
	// the first connection on a censored network downloads a server list and walks the CDN
	// edges; a minute cut it short, and each restart began the walk again
	defaultEstablishTunnelTimeout = 3 * time.Minute
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PsiphonOutboundOptions](registry, C.TypePsiphon, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)
var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	dialer    N.Dialer

	// ctx is the outbound's own: Close cancels it, which ends run. It was the box's context,
	// which a hot reload or a lazy unload does not end, so a closed outbound started its
	// controller again five seconds later, behind its closed proxy bridge.
	ctx     context.Context
	cancel  context.CancelFunc
	runDone chan struct{} // closed when run returns; nil until Start

	mu          sync.RWMutex
	reconnectCh chan struct{}
	psiphon     *Psiphon
	tracker     adapter.StatusTracker //H
	proxy       *proxybridge.Bridge
	scanner     *edgeScanner // H: nil behind a detour, see scannerEnabled
	// fixedNetworkID: network_id, or the config, names the network; the scanner does not
	fixedNetworkID bool
	// establishTimeout is establish_tunnel_timeout, which a search shortens (see h_search.go)
	establishTimeout time.Duration
	options          option.PsiphonOutboundOptions // H: for the first hop by detour, see PreStart
	lastWayPending   bool                          // H: the next attempt is the first of a search: it tries the last way (see h_last_way.go)
}

type tunnelOwner struct{ notify func() }

func (tunnelOwner) SignalSeededNewSLOK() {}
func (o tunnelOwner) SignalTunnelFailure(*psiphon.Tunnel) {
	if o.notify != nil {
		o.notify()
	}
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.PsiphonOutboundOptions) (adapter.Outbound, error) {
	// Psiphon's own connections (its server list, its servers) name domains: resolved here, or
	// by the detour. With false they all failed with "domain not resolved".
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, true)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(options.EstablishTunnelTimeout)
	if timeout <= 0 {
		timeout = defaultEstablishTunnelTimeout
	}
	if strings.TrimSpace(options.Config) == hiddifyConfigName && embeddedHiddifyConfig == "" {
		logger.Warn("this build has no embedded hiddify psiphon config, using the default psiphon config")
	}
	config, err := buildConfig(options, timeout, tag)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	psiphon, err := NewPsiphon(ctx, logger, config, tag)
	if err != nil {
		cancel()
		return nil, err
	}
	outbound := &Outbound{
		cancel:      cancel,
		Adapter:     outbound.NewAdapterWithDialerOptions(C.TypePsiphon, tag, []string{N.NetworkTCP}, options.DialerOptions),
		dialer:      outboundDialer,
		psiphon:     psiphon,
		logger:      logger,
		ctx:         ctx,
		dnsRouter:   service.FromContext[adapter.DNSRouter](ctx),
		reconnectCh: make(chan struct{}, 1),
		options:     options,
		// the network named by the scanner's detection, unless set (see scanEdges)
		fixedNetworkID:   config.NetworkID != defaultNetworkID,
		establishTimeout: timeout,
	}
	if scannerEnabled(options) {
		outbound.useScanner()
	}
	return outbound, nil

}
func (h *Outbound) PreStart() error {
	if h.scanner == nil && scannerByDetour(h.ctx, h.options) { //H: a direct detour: the first hop
		if err := h.firstHopByDetour(); err != nil {
			return err
		}
	}
	if h.scanner != nil { //H: the cache file and the detour exist now
		h.scanner.open(h.ctx, h.options.Detour)
	}
	return h.psiphon.PreStart()
}
func (h *Outbound) Start() error {
	// The Psiphon library opens its own connections. Without this bridge they ignored the
	// outbound's dialer (its detour, e.g. the main proxy), and in VPN mode they went back into
	// the tunnel. Same approach as the Tor outbound.
	if h.psiphon.config.UpstreamProxyURL == "" {
		proxy, err := proxybridge.New(h.ctx, h.logger, "psiphon", h.dialer)
		if err != nil {
			return err
		}
		if err = proxy.Start(); err != nil {
			return err
		}
		h.proxy = proxy
		h.psiphon.config.UpstreamProxyURL = fmt.Sprint("socks5://", proxy.Username(), ":", proxy.Password(), "@127.0.0.1:", proxy.Port())
	}
	runDone := make(chan struct{})
	h.runDone = runDone
	go func() {
		defer close(runDone)
		h.run()
	}()
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
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("UDP is not supported by psiphon outbound")
}

func (h *Outbound) Close() error {
	h.cancel()
	if h.runDone != nil {
		<-h.runDone // run ends with the context, and does not start a controller again
	}
	h.psiphon.Close()
	if h.proxy != nil {
		h.proxy.Close()
	}
	return nil
}

// embeddedHiddifyConfig is the app's Psiphon config, encrypted at build time from the
// CI secret PSIPHON_CONFIG; outbounds use it with config "hiddify".
var embeddedHiddifyConfig string

const hiddifyConfigName = "hiddify"

// resolveConfig returns the Psiphon config JSON for options.Config: "hiddify" (the embedded app
// config), a value encrypted with the build-time key, or plain base64. "{}" means use the defaults.
func resolveConfig(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == hiddifyConfigName {
		value = embeddedHiddifyConfig
	}
	if value == "" {
		return []byte("{}"), nil
	}
	if plaintext, ok := secret.TryDecrypt(value); ok {
		return plaintext, nil
	}
	return decodeBase64Config(value) // not encrypted with this build's key

}

// buildConfig starts from options.Config (see resolveConfig), then
// applies explicit outbound options and fills values left unset with the defaults. The data directory,
// tunnel timeout and local proxies are always managed here.
// instanceDirectory is the name of an outbound's data directory: its tag, made safe for a path.
func instanceDirectory(tag string) string {
	name := []byte(tag)
	for i, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			name[i] = '_'
		}
	}
	if len(name) == 0 || string(name) == "." || string(name) == ".." {
		return "default"
	}
	return string(name)
}

func buildConfig(options option.PsiphonOutboundOptions, timeout time.Duration, tag string) (*psiphon.Config, error) {
	raw, err := resolveConfig(options.Config)
	if err != nil {
		return nil, E.Cause(err, "decode psiphon config")
	}
	config, err := psiphon.LoadConfig(raw)
	if err != nil {
		return nil, E.Cause(err, "parse psiphon config")
	}

	pick := func(explicit, fromConfig, fallback string) string {
		if explicit != "" {
			return explicit
		}
		if fromConfig != "" {
			return fromConfig
		}
		return fallback
	}
	config.PropagationChannelId = pick(options.PropagationChannelID, config.PropagationChannelId, defaultPropagationChannelID)
	config.SponsorId = pick(options.SponsorID, config.SponsorId, defaultSponsorID)
	config.NetworkID = pick(options.NetworkID, config.NetworkID, defaultNetworkID)
	config.ClientPlatform = pick(options.ClientPlatform, config.ClientPlatform, defaultClientPlatform)
	config.ClientVersion = pick(options.ClientVersion, config.ClientVersion, "")
	config.RemoteServerListUrl = pick(options.RemoteServerListURL, config.RemoteServerListUrl, defaultRemoteServerListURL)
	config.RemoteServerListDownloadFilename = pick(options.RemoteServerListDownloadFilename, config.RemoteServerListDownloadFilename, defaultRemoteServerListFilename)
	config.RemoteServerListSignaturePublicKey = pick(options.RemoteServerListSignaturePublicKey, config.RemoteServerListSignaturePublicKey, defaultSignaturePublicKey)
	config.EgressRegion = pick(options.EgressRegion, config.EgressRegion, "")
	config.UpstreamProxyURL = pick(options.UpstreamProxyURL, config.UpstreamProxyURL, "")

	applyTunnelProtocols(config, options)

	config.AllowDefaultDNSResolverWithBindToDevice = true
	if options.AllowDefaultDNSResolverWithBindToDevice != nil {
		config.AllowDefaultDNSResolverWithBindToDevice = *options.AllowDefaultDNSResolverWithBindToDevice
	}
	// the config's own value (0 = wait forever) would hang a failing chain hop
	config.EstablishTunnelTimeoutSeconds = durationToSecondsPtr(timeout)

	dataDir := options.DataDirectory
	if dataDir == "" {
		dataDir = defaultDataDirectory
	}
	// each outbound downloads into a directory of its own: several Psiphon outbounds run at once
	// (one per egress region), and must not write the same server list files. What was kept in
	// the shared directory before is migrated.
	config.DataRootDirectory = filepath.Join(dataDir, instanceDirectory(tag))
	config.MigrateDataStoreDirectory = dataDir
	config.MigrateObfuscatedServerListDownloadDirectory = dataDir
	config.MigrateRemoteServerListDownloadFilename = filepath.Join(dataDir, "server_list_compressed")
	config.DisableLocalHTTPProxy = true
	config.DisableLocalSocksProxy = true
	return config, nil
}

// decodeBase64Config accepts standard or URL-safe base64, with or without padding.
func decodeBase64Config(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	var err error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		var decoded []byte
		if decoded, err = encoding.DecodeString(encoded); err == nil {
			return decoded, nil
		}
	}
	return nil, err
}

func durationToSecondsPtr(duration time.Duration) *int {
	seconds := int(duration / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return &seconds
}

// The controller is started again after it stops (it gives up after the establish timeout, or
// fails), with a backoff between these.
const (
	restartMin = 5 * time.Second
	restartMax = 5 * time.Minute
)

// run keeps a controller running: it starts one, waits until it stops, and starts another. Before,
// a controller that gave up left the outbound dead until the box restarted.
func (h *Outbound) run() {
	backoff := restartMin
	searchStart := time.Now() //H: see h_search.go
	h.lastWayPending = true   //H
	for {
		// H: no network (no Wi-Fi, no mobile data, or paused): wait for one instead of trying,
		// and the wait does not count toward the search
		waited, reachable := edgescan.WaitReachable(h.ctx, h.logger)
		if !reachable {
			return
		}
		searchStart = searchStart.Add(waited)
		h.limitSearch(searchStart) //H
		err := h.connectOnce()
		if err == nil {
			backoff = restartMin // it connected: a later stop starts over quickly
			h.searchFound()      //H
			h.psiphon.Wait()
			err = E.New("the controller stopped")
			searchStart = time.Now() //H: the tunnel was lost: a new search
			h.lastWayPending = true  //H
		}
		h.psiphon.stop()
		if h.ctx.Err() != nil {
			return
		}
		if h.searchExhausted(searchStart) { //H: a deep search is offered, and the normal search goes on
			searchStart = time.Now() //H
		} //H
		h.logger.Warn("psiphon: ", err, ", starting again in ", backoff)
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(backoff):
		case <-h.reconnectCh: //H: a deep search asked for, or another network
			h.searchWoken()                               //H
			searchStart, backoff = time.Now(), restartMin //H
			continue                                      //H
		}
		backoff = min(backoff*2, restartMax)
	}
}

func (h *Outbound) connectOnce() error {
	if h.tryLastWay() { //H
		return nil //H
	} //H
	h.scanEdges()
	return h.psiphon.Start()
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
func (h *Outbound) Status() adapter.Status { //H
	return h.tracker.Status(h.psiphon.IsConnected()) //H
} //H

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.logger.Info("Network Changed... Restarting Psiphon Tunnel")
	h.psiphon.NetworkChanged()
	if h.scanner != nil && h.scanner.store != nil { //H: named again by the next scan
		h.scanner.store.NetworkChanged()
		if !h.psiphon.IsConnected() { //H: a search starts over on the new network, with a scan of it
			h.psiphon.stop()
		}
	}
	h.requestReconnect() //H: a search that gave up starts over on the new network
}
