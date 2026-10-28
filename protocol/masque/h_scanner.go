package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const defaultServerName = "consumer-masque.cloudflareclient.com"

// tunnelMode returns the HTTP version from vhttp, and use_http2 when vhttp is empty.
func tunnelMode(options option.MASQUEOutboundOptions) (string, error) {
	switch options.VHTTP {
	case "":
		if options.UseHTTP2 {
			return masque.ModeHTTP2, nil
		}
		return masque.ModeAuto, nil
	case masque.ModeHTTP3, masque.ModeHTTP2, masque.ModeAuto:
		return options.VHTTP, nil
	}
	return "", E.New("unknown vhttp: ", options.VHTTP, ` (expected "h3", "h2" or "auto")`)
}

// masqueScanner keeps the endpoint scores of a masque outbound (see warpscan.Book) and finds
// endpoints that answer, per HTTP version.
type masqueScanner struct {
	ctx         context.Context
	logger      log.ContextLogger
	options     option.MASQUEOutboundOptions
	key         string
	traceDialer N.Dialer
	probes      map[bool]warpscan.Probe // per HTTP/2

	status *warpscan.Status

	access  sync.Mutex
	book    *warpscan.Book
	network warpscan.NetworkInfo
}

func newMASQUEScanner(ctx context.Context, logger log.ContextLogger, key string, options option.MASQUEOutboundOptions, probeDialer N.Dialer, tlsConfig tls.Config, status *warpscan.Status) (*masqueScanner, error) {
	traceDialer, err := dialer.NewWithOptions(dialer.Options{ // the trace URLs are named by domain
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, err
	}
	scanner := &masqueScanner{
		ctx:         ctx,
		logger:      logger,
		options:     options,
		key:         key,
		traceDialer: traceDialer,
		status:      status,
		probes: map[bool]warpscan.Probe{
			false: warpscan.MASQUEProbe(probeDialer, tlsConfig, false),
			true:  warpscan.MASQUEProbe(probeDialer, tlsConfig, true),
		},
		book: warpscan.Load(service.FromContext[adapter.CacheFile](ctx), key),
	}
	scanner.DetectNetwork()
	return scanner, nil
}

func (s *masqueScanner) DetectNetwork() {
	network := warpscan.DetectNetwork(s.ctx, s.logger, s.traceDialer)
	s.access.Lock()
	s.network = network
	s.access.Unlock()
}

func (s *masqueScanner) currentNetwork() warpscan.NetworkInfo {
	s.access.Lock()
	defer s.access.Unlock()
	return s.network
}

func (s *masqueScanner) save() {
	if err := warpscan.Save(service.FromContext[adapter.CacheFile](s.ctx), s.key, s.book); err != nil {
		s.logger.WarnContext(s.ctx, "WARP scanner: save scores: ", err)
	}
}

// Scan finds the best answering endpoint of the HTTP version, without exclude.
func (s *masqueScanner) Scan(http2 bool, exclude []netip.AddrPort) (net.Addr, error) {
	network := s.currentNetwork()
	ipv4, ipv6 := network.IPv4, network.IPv6
	if s.options.UseIPv6 {
		ipv4, ipv6 = false, true
	}
	defaults := warpscan.Defaults{CIDRs: warpscan.MASQUEQUICCIDRs, Ports: warpscan.MASQUEPorts}
	if http2 {
		defaults.CIDRs = warpscan.MASQUEHTTP2CIDRs
	}
	s.status.Begin()
	results, err := warpscan.Scan(s.ctx, s.logger, warpscan.Request{
		Options:  s.options.Scanner,
		Defaults: defaults,
		IPv4:     ipv4,
		IPv6:     ipv6,
		Book:     s.book,
		Network:  network.Name + versionSuffix(http2),
		Exclude:  exclude,
		Probe:    s.probes[http2],
	})
	s.save()
	if err != nil {
		s.status.NotFound()
		return nil, err
	}
	best := results[0]
	s.status.Found(best.AddrPort)
	s.logger.InfoContext(s.ctx, "WARP scanner: using ", best.AddrPort, versionSuffix(http2), " (score ", best.Score, ", ", best.RTT, ")")
	return endpointAddr(best.AddrPort, http2), nil
}

// OnConnected counts a connect of the tunnel as an answer of its endpoint.
func (s *masqueScanner) OnConnected(endpoint net.Addr, http2 bool, elapsed time.Duration) {
	if addrPort, ok := addrPortOf(endpoint); ok {
		s.book.Success(s.currentNetwork().Name+versionSuffix(http2), addrPort, elapsed, time.Now())
		s.save()
	}
}

// NextEndpoint counts the failure of endpoint and looks for another one.
func (s *masqueScanner) NextEndpoint(failed net.Addr, http2 bool) net.Addr {
	addrPort, ok := addrPortOf(failed)
	if ok {
		s.book.Failure(s.currentNetwork().Name+versionSuffix(http2), addrPort, time.Now())
	}
	next, err := s.Scan(http2, []netip.AddrPort{addrPort})
	if err != nil {
		s.logger.WarnContext(s.ctx, err, ", keeping ", failed)
		return nil
	}
	return next
}

// HTTP/3 and HTTP/2 endpoints are scored apart: they are different servers.
func versionSuffix(http2 bool) string {
	if http2 {
		return "/h2"
	}
	return "/h3"
}

func endpointAddr(addrPort netip.AddrPort, http2 bool) net.Addr {
	if http2 {
		return net.TCPAddrFromAddrPort(addrPort)
	}
	return net.UDPAddrFromAddrPort(addrPort)
}

func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addr.AddrPort(), true
	case *net.TCPAddr:
		return addr.AddrPort(), true
	}
	return netip.AddrPort{}, false
}

// selectEndpoints picks the HTTP/3 and, for auto, the HTTP/2 endpoint: peer when it is set
// (the warp endpoint's server and server_port), the scanner's choice when it finds one,
// otherwise the profile's. The profile has no HTTP/2 IPv6 endpoint, so with use_ipv6 and no
// scanner result auto keeps to HTTP/3 instead of failing.
func selectEndpoints(ctx context.Context, logger log.ContextLogger, config *Config, mode string, useIPv6 bool, peer M.Socksaddr, scan func(http2 bool) (net.Addr, error)) (endpoint net.Addr, h2Endpoint net.Addr, _ string, _ error) {
	choose := func(http2 bool) (net.Addr, error) {
		if hasPeer(peer) {
			return fixedEndpoint(config, peer, http2, useIPv6)
		}
		if scan != nil {
			scanned, err := scan(http2)
			if err == nil {
				return scanned, nil
			}
			logger.WarnContext(ctx, err, ", using the profile's endpoint")
		}
		return config.SelectEndpointFromConfig(http2, useIPv6, profilePort)
	}
	endpoint, err := choose(mode == masque.ModeHTTP2)
	if err != nil {
		return nil, nil, "", err
	}
	if mode == masque.ModeAuto {
		h2Endpoint, err = choose(true)
		if err != nil {
			logger.WarnContext(ctx, "no HTTP/2 endpoint (", err, "), using HTTP/3 only")
			return endpoint, nil, masque.ModeHTTP3, nil
		}
	}
	return endpoint, h2Endpoint, mode, nil
}

// profilePort is the port of the profile's MASQUE endpoints.
const profilePort = 443

// fixedEndpoint is peer, with the profile's address when peer has only a port.
func fixedEndpoint(config *Config, peer M.Socksaddr, http2 bool, useIPv6 bool) (net.Addr, error) {
	port := peer.Port
	if port == 0 {
		port = profilePort
	}
	if !peer.Addr.IsValid() {
		return config.SelectEndpointFromConfig(http2, useIPv6, int(port))
	}
	return endpointAddr(netip.AddrPortFrom(peer.Addr, port), http2), nil
}
