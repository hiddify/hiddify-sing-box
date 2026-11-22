package masque

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
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
	probes      map[bool]warpscan.Probe // per HTTP/2, with the configured server name
	noises      *masqueNoises           // the TLS and probes of the other server names, see h_noise.go

	status *warpscan.Status

	store   *edgescan.Store // shared with the other scanners on the network, see newMASQUEScanner
	access  sync.Mutex
	book    *warpscan.Book
	network warpscan.NetworkInfo
	cancel  context.CancelFunc // ends the searches with the outbound

	// the search for an endpoint runs in the background, per HTTP/2: the tunnel asks for one
	// while it holds its lock, and gets the one it found at its next ask
	searching map[bool]bool
	found     map[bool]net.Addr
}

// Close ends the searches.
func (s *masqueScanner) Close() {
	s.cancel()
}

func newMASQUEScanner(ctx context.Context, logger log.ContextLogger, key string, options option.MASQUEOutboundOptions, probeDialer N.Dialer, tlsConfig tls.Config, status *warpscan.Status) (*masqueScanner, error) {
	ctx, cancel := context.WithCancel(ctx)
	traceDialer, err := dialer.NewWithOptions(dialer.Options{ // the trace URLs are named by domain
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	scanner := &masqueScanner{
		ctx:         ctx,
		cancel:      cancel,
		searching:   make(map[bool]bool),
		found:       make(map[bool]net.Addr),
		logger:      logger,
		options:     options,
		key:         key,
		traceDialer: traceDialer,
		status:      status,
		probes: map[bool]warpscan.Probe{
			false: warpscan.MASQUEProbe(probeDialer, tlsConfig, false),
			true:  warpscan.MASQUEProbe(probeDialer, tlsConfig, true),
		},
		noises: newMASQUENoises(probeDialer, tlsConfig),
	}
	// the store shared by the scanners that reach the network directly, where the scores kept
	// under the profile's key before join the others
	scanner.store = edgescan.OpenScannerStore(ctx, options.Detour, key+"/edge-scanner")
	scanner.store.Adopt(edgescan.KindWARPMASQUE, key+"/warp-scanner")
	scanner.book = scanner.store.Book(edgescan.KindWARPMASQUE)
	scanner.DetectNetwork(false)
	return scanner, nil
}

// DetectNetwork names the network (see edgescan.Store.Network); changed, after a network change.
func (s *masqueScanner) DetectNetwork(changed bool) {
	if changed {
		s.store.NetworkChanged()
	}
	network := s.store.Network(s.ctx, s.logger, s.traceDialer)
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
	if err := s.store.Save(); err != nil {
		s.logger.WarnContext(s.ctx, "WARP scanner: save scores: ", err)
	}
}

// Scan finds the best answering endpoint of the HTTP version, without exclude, in one round: the
// tunnel's start waits for it.
func (s *masqueScanner) Scan(http2 bool, exclude []netip.AddrPort) (net.Addr, error) {
	s.status.Begin()
	results, noise, err := s.scanRound(s.ctx, http2, exclude, false)
	if err != nil {
		s.status.NotFound()
		return nil, err
	}
	return s.use(results, http2, noise), nil
}

// use takes the best of results, found with noise.
func (s *masqueScanner) use(results []warpscan.Result, http2 bool, noise string) net.Addr {
	best := results[0]
	s.useNoise(http2, noise)
	s.status.Found(best.AddrPort)
	s.logger.InfoContext(s.ctx, "WARP scanner: using ", best.AddrPort, versionSuffix(http2), " (score ", best.Score, ", ", best.RTT, ")")
	return endpointAddr(best.AddrPort, http2)
}

// search finds the best answering endpoint of the HTTP version, without exclude, round after
// round for the search time, or without a limit in a deep search (see edgescan.SearchLimit); an
// exhausted search offers a deep search. The WARP over MASQUE tunnels that search the same network at the
// same time share one search (see edgescan.Store.Do).
func (s *masqueScanner) search(http2 bool, exclude []netip.AddrPort, deepAsked bool) (net.Addr, error) {
	timeout, deep := edgescan.SearchLimit(searchOptions(s.options.Scanner), deepAsked)
	if !edgescan.Direct(s.ctx, s.options.Detour) {
		timeout, deep = -1, false // behind another proxy: one round, as before (see edgescan.Search)
	}
	type found struct { // the endpoints and the noise they answered with
		results []warpscan.Result
		noise   string
	}
	run := func(ctx context.Context) (any, error) {
		var noise string
		results, err := edgescan.Search(ctx, s.logger, timeout, func(ctx context.Context) ([]warpscan.Result, error) {
			results, roundNoise, err := s.scanRound(ctx, http2, exclude, deep)
			if err == nil {
				noise = roundNoise
			}
			return results, err
		})
		return found{results, noise}, err
	}
	s.status.Begin()
	value, err := s.store.Do(s.ctx, s.searchKey(http2, deep), run)
	shared, _ := value.(found)
	results := excludeResults(shared.results, exclude)
	if err == nil && len(results) == 0 { // every answer of the shared search is excluded here
		value, err = run(s.ctx)
		shared, _ = value.(found)
		results = shared.results
	}
	switch {
	case err == nil && len(results) > 0:
		s.status.Exhausted(false)
		if deepAsked {
			s.status.Deep(false)
		}
		return s.use(results, http2, shared.noise), nil
	case errors.Is(err, edgescan.ErrSearchExhausted):
		s.status.NotFound()
		if deepAsked {
			s.status.Deep(false)
		}
		s.status.Exhausted(true)
	default:
		s.status.NotFound()
	}
	if err == nil {
		err = E.New("WARP scanner: nothing answered")
	}
	return nil, err
}

// searchKey names a search for sharing: the network, the HTTP version and the scanner's options.
func (s *masqueScanner) searchKey(http2 bool, deep bool) string {
	content, _ := json.Marshal(struct {
		Scanner any
		IPv6    bool
		Deep    bool
	}{s.options.Scanner, s.options.UseIPv6, deep})
	sum := sha256.Sum256(content)
	return edgescan.KindWARPMASQUE + "|" + s.currentNetwork().Name + versionSuffix(http2) + "|" + hex.EncodeToString(sum[:8])
}

func excludeResults(results []warpscan.Result, exclude []netip.AddrPort) []warpscan.Result {
	if len(exclude) == 0 {
		return results
	}
	kept := make([]warpscan.Result, 0, len(results))
	for _, result := range results {
		if !slices.Contains(exclude, result.AddrPort) {
			kept = append(kept, result)
		}
	}
	return kept
}

// scanRound is one round of a search: with search_noise, one scan per noise until one gets an
// answer (see scanNoises). It returns the noise the endpoints answered with.
func (s *masqueScanner) scanRound(ctx context.Context, http2 bool, exclude []netip.AddrPort, deep bool) ([]warpscan.Result, string, error) {
	network := s.currentNetwork()
	ipv4, ipv6 := network.IPv4, network.IPv6
	if s.options.UseIPv6 {
		ipv4, ipv6 = false, true
	}
	defaults := warpscan.Defaults{CIDRs: warpscan.MASQUEQUICCIDRs, Ports: warpscan.MASQUEPorts}
	if http2 {
		defaults.CIDRs = warpscan.MASQUEHTTP2CIDRs
	}
	networkName := network.Name + versionSuffix(http2)
	results, noise, err := s.scanNoises(ctx, networkName, func(options *masqueScannerOptions, probe warpscan.Probe) ([]warpscan.Result, error) {
		return warpscan.Scan(ctx, s.logger, warpscan.Request{
			Deep:     deep,
			Options:  options,
			Defaults: defaults,
			IPv4:     ipv4,
			IPv6:     ipv6,
			Book:     s.book,
			Network:  networkName,
			Exclude:  exclude,
			Probe:    probe,
		})
	}, http2)
	s.save()
	return results, noise, err
}

// OnConnected counts a connect of the tunnel as an answer of its endpoint.
func (s *masqueScanner) OnConnected(endpoint net.Addr, http2 bool, elapsed time.Duration) {
	if addrPort, ok := addrPortOf(endpoint); ok {
		s.book.Success(s.currentNetwork().Name+versionSuffix(http2), addrPort, elapsed, time.Now())
		s.save()
	}
}

// NextEndpoint looks for another endpoint than failed, and counts the failure once another one
// answers: when none does, the network is down, not the endpoint.
// The tunnel asks while it holds its lock, so it gets one round, and the search goes on in the
// background (see searchInBackground); its endpoint is the answer to the next ask.
func (s *masqueScanner) NextEndpoint(failed net.Addr, http2 bool) net.Addr {
	addrPort, ok := addrPortOf(failed)
	s.access.Lock()
	next := s.found[http2]
	delete(s.found, http2)
	s.access.Unlock()
	if next == nil || next.String() == failed.String() {
		var exclude []netip.AddrPort
		if ok {
			exclude = append(exclude, addrPort)
		}
		s.status.Begin()
		results, noise, err := s.scanRound(s.ctx, http2, exclude, false)
		if err != nil {
			s.status.NotFound()
			s.logger.WarnContext(s.ctx, err, ", keeping ", failed, "; searching on")
			s.searchInBackground(http2, exclude, false)
			return nil
		}
		next = s.use(results, http2, noise)
	}
	if ok {
		s.book.Failure(s.currentNetwork().Name+versionSuffix(http2), addrPort, time.Now())
		s.save()
	}
	return next
}

// searchInBackground searches for an endpoint of the HTTP version for the search time, or as the
// deep search the user asked for, unless one runs; the tunnel takes what it finds at its next ask
// for an endpoint. It ends with the outbound.
func (s *masqueScanner) searchInBackground(http2 bool, exclude []netip.AddrPort, deepAsked bool) {
	s.access.Lock()
	if s.searching[http2] {
		s.access.Unlock()
		return
	}
	s.searching[http2] = true
	s.access.Unlock()
	go func() {
		next, err := s.search(http2, exclude, deepAsked)
		if err != nil && !deepAsked && s.status.IsDeep() && s.ctx.Err() == nil {
			// a deep search was asked for while this one ran: it goes on as that one
			next, err = s.search(http2, exclude, true)
		}
		s.access.Lock()
		s.searching[http2] = false
		if err == nil {
			s.found[http2] = next
		}
		s.access.Unlock()
		if err != nil && s.ctx.Err() == nil {
			s.logger.WarnContext(s.ctx, err)
		}
	}()
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

// selectEndpoints picks the HTTP/3 and, for auto, the HTTP/2 endpoint (both at once): peer when
// it is set (the warp endpoint's server and server_port), the scanner's choice when it finds
// one, otherwise the profile's. The profile has no HTTP/2 IPv6 endpoint, so with use_ipv6 and no
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
		return config.SelectEndpointFromConfig(http2, useIPv6, config.port())
	}
	if mode != masque.ModeAuto {
		endpoint, err := choose(mode == masque.ModeHTTP2)
		if err != nil {
			return nil, nil, "", err
		}
		return endpoint, nil, mode, nil
	}
	// auto: HTTP/3 (QUIC over UDP) and HTTP/2 (TLS over TCP) are scanned at once, so a network
	// that drops UDP does not wait out the whole HTTP/3 scan before HTTP/2 is looked for
	var (
		h2Err error
		wait  sync.WaitGroup
	)
	wait.Add(1)
	go func() {
		defer wait.Done()
		h2Endpoint, h2Err = choose(true)
	}()
	endpoint, err := choose(false)
	wait.Wait()
	if err != nil {
		if h2Err != nil {
			return nil, nil, "", err
		}
		logger.WarnContext(ctx, "no HTTP/3 endpoint (", err, "), using HTTP/2 only")
		return h2Endpoint, nil, masque.ModeHTTP2, nil
	}
	if h2Err != nil {
		logger.WarnContext(ctx, "no HTTP/2 endpoint (", h2Err, "), using HTTP/3 only")
		return endpoint, nil, masque.ModeHTTP3, nil
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
