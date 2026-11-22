package psiphon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	utls "github.com/refraction-networking/utls"
)

// The scanner (see option.PsiphonScannerOptions) finds the CDN edges Psiphon can front through
// on this network, with the engine of the WARP scanner: its per-network scores, its walk of the
// candidate space and its network detection. Psiphon's own scan (the fork's CDN fronting scan)
// tries each edge with a full tunnel dial, a few at a time; a TLS handshake tells first, and in
// a fraction of the time, which edges and server names the network lets through. The tunnel core
// then dials those first, and reports the one it connected over, which gains points here.

const (
	scannerName              = "Psiphon scanner"
	scannerStoreSuffix       = "/psiphon-scanner"
	defaultScannerCandidates = 2 // per CDN
	cdnPort                  = 443
)

var scannerDefaults = option.WARPScannerOptions{
	MaxRTT:      badoption.Duration(2 * time.Second),
	Timeout:     badoption.Duration(3 * time.Second),
	Count:       256,
	Concurrency: edgescan.PlatformDefault(16, 48),
}

type cdnEdgeSet struct {
	name        string
	cidrs       []string
	serverNames []string
}

type edgeScanner struct {
	ctx     context.Context
	logger  log.ContextLogger
	dialer  N.Dialer
	options option.PsiphonScannerOptions
	key     string
	port    uint16 // the edges' port: cdnPort, another in tests

	// resolve looks a server name up (the box's DNS); nil leaves the scan without seeds
	resolve func(ctx context.Context, name string) ([]netip.Addr, error)

	store   *edgescan.Store // shared with the other scanners on the network, see newEdgeScanner
	access  sync.Mutex
	book    *edgescan.Book
	network edgescan.NetworkInfo
	status  edgescan.Status
	// seedSets are the sets of the seeds of the last scan, by address
	seedSets map[netip.Addr]string
	// lastEdge is the edge the tunnel core connected over in this attempt (see h_last_way.go)
	lastEdge edgescan.Target
}

const (
	// seedNames is the number of server names of each set resolved for seeds
	seedNames   = 6
	seedTimeout = 3 * time.Second
)

// seeds resolves a few server names of each set: the addresses they resolve to are live edges of
// that CDN, where most addresses of its ranges do not answer (one Fastly address in many does).
// The sets take turns, so each has its seeds early. Names that are not real (".redirect") and
// addresses that are not public (a poisoned answer) are left out.
func (s *edgeScanner) seeds(sets []edgescan.Set) ([]edgescan.Target, map[netip.Addr]string) {
	if s.resolve == nil || len(s.options.CIDRs) > 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(s.ctx, seedTimeout)
	defer cancel()
	type lookup struct {
		set, name string
		addresses []netip.Addr
	}
	perSet := make([][]*lookup, len(sets))
	var wait sync.WaitGroup
	for i, set := range sets {
		for _, name := range seedOrder(set) {
			if name == "" || strings.HasSuffix(name, ".redirect") || len(perSet[i]) >= seedNames {
				continue
			}
			entry := &lookup{set: set.Name, name: name}
			perSet[i] = append(perSet[i], entry)
			wait.Add(1)
			go func() {
				defer wait.Done()
				addresses, err := s.resolve(ctx, entry.name)
				if err == nil {
					entry.addresses = addresses
				}
			}()
		}
	}
	wait.Wait()
	var seeds []edgescan.Target
	setOf := map[netip.Addr]string{}
	seen := map[edgescan.Target]bool{}
	for round := 0; round < seedNames; round++ {
		for _, lookups := range perSet {
			if round >= len(lookups) {
				continue
			}
			entry := lookups[round]
			for _, address := range entry.addresses {
				address = address.Unmap()
				if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
					continue
				}
				target := edgescan.Target{AddrPort: netip.AddrPortFrom(address, s.port), ServerName: entry.name}
				if seen[target] {
					continue
				}
				seen[target] = true
				seeds = append(seeds, target)
				if _, known := setOf[address]; !known {
					setOf[address] = entry.set
				}
				break // one address of each name: the others are alike
			}
		}
	}
	return seeds, setOf
}

// seedOrder returns the server names of set with its CDN's own first (www.fastly.com before
// the GitHub names of the Fastly set): those resolve to that CDN's edges.
func seedOrder(set edgescan.Set) []string {
	own := regexp.MustCompile(`^$`)
	if domains := cdnFrontingDomains[set.Name]; len(domains) > 0 {
		own = regexp.MustCompile(strings.Join(domains, "|"))
	}
	names := slices.Clone(set.ServerNames)
	slices.SortStableFunc(names, func(a, b string) int {
		ownA, ownB := own.MatchString(a), own.MatchString(b)
		switch {
		case ownA && !ownB:
			return -1
		case ownB && !ownA:
			return 1
		}
		return 0
	})
	return names
}

// setOf returns the built-in set of an edge: the one whose ranges hold it, or else the one it was
// a seed of. The ranges come first: a set's name may be served by another CDN
// (alambic-origin.githubusercontent.com, of the Fastly set, is GitHub's).
func (s *edgeScanner) setOf(address netip.Addr) string {
	if set := edgeSet(address); set != "" && set != curatedSet {
		return set
	}
	s.access.Lock()
	defer s.access.Unlock()
	return s.seedSets[address]
}

// scannerEnabled reports whether the outbound scans: as asked, or when Psiphon is the first hop.
// Behind a detour or an upstream proxy, that proxy already gets out of the network.
func scannerEnabled(options option.PsiphonOutboundOptions) bool {
	if options.Scanner != nil && options.Scanner.Enabled != nil {
		return *options.Scanner.Enabled
	}
	return options.Detour == "" && options.UpstreamProxyURL == ""
}

// scannerByDetour reports whether the scanner, off when the outbound was created, is on: its
// detour is a direct outbound, so Psiphon is the first hop all the same. The detour is looked up
// at the start, when every outbound exists.
func scannerByDetour(ctx context.Context, options option.PsiphonOutboundOptions) bool {
	if options.Scanner != nil && options.Scanner.Enabled != nil || options.UpstreamProxyURL != "" || options.Detour == "" {
		return false
	}
	return edgescan.Direct(ctx, options.Detour)
}

// newEdgeScanner is the scanner of an outbound dialing through detour: its scores are in the store
// shared by the scanners that reach the network directly (the WARP endpoints' too, and those of
// another Psiphon outbound), or in one of its own behind another detour.
func newEdgeScanner(ctx context.Context, logger log.ContextLogger, dialer N.Dialer, options *option.PsiphonScannerOptions, tag string, detour string) *edgeScanner {
	s := &edgeScanner{ctx: ctx, logger: logger, dialer: dialer, key: "psiphon/" + tag + scannerStoreSuffix, port: cdnPort}
	if options != nil {
		s.options = *options
	}
	return s
}

// open opens the store at the start: the cache file is registered after the outbounds are
// created, and the detour only exists then.
func (s *edgeScanner) open(ctx context.Context, detour string) {
	store := edgescan.OpenScannerStore(ctx, detour, s.key)
	s.access.Lock()
	s.store = store
	s.book = store.Book(edgescan.KindPsiphon)
	s.access.Unlock()
}

func (s *edgeScanner) save() {
	if err := s.store.Save(); err != nil {
		s.logger.Debug(scannerName, ": save: ", err)
	}
}

// candidates is the number of edges of each CDN handed to the tunnel core.
func (s *edgeScanner) candidates() int {
	if s.options.Candidates > 0 {
		return s.options.Candidates
	}
	return defaultScannerCandidates
}

// sets are the CDN sets the scanner walks: the cidrs option alone, or the built-in sets that
// the sets option names.
func (s *edgeScanner) sets() []edgescan.Set {
	if len(s.options.CIDRs) > 0 {
		return []edgescan.Set{{Name: "user", CIDRs: s.options.CIDRs, ServerNames: append([]string{""}, s.options.ServerNames...)}}
	}
	var sets []edgescan.Set
	for _, set := range cdnEdgeSets {
		if !builtInSetSelected(s.options.Sets, set.name) {
			continue
		}
		prefixes := make([]netip.Prefix, 0, len(set.cidrs))
		for _, cidr := range set.cidrs {
			if prefix, err := netip.ParsePrefix(cidr); err == nil {
				prefixes = append(prefixes, prefix)
			}
		}
		// each edge is also tried without a server name, as the tunnel core does
		sets = append(sets, edgescan.Set{Name: set.name, CIDRs: prefixes, ServerNames: append([]string{""}, set.serverNames...)})
	}
	return sets
}

func builtInSetSelected(selected []string, name string) bool {
	if len(selected) == 0 {
		return true
	}
	for _, wanted := range selected {
		wanted = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(wanted)), "built-in-")
		if wanted == name {
			return true
		}
	}
	return false
}

// Scan detects the network and returns the edges that answer, best first.
// edgeSearch is what a scan found: the edges, and the sets of the seeds among them.
type edgeSearch struct {
	results  []edgescan.Result
	seedSets map[netip.Addr]string
}

// Scan detects the network and returns the edges that answer, best first. The Psiphon outbounds
// that scan the same network the same way at the same time share one scan (see
// edgescan.Store.Do).
func (s *edgeScanner) Scan() (edgescan.NetworkInfo, []edgescan.Result, error) {
	network := s.store.Network(s.ctx, s.logger, s.dialer)
	s.access.Lock()
	s.network = network
	s.access.Unlock()
	_, deep := edgescan.SearchLimit(&s.options.EdgeSearchOptions, s.status.IsDeep())
	s.status.Begin()
	value, err := s.store.Do(s.ctx, s.scanKey(network.Name, deep), func(ctx context.Context) (any, error) {
		return s.scan(ctx, network, deep)
	})
	found, _ := value.(edgeSearch)
	s.access.Lock()
	s.seedSets = found.seedSets
	s.access.Unlock()
	if err != nil {
		s.status.NotFound()
		return network, nil, err
	}
	s.status.Found(found.results[0].AddrPort)
	return network, found.results, nil
}

// scanKey names a scan for sharing: the network and what the scanner was told.
func (s *edgeScanner) scanKey(network string, deep bool) string {
	content, _ := json.Marshal(struct {
		Options any
		Port    uint16
		Deep    bool
	}{s.options, s.port, deep})
	sum := sha256.Sum256(content)
	return edgescan.KindPsiphon + "|" + network + "|" + hex.EncodeToString(sum[:8])
}

// scan is one scan of the edges.
func (s *edgeScanner) scan(ctx context.Context, network edgescan.NetworkInfo, deep bool) (edgeSearch, error) {
	options := scannerDefaults
	options.EdgeSearchOptions = s.options.EdgeSearchOptions
	if s.options.MaxRTT > 0 {
		options.MaxRTT = s.options.MaxRTT
	}
	if s.options.Timeout > 0 {
		options.Timeout = s.options.Timeout
	}
	if s.options.Count > 0 {
		options.Count = s.options.Count
	}
	if s.options.Concurrency > 0 {
		options.Concurrency = s.options.Concurrency
	}
	// a TLS handshake costs little next to a tunnel dial: the scan goes on until each CDN could
	// have given its edges, so the CDN the server entries front through is not left out
	sets := s.sets()
	enough := s.candidates() * len(sets)
	seeds, seedSets := s.seeds(sets)
	s.access.Lock()
	s.seedSets = seedSets // read by SetOf below
	s.access.Unlock()
	results, err := edgescan.Scan(ctx, s.logger, edgescan.Request{
		Name:     scannerName,
		Options:  &options,
		Defaults: edgescan.Defaults{Ports: []uint16{s.port}, Sets: sets},
		// the tunnel core fronts over IPv4 only
		IPv4:         network.IPv4,
		Book:         s.book,
		Network:      network.Name,
		TargetProbe:  s.probe,
		Enough:       enough,
		EnoughPerSet: s.candidates(),
		SetOf:        func(target edgescan.Target) string { return s.setOf(target.AddrPort.Addr()) },
		Seeds:        seeds,
		// an edge that answers TLS may not front Psiphon (a Google edge does not): only the
		// edge the tunnel core connected over is scored, in onNotice
		ConfirmedOnly: true,
		Deep:          deep,
	})
	s.save()
	return edgeSearch{results, seedSets}, err
}

// probe runs a TLS handshake with the edge, with a browser's fingerprint and the target's server
// name (none when empty). The certificate is not checked: a CDN edge answers a name it does not
// serve with a certificate of its own (Fastly's www.fastly.com), and fronts all the same, while a
// network that filters the name resets the handshake. Psiphon's tunnel inside authenticates the
// server.
func (s *edgeScanner) probe(ctx context.Context, target edgescan.Target) (time.Duration, error) {
	start := time.Now()
	conn, err := s.dialer.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNetIP(target.AddrPort))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         target.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, utls.HelloChrome_Auto)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// cdnFrontingDomains names, per built-in set, the fronting domains of the server entries that
// front through that CDN, as regular expressions: a server entry names its CDN by its fronting
// addresses (m.sni.global.fastly.net), or by addresses in the CDN's ranges.
var cdnFrontingDomains = map[string][]string{
	"legacy-android-overrides": {`akamai`, `edgekey\.net$`, `edgesuite\.net$`},
	"psiphon-akamai":           {`akamai`, `edgekey\.net$`, `edgesuite\.net$`},
	"fastly":                   {`fastly`},
	"psiphon-bunny":            {`b-cdn\.net$`, `bunny`},
	"cloudflare":               {`cloudflare`},
	"cloudfront":               {`cloudfront\.net$`},
	"vercel":                   {`vercel`},
	"github":                   {`github`},
	"google":                   {`google`, `gstatic`, `ggpht`},
}

// curatedSet holds edges of several CDNs: an edge of it counts for the CDN whose ranges hold it.
const curatedSet = "curated-fronting"

// edgeSet returns the built-in set of address: the first that holds it, the curated one last.
func edgeSet(address netip.Addr) string {
	found := ""
	for _, set := range cdnEdgeSets {
		for _, cidr := range set.cidrs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil || !prefix.Contains(address) {
				continue
			}
			if set.name != curatedSet {
				return set.name
			}
			found = set.name
		}
	}
	return found
}

// rangeRegex matches the IPv4 addresses of prefixes, written as text: the whole octets of each
// prefix, then the values of a partial one.
func rangeRegex(prefixes []string) string {
	var alternatives []string
	seen := map[string]bool{}
	for _, cidr := range prefixes {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		octets := prefix.Addr().As4()
		whole := prefix.Bits() / 8
		var pattern strings.Builder
		pattern.WriteString(`^`)
		for i := range whole {
			pattern.WriteString(strconv.Itoa(int(octets[i])) + `\.`)
		}
		if extra := prefix.Bits() % 8; extra > 0 && whole < 4 {
			first := int(octets[whole])
			values := make([]string, 0, 1<<(8-extra))
			for value := first; value < first+1<<(8-extra); value++ {
				values = append(values, strconv.Itoa(value))
			}
			pattern.WriteString(`(?:` + strings.Join(values, "|") + `)`)
			if whole < 3 {
				pattern.WriteString(`\.`)
			} else {
				pattern.WriteString(`$`)
			}
		} else if whole == 4 {
			alternative := strings.TrimSuffix(pattern.String(), `\.`) + `$`
			pattern.Reset()
			pattern.WriteString(alternative)
		}
		if !seen[pattern.String()] {
			seen[pattern.String()] = true
			alternatives = append(alternatives, pattern.String())
		}
	}
	if len(alternatives) == 0 {
		return ""
	}
	return `(?:` + strings.Join(alternatives, "|") + `)`
}

// frontingOverrides is what the tunnel core gets from a scan: for each CDN that answered, a dial
// override that applies to the server entries fronting through that CDN only, with up to perCDN
// of its edges, best first, and the server name they answered with (none for an empty one). The core's own CDN scan pairs
// every edge with every server entry and every name: an edge of another CDN than the server's
// answers 400 or 404, and on a censored network those dials are most of the scan.
func frontingOverrides(results []edgescan.Result, perCDN int, setOf func(netip.Addr) string) parameters.FrontedMeekDialOverrideSpecs {
	type group struct {
		set, serverName string
	}
	var (
		order   []group
		byGroup = map[group][]string{}
		perSet  = map[string]int{}
	)
	for _, result := range results {
		address := result.AddrPort.Addr().Unmap()
		set := setOf(address)
		if set == "" || set == curatedSet || perSet[set] >= perCDN {
			continue // no CDN to match the server entries by, or enough of it
		}
		key := group{set, result.ServerName}
		if slices.Contains(byGroup[key], address.String()) {
			continue
		}
		if byGroup[key] == nil {
			order = append(order, key)
		}
		byGroup[key] = append(byGroup[key], address.String())
		perSet[set]++
	}
	var overrides parameters.FrontedMeekDialOverrideSpecs
	for _, key := range order {
		var ranges []string
		for _, set := range cdnEdgeSets {
			if set.name == key.set {
				ranges = set.cidrs
			}
		}
		match := slices.Clone(cdnFrontingDomains[key.set])
		if regex := rangeRegex(ranges); regex != "" {
			match = append(match, regex)
		}
		override := &parameters.FrontedMeekDialOverride{
			OverrideID:              "hiddify-scan-" + key.set,
			MatchDialAddressRegexes: []string{strings.Join(match, "|")},
			DialAddresses:           byGroup[key],
			ALPNProtocols:           []string{"http/1.1"},
		}
		if key.serverName == "" {
			override.DisableSNI = true
		} else {
			// no VerifyServerNames: the edge may answer with its own certificate, see probe
			override.SNIServerName = key.serverName
		}
		overrides = append(overrides, override)
	}
	return overrides
}

// frontingFoundNotice is the tunnel core's notice of the edge it connected over:
// "cdn fronting scan found (ip: 1\.2\.3\.4, sni: name)", "none" for no server name.
var frontingFoundNotice = regexp.MustCompile(`cdn fronting scan found \(ip: ([^,]+), sni: ([^)]+)\)`)

// parseFrontingFound returns the edge of a fronting found notice.
func parseFrontingFound(event NoticeEvent) (edgescan.Target, bool) {
	if event.Type != "Info" {
		return edgescan.Target{}, false
	}
	message, _ := event.Data["message"].(string)
	match := frontingFoundNotice.FindStringSubmatch(message)
	if match == nil {
		return edgescan.Target{}, false
	}
	address, err := netip.ParseAddr(strings.ReplaceAll(strings.ReplaceAll(match[1], `\.`, "."), `\:`, ":"))
	if err != nil {
		return edgescan.Target{}, false
	}
	serverName := match[2]
	if serverName == "none" {
		serverName = ""
	}
	return edgescan.Target{AddrPort: netip.AddrPortFrom(address, cdnPort), ServerName: serverName}, true
}

// onNotice gives the edge the tunnel core connected over a point on the network: it carried a
// whole tunnel, more than a handshake shows.
func (s *edgeScanner) onNotice(event NoticeEvent) {
	if event.Type == "ActiveTunnel" {
		s.protocolConnected(event)
		return
	}
	target, ok := parseFrontingFound(event)
	if !ok {
		return
	}
	s.access.Lock()
	network := s.network.Name
	s.lastEdge = target
	s.access.Unlock()
	if network == "" {
		return
	}
	s.logger.Info(scannerName, ": Psiphon connected over ", target)
	s.book.SuccessTarget(network, target, 0, time.Now())
	s.save()
}

// protocolMethod is the method key of a tunnel protocol, rated by the tunnels that came up with it.
func protocolMethod(name string) string { return "proto/" + name }

// protocolConnected gives the protocol of a tunnel that came up a point on the network.
func (s *edgeScanner) protocolConnected(event NoticeEvent) {
	protocol, _ := event.Data["protocol"].(string)
	if protocol == "" {
		return
	}
	s.rememberWay(protocol)
	s.access.Lock()
	network := s.network.Name
	s.access.Unlock()
	if network == "" {
		return
	}
	s.book.MethodSuccess(network, protocolMethod(protocol), time.Now())
	s.save()
}

// firstProtocols are the protocols the tunnel core tries first on network: up to
// preferredProtocols of those that came up there before, drawn by weight (see
// edgescan.Book.OrderMethods), so the core does not go through all of them before the one that
// works; none before any came up.
func (s *edgeScanner) firstProtocols(network string, protocols []string) []string {
	methods := make([]string, len(protocols))
	for i, protocol := range protocols {
		methods[i] = protocolMethod(protocol)
	}
	var first []string
	for _, method := range s.book.OrderMethods(network, methods, nil) {
		if score, _ := s.book.MethodScore(network, method); score > 0 && len(first) < preferredProtocols {
			first = append(first, strings.TrimPrefix(method, "proto/"))
		}
	}
	return first
}

const (
	// preferredProtocols is the most protocols tried first, and preferredCandidates the server
	// candidates they are tried with before all the protocols are
	preferredProtocols  = 3
	preferredCandidates = 20
)
