// Package edgescan finds a server edge that answers: a Cloudflare WARP endpoint (see warpscan),
// or a CDN edge that Psiphon fronts through. Each target, an address and port with an optional
// TLS server name, has a score per network (see Book); the best known targets are tried first,
// then new ones from the configured ranges, each probed by the caller (a WireGuard, QUIC or TLS
// handshake), through the client's own dialer. The book also rates the methods tried on each
// network (noises, tunnels), which are drawn in a weighted random order.
//
// New targets are not drawn at random: each network walks the candidate space (ranges × ports ×
// server names) in an order of its own, a permutation keyed by a seed kept with its cursor, and a
// scan goes on where the last one stopped. A target that failed is not tried again until the
// whole space was walked, without keeping a record of each failure, and two clients walk the
// space in different orders.
package edgescan

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	defaultMaxRTT  = time.Second
	defaultTimeout = 2 * time.Second
	defaultCount   = 64
	// enoughResults ends a scan early: the best of a few answering targets is good enough,
	// and the rest are kept for next time.
	enoughResults = 4
	// stableScore ends a scan as soon as a target with that score answers: it has a record of
	// working on this network, so exploring further only delays connecting.
	stableScore rating.Score = 3
)

// Target is what a probe reaches: an address and port, and the TLS server name to send, ""
// for none or for a protocol without one.
type Target struct {
	AddrPort   netip.AddrPort `json:"address"`
	ServerName string         `json:"server_name,omitempty"`
}

// String is the target's key in the book: the address and port, then "|" and the server name
// when there is one. A target without one keeps the key the book had before server names.
func (t Target) String() string {
	if t.ServerName == "" {
		return t.AddrPort.String()
	}
	return t.AddrPort.String() + "|" + t.ServerName
}

// ParseTarget reads what String wrote.
func ParseTarget(key string) (Target, error) {
	address, serverName, _ := strings.Cut(key, "|")
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return Target{}, err
	}
	return Target{AddrPort: addrPort, ServerName: serverName}, nil
}

// Result is a target that answered, with its handshake time and its score afterwards.
type Result struct {
	Target
	RTT   time.Duration `json:"rtt"`
	Score rating.Score  `json:"score"`
}

// Probe runs one handshake with addrPort and returns the time it took.
type Probe func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error)

// TargetProbe runs one handshake with target and returns the time it took.
type TargetProbe func(ctx context.Context, target Target) (time.Duration, error)

// Defaults are the ranges, ports and server names used when the options leave them empty.
type Defaults struct {
	// CIDRs take turns, each with ServerNames (see Set); Sets, when given, take their place.
	CIDRs []netip.Prefix
	Ports []uint16
	// ServerNames are tried with each address and port of CIDRs, and with the ranges of the
	// cidrs option; none means no server name.
	ServerNames []string
	// Sets group ranges with their own server names, such as the edges of each CDN; the sets
	// take turns, then the ranges within each.
	Sets []Set
}

// Request is one scan.
type Request struct {
	// Name prefixes the log lines, such as "WARP scanner"; "scanner" when empty.
	Name     string
	Options  *option.WARPScannerOptions
	Defaults Defaults
	// IPv4 and IPv6 are the address families the network can reach; new candidates are only
	// drawn from those.
	IPv4, IPv6 bool
	// Book holds the scores; Network names the network the scan runs on.
	Book    *Book
	Network string
	// Exclude are addresses and ports not to try, with any server name, such as the one that
	// just failed.
	Exclude []netip.AddrPort
	// Probe, or TargetProbe when the candidates have server names, probes one candidate.
	Probe       Probe
	TargetProbe TargetProbe
	// Seeds are tried after the known targets and before new ones: targets likely to answer,
	// such as the addresses a CDN's names resolve to, where most of its ranges are silent.
	Seeds []Target
	// Deep runs the scan with options.DeepConcurrency (see Search).
	Deep bool
	// Enough ends the scan once that many targets answered; 4 when zero.
	Enough int
	// EnoughPerSet, when set, counts at most that many answers of each set toward Enough, so a
	// set whose targets answer fast does not end the scan before the others had their turn. The
	// set of a target is the one it was drawn from, or what SetOf says (a seed).
	EnoughPerSet int
	SetOf        func(Target) string
	// ConfirmedOnly: an answer to the probe only shows that a target is reachable, not that it
	// works (a CDN edge that answers TLS may not carry the tunnel). The scan then scores no
	// answer; the caller scores the targets it confirms with SuccessTarget, and only those end a
	// scan early as stable. Failures of confirmed targets still cost them a point.
	ConfirmedOnly bool
}

// Scan probes the known targets of the network best first, then the good ones of other
// networks, then new ones, and records every answer in the book. The failures are recorded only
// when some target answered: when none does, the network, or the noise the probe sends, is the
// likely cause, and a scan with a noise that does not get through must not mark the targets
// down. It returns the targets that answered within max_rtt, highest score first, then fastest.
func Scan(ctx context.Context, logger logger.ContextLogger, request Request) ([]Result, error) {
	name := request.Name
	if name == "" {
		name = "scanner"
	}
	options := request.Options
	if options == nil {
		options = &option.WARPScannerOptions{}
	}
	reachable := func(cidrs []netip.Prefix) []netip.Prefix {
		return slices.DeleteFunc(slices.Clone(cidrs), func(prefix netip.Prefix) bool {
			return prefix.Addr().Is4() && !request.IPv4 || prefix.Addr().Is6() && !request.IPv6
		})
	}
	var sets []Set
	if len(options.CIDRs) == 0 && len(request.Defaults.Sets) > 0 {
		for _, set := range request.Defaults.Sets {
			set.CIDRs = reachable(set.CIDRs)
			sets = append(sets, set)
		}
	} else {
		cidrs := []netip.Prefix(options.CIDRs)
		if len(cidrs) == 0 {
			cidrs = request.Defaults.CIDRs
		}
		for _, prefix := range reachable(cidrs) {
			sets = append(sets, Set{CIDRs: []netip.Prefix{prefix}, ServerNames: request.Defaults.ServerNames})
		}
	}
	ports := []uint16(options.Ports)
	if len(ports) == 0 {
		ports = request.Defaults.Ports
	}
	if len(ports) == 0 {
		return nil, E.New(name, ": no ports to scan")
	}
	maxRTT := time.Duration(options.MaxRTT)
	if maxRTT <= 0 {
		maxRTT = defaultMaxRTT
	}
	timeout := time.Duration(options.Timeout)
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	count := options.Count
	if count <= 0 {
		count = defaultCount
	}
	concurrency := options.Concurrency
	if concurrency <= 0 {
		concurrency = PlatformDefault(8, 32)
	}
	if request.Deep {
		if options.DeepConcurrency > 0 {
			concurrency = options.DeepConcurrency
		} else {
			concurrency *= 2
		}
	}
	enough := request.Enough
	if enough <= 0 {
		enough = enoughResults
	}
	probe := request.TargetProbe
	if probe == nil {
		if request.Probe == nil {
			return nil, E.New(name, ": no probe")
		}
		probe = func(ctx context.Context, target Target) (time.Duration, error) {
			return request.Probe(ctx, target.AddrPort)
		}
	}
	book := request.Book
	if book == nil {
		book = NewBook()
	}
	logger.InfoContext(ctx, name, ": network ", request.Network)
	space := newSpace(sets, ports, options.BlockBitsIPv4, options.BlockBitsIPv6)
	preferred, last := book.CandidateTargets(request.Network)
	preferred = append(preferred, request.Seeds...)
	setOf := map[Target]string{}
	candidates := candidateList(preferred, last, request.Exclude, func(want int, allowed func(Target) bool) []Target {
		return book.draw(request.Network, space, want, allowed, setOf)
	}, count, request.IPv4, request.IPv6)
	if len(candidates) == 0 {
		return nil, E.New(name, ": no address to scan")
	}
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		access      sync.Mutex
		useful      int            // answers that count toward enough
		perSet      map[string]int // answers by set, with EnoughPerSet
		results     []Result
		failed      []Target // recorded when some target answered
		unreachable [2]bool  // the network cannot reach IPv4, IPv6
		wait        sync.WaitGroup
	)
	family := func(target Target) int {
		if target.AddrPort.Addr().Unmap().Is4() {
			return 0
		}
		return 1
	}
	queue := make(chan Target)
	for range concurrency {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for target := range queue {
				access.Lock()
				skip := unreachable[family(target)]
				access.Unlock()
				if skip || scanCtx.Err() != nil {
					continue
				}
				if !acquireProbe(scanCtx) {
					continue
				}
				probeCtx, probeCancel := context.WithTimeout(scanCtx, timeout)
				rtt, err := probe(probeCtx, target)
				probeCancel()
				releaseProbe()
				now := time.Now()
				if err != nil {
					if scanCtx.Err() != nil {
						// cut off by the end of the scan, not a failure of the target
						continue
					}
					access.Lock()
					if familyUnreachable(err) {
						unreachable[family(target)] = true
					}
					failed = append(failed, target)
					access.Unlock()
					logger.TraceContext(ctx, name, ": ", target, ": ", err)
					continue
				}
				if rtt > maxRTT {
					access.Lock()
					failed = append(failed, target)
					access.Unlock()
					logger.DebugContext(ctx, name, ": ", target, " answered in ", rtt, ", too slow")
					continue
				}
				// the block and the server name got through; the target and its set too, unless
				// only the caller can tell
				book.BlockSuccess(request.Network, space.block(target.AddrPort.Addr()), now)
				if target.ServerName != "" {
					book.MethodSuccess(request.Network, ServerNameMethod(target.ServerName), now)
				}
				if !request.ConfirmedOnly {
					book.SuccessTarget(request.Network, target, rtt, now)
					if set := setOf[target]; set != "" {
						book.MethodSuccess(request.Network, SetMethod(set), now)
					}
				}
				score, _ := book.TargetScore(request.Network, target)
				logger.DebugContext(ctx, name, ": ", target, " answered in ", rtt, ", score ", score)
				access.Lock()
				results = append(results, Result{target, rtt, score})
				if request.EnoughPerSet > 0 {
					set := setOf[target]
					if set == "" && request.SetOf != nil {
						set = request.SetOf(target)
					}
					if perSet == nil {
						perSet = make(map[string]int)
					}
					perSet[set]++
					if perSet[set] <= request.EnoughPerSet {
						useful++
					}
				} else {
					useful++
				}
				if useful >= enough || score >= stableScore {
					cancel()
				}
				access.Unlock()
			}
		}()
	}
feed:
	for _, candidate := range candidates {
		select {
		case queue <- candidate:
		case <-scanCtx.Done():
			break feed
		}
	}
	close(queue)
	wait.Wait()
	if len(results) > 0 {
		now := time.Now()
		for _, target := range failed {
			book.FailureTarget(request.Network, target, now)
			// the server names and sets are only rated up: a name fails with a dead address
			// as much as with a filter, and a scan tries few of each
			book.BlockFailure(request.Network, space.block(target.AddrPort.Addr()), now)
		}
	}
	if len(results) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, E.New(name, ": nothing answered within ", maxRTT, " (", len(candidates), " candidates)")
	}
	slices.SortFunc(results, func(a, b Result) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		return cmp.Compare(a.RTT, b.RTT)
	})
	return results, nil
}

// candidateList returns preferred, then new targets that draw gives, then last, without the
// excluded addresses and up to count in total (preferred and last are always included).
func candidateList(preferred, last []Target, exclude []netip.AddrPort, draw func(want int, allowed func(Target) bool) []Target, count int, ipv4, ipv6 bool) []Target {
	excluded := make(map[netip.AddrPort]bool)
	for _, addrPort := range exclude {
		excluded[addrPort] = true
	}
	seen := make(map[Target]bool)
	allowed := func(target Target) bool {
		address := target.AddrPort.Addr().Unmap()
		return target.AddrPort.IsValid() && !excluded[target.AddrPort] && !seen[target] && (address.Is4() && ipv4 || address.Is6() && ipv6)
	}
	var candidates []Target
	for _, target := range preferred {
		if allowed(target) {
			seen[target] = true
			candidates = append(candidates, target)
		}
	}
	lastAllowed := make([]Target, 0, len(last))
	for _, target := range last {
		if allowed(target) {
			seen[target] = true
			lastAllowed = append(lastAllowed, target)
		}
	}
	if want := count - len(candidates); want > 0 && draw != nil {
		for _, target := range draw(want, allowed) {
			seen[target] = true
			candidates = append(candidates, target)
		}
	}
	return append(candidates, lastAllowed...)
}

func familyUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT)
}

func randomInt(n int) int {
	if n <= 1 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(value.Int64())
}
