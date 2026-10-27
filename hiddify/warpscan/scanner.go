// Package warpscan finds a Cloudflare WARP endpoint that answers. Each endpoint has a score per
// network (see Book); the best known endpoints are tried first, then random addresses in the
// configured ranges. Each is probed with the handshake of the protocol in use (WireGuard or
// MASQUE), through the client's own dialer.
package warpscan

import (
	"cmp"
	"context"
	"errors"
	"crypto/rand"
	"math/big"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	defaultMaxRTT      = time.Second
	defaultTimeout     = 2 * time.Second
	defaultCount       = 64
	defaultConcurrency = 8
	// enoughResults ends a scan early: the best of a few answering endpoints is good enough,
	// and the rest are kept for next time.
	enoughResults = 4
	// stableScore ends a scan as soon as an endpoint with that score answers: it has a
	// record of working on this network, so exploring further only delays connecting.
	stableScore = 3
)

// Result is an endpoint that answered, with its handshake time and its score afterwards.
type Result struct {
	AddrPort netip.AddrPort `json:"address"`
	RTT      time.Duration  `json:"rtt"`
	Score    int            `json:"score"`
}

// Probe runs one handshake with addrPort and returns the time it took.
type Probe func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error)

// Defaults are the ranges and ports used when the options leave them empty.
type Defaults struct {
	CIDRs []netip.Prefix
	Ports []uint16
}

// Request is one scan.
type Request struct {
	Options  *option.WARPScannerOptions
	Defaults Defaults
	// IPv4 and IPv6 are the address families the network can reach; random candidates are
	// only drawn from those.
	IPv4, IPv6 bool
	// Book holds the scores; Network names the network the scan runs on.
	Book    *Book
	Network string
	// Exclude are endpoints not to try, such as the one that just failed.
	Exclude []netip.AddrPort
	Probe   Probe
}

// Scan probes the known endpoints of the network best first, then the good ones of other
// networks, then random ones, and records every answer and failure in the book. It returns the
// endpoints that answered within max_rtt, highest score first, then fastest.
func Scan(ctx context.Context, logger logger.ContextLogger, request Request) ([]Result, error) {
	options := request.Options
	if options == nil {
		options = &option.WARPScannerOptions{}
	}
	cidrs := []netip.Prefix(options.CIDRs)
	if len(cidrs) == 0 {
		cidrs = request.Defaults.CIDRs
	}
	cidrs = slices.DeleteFunc(slices.Clone(cidrs), func(prefix netip.Prefix) bool {
		return prefix.Addr().Is4() && !request.IPv4 || prefix.Addr().Is6() && !request.IPv6
	})
	ports := []uint16(options.Ports)
	if len(ports) == 0 {
		ports = request.Defaults.Ports
	}
	if len(ports) == 0 {
		return nil, E.New("WARP scanner: no ports to scan")
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
		concurrency = defaultConcurrency
	}
	book := request.Book
	if book == nil {
		book = NewBook()
	}
	logger.InfoContext(ctx, "WARP scanner: network ", request.Network)
	preferred, last := book.Candidates(request.Network)
	candidates := candidateList(preferred, last, request.Exclude, cidrs, ports, count, request.IPv4, request.IPv6)
	if len(candidates) == 0 {
		return nil, E.New("WARP scanner: no address to scan")
	}
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		access      sync.Mutex
		results     []Result
		unreachable [2]bool // the network cannot reach IPv4, IPv6
		wait        sync.WaitGroup
	)
	family := func(addrPort netip.AddrPort) int {
		if addrPort.Addr().Unmap().Is4() {
			return 0
		}
		return 1
	}
	queue := make(chan netip.AddrPort)
	for range concurrency {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for addrPort := range queue {
				access.Lock()
				skip := unreachable[family(addrPort)]
				access.Unlock()
				if skip || scanCtx.Err() != nil {
					continue
				}
				probeCtx, probeCancel := context.WithTimeout(scanCtx, timeout)
				rtt, err := request.Probe(probeCtx, addrPort)
				probeCancel()
				now := time.Now()
				if err != nil {
					if scanCtx.Err() != nil {
						// cut off by the end of the scan, not a failure of the endpoint
						continue
					}
					if familyUnreachable(err) {
						access.Lock()
						unreachable[family(addrPort)] = true
						access.Unlock()
					}
					book.Failure(request.Network, addrPort, now)
					logger.TraceContext(ctx, "WARP scanner: ", addrPort, ": ", err)
					continue
				}
				if rtt > maxRTT {
					book.Failure(request.Network, addrPort, now)
					logger.DebugContext(ctx, "WARP scanner: ", addrPort, " answered in ", rtt, ", too slow")
					continue
				}
				book.Success(request.Network, addrPort, rtt, now)
				score, _ := book.Score(request.Network, addrPort)
				logger.DebugContext(ctx, "WARP scanner: ", addrPort, " answered in ", rtt, ", score ", score)
				access.Lock()
				results = append(results, Result{addrPort, rtt, score})
				if len(results) >= enoughResults || score >= stableScore {
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
	if len(results) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, E.New("WARP scanner: no endpoint answered within ", maxRTT, " (", len(candidates), " candidates)")
	}
	slices.SortFunc(results, func(a, b Result) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		return cmp.Compare(a.RTT, b.RTT)
	})
	return results, nil
}

// candidateList returns preferred, then random endpoints, then last, without the excluded ones
// and up to count in total (preferred and last are always included).
func candidateList(preferred, last, exclude []netip.AddrPort, cidrs []netip.Prefix, ports []uint16, count int, ipv4, ipv6 bool) []netip.AddrPort {
	seen := make(map[netip.AddrPort]bool)
	for _, addrPort := range exclude {
		seen[addrPort] = true
	}
	allowed := func(addrPort netip.AddrPort) bool {
		address := addrPort.Addr().Unmap()
		return addrPort.IsValid() && !seen[addrPort] && (address.Is4() && ipv4 || address.Is6() && ipv6)
	}
	var candidates []netip.AddrPort
	for _, addrPort := range preferred {
		if allowed(addrPort) {
			seen[addrPort] = true
			candidates = append(candidates, addrPort)
		}
	}
	if len(cidrs) > 0 {
		for attempts := 0; len(candidates) < count && attempts < count*4; attempts++ {
			addrPort := netip.AddrPortFrom(randomAddress(cidrs[randomInt(len(cidrs))]), ports[randomInt(len(ports))])
			if allowed(addrPort) {
				seen[addrPort] = true
				candidates = append(candidates, addrPort)
			}
		}
	}
	for _, addrPort := range last {
		if allowed(addrPort) {
			seen[addrPort] = true
			candidates = append(candidates, addrPort)
		}
	}
	return candidates
}

func familyUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT)
}

func randomAddress(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	address := prefix.Addr().AsSlice()
	hostBits := len(address)*8 - prefix.Bits()
	for i := len(address) - 1; i >= 0 && hostBits > 0; i-- {
		bits := min(hostBits, 8)
		mask := byte(1<<bits - 1)
		address[i] = address[i]&^mask | byte(randomInt(256))&mask
		hostBits -= bits
	}
	result, _ := netip.AddrFromSlice(address)
	return result
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
