// Package warpscan finds a Cloudflare WARP endpoint that answers. Addresses that worked before
// are tried first, then random addresses in the configured ranges; each is probed with the
// handshake of the protocol in use (WireGuard or MASQUE), through the client's own dialer.
package warpscan

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/netip"
	"slices"
	"sync"
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
	// keptResults is the number of answering endpoints remembered for the next scan.
	keptResults = 10
)

// Result is an endpoint that answered, with its handshake time.
type Result struct {
	AddrPort netip.AddrPort `json:"address"`
	RTT      time.Duration  `json:"rtt"`
}

// Probe runs one handshake with addrPort and returns the time it took.
type Probe func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error)

// Defaults are the ranges and ports used when the options leave them empty.
type Defaults struct {
	CIDRs []netip.Prefix
	Ports []uint16
}

// Scan probes the saved endpoints, then random ones, and returns those that answered within
// max_rtt, fastest first.
func Scan(ctx context.Context, logger logger.ContextLogger, options *option.WARPScannerOptions, defaults Defaults, saved []netip.AddrPort, probe Probe) ([]Result, error) {
	cidrs := []netip.Prefix(options.CIDRs)
	if len(cidrs) == 0 {
		cidrs = defaults.CIDRs
	}
	ports := []uint16(options.Ports)
	if len(ports) == 0 {
		ports = defaults.Ports
	}
	if len(cidrs) == 0 || len(ports) == 0 {
		return nil, E.New("WARP scanner: no address ranges or ports to scan")
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
	candidates := candidateList(saved, cidrs, ports, count)
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		access  sync.Mutex
		results []Result
		wait    sync.WaitGroup
	)
	queue := make(chan netip.AddrPort)
	for range concurrency {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for addrPort := range queue {
				probeCtx, probeCancel := context.WithTimeout(scanCtx, timeout)
				rtt, err := probe(probeCtx, addrPort)
				probeCancel()
				if err != nil {
					logger.TraceContext(ctx, "WARP scanner: ", addrPort, ": ", err)
					continue
				}
				if rtt > maxRTT {
					logger.DebugContext(ctx, "WARP scanner: ", addrPort, " answered in ", rtt, ", too slow")
					continue
				}
				logger.DebugContext(ctx, "WARP scanner: ", addrPort, " answered in ", rtt)
				access.Lock()
				results = append(results, Result{addrPort, rtt})
				if len(results) >= enoughResults {
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
		return nil, E.New("WARP scanner: no endpoint answered within ", maxRTT, " (", len(candidates), " probed)")
	}
	slices.SortFunc(results, func(a, b Result) int {
		return int(a.RTT - b.RTT)
	})
	return results, nil
}

// candidateList returns the saved endpoints first, then random ones up to count in total.
func candidateList(saved []netip.AddrPort, cidrs []netip.Prefix, ports []uint16, count int) []netip.AddrPort {
	seen := make(map[netip.AddrPort]bool)
	var candidates []netip.AddrPort
	for _, addrPort := range saved {
		if addrPort.IsValid() && !seen[addrPort] {
			seen[addrPort] = true
			candidates = append(candidates, addrPort)
		}
	}
	for attempts := 0; len(candidates) < count && attempts < count*4; attempts++ {
		addrPort := netip.AddrPortFrom(randomAddress(cidrs[randomInt(len(cidrs))]), ports[randomInt(len(ports))])
		if !seen[addrPort] {
			seen[addrPort] = true
			candidates = append(candidates, addrPort)
		}
	}
	return candidates
}

// Kept returns the endpoints to remember for the next scan.
func Kept(results []Result) []netip.AddrPort {
	kept := make([]netip.AddrPort, 0, min(len(results), keptResults))
	for _, result := range results[:min(len(results), keptResults)] {
		kept = append(kept, result.AddrPort)
	}
	return kept
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
