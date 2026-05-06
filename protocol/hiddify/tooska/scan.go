package tooska

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/protocol/hiddify/tooska/scanner"
	E "github.com/sagernet/sing/common/exceptions"
)

// defaultPorts is the cross-product source for bare IP / CIDR targets
// that don't specify their own ports.
var defaultPorts = []int{1080, 8080, 3128, 8888, 1085, 8118, 8123}

// maxCandidates caps target expansion so a misconfigured "0.0.0.0/0"
// doesn't OOM the host before the scan ever starts.
const maxCandidates = 1_000_000

func parseCandidates(targets []string, ports []int) ([]scanner.Endpoint, error) {
	if len(targets) == 0 {
		return nil, E.New("tooska: no targets configured")
	}
	if len(ports) == 0 {
		ports = defaultPorts
	}

	seen := make(map[string]struct{})
	out := make([]scanner.Endpoint, 0, 64)

	add := func(ep scanner.Endpoint) error {
		key := joinHostPort(ep.IP.String(), ep.Port)
		if _, ok := seen[key]; ok {
			return nil
		}
		if len(seen) >= maxCandidates {
			return E.New("tooska: target expansion exceeds ", maxCandidates, " endpoints; tighten your CIDR/ports")
		}
		seen[key] = struct{}{}
		out = append(out, ep)
		return nil
	}

	for _, raw := range targets {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if host, portStr, err := net.SplitHostPort(t); err == nil {
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return nil, E.New("tooska: invalid target ", t, ": ", err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port <= 0 || port > 65535 {
				return nil, E.New("tooska: invalid port in target ", t)
			}
			if err := add(scanner.Endpoint{IP: ip, Port: port}); err != nil {
				return nil, err
			}
			continue
		}
		if strings.Contains(t, "/") {
			prefix, err := netip.ParsePrefix(t)
			if err != nil {
				return nil, E.New("tooska: invalid CIDR ", t, ": ", err)
			}
			for ip := prefix.Masked().Addr(); prefix.Contains(ip); ip = ip.Next() {
				for _, p := range ports {
					if err := add(scanner.Endpoint{IP: ip, Port: p}); err != nil {
						return nil, err
					}
				}
			}
			continue
		}
		ip, err := netip.ParseAddr(t)
		if err != nil {
			return nil, E.New("tooska: invalid target ", t, ": ", err)
		}
		for _, p := range ports {
			if err := add(scanner.Endpoint{IP: ip, Port: p}); err != nil {
				return nil, err
			}
		}
	}

	if len(out) == 0 {
		return nil, E.New("tooska: target expansion produced zero candidates")
	}
	return out, nil
}

func (h *Outbound) orderForScan(in []scanner.Endpoint) []scanner.Endpoint {
	out := make([]scanner.Endpoint, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		return h.pool.score(out[i].IP.String(), out[i].Port) > h.pool.score(out[j].IP.String(), out[j].Port)
	})
	return out
}

func (h *Outbound) runScan(parent context.Context, reason string) {
	if !h.scanGate.tryAcquire() {
		return
	}
	defer h.scanGate.release()

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	endpoints := h.orderForScan(h.candidates)
	cfg := scanner.Config{
		Endpoints:          endpoints,
		Concurrency:        h.options.Concurrency,
		DialTimeout:        durationOr(h.options.DialTimeout, 1200*time.Millisecond),
		FingerprintTimeout: durationOr(h.options.FingerprintTimeout, time.Second),
		ProbeTimeout:       durationOr(h.options.ProbeTimeout, 6*time.Second),
		UserAgent:          h.options.UserAgent,
		EmitFailures:       true,
	}
	h.logger.InfoContext(ctx, "tooska scan starting (", reason, "): ", len(endpoints), " candidates, concurrency=", cfg.Concurrency)

	results := scanner.Scan(ctx, cfg)
	hits, misses := 0, 0
	for r := range results {
		if r.OK() {
			h.pool.recordHit(r)
			hits++
			h.markStarted()
		} else {
			h.pool.recordMiss(r.IP, r.Port)
			misses++
		}
		if h.pool.workingCount() >= h.options.PoolSize {
			cancel()
			break
		}
	}
	for range results {
	}
	h.pool.save(h.cache, h.Tag())
	h.logger.InfoContext(ctx, "tooska scan finished (", reason, "): ", hits, " hits / ", misses, " misses, pool=", h.pool.workingCount())
}

// scanGate serializes scan invocations. busy() is a lock-free fast path
// for cheap callers like kickRescanOnConnect.
type scanGate struct {
	active atomic.Bool
}

func (g *scanGate) tryAcquire() bool { return g.active.CompareAndSwap(false, true) }
func (g *scanGate) release()         { g.active.Store(false) }
func (g *scanGate) busy() bool       { return g.active.Load() }

func joinHostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}
