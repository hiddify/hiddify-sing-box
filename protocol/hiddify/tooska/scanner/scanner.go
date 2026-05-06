// Package scanner is a high-throughput, dependency-free TCP proxy scanner
// embedded into the Hiddify sing-box core. It vendors the goBrrrr design:
// a pure-Go TCP connect sweep with a 3-byte Tier-C fingerprint and a deep
// SOCKS5 / HTTP validation step. Results stream back over a channel and
// the worker pool is bounded so it stays safe on FD-constrained devices.
package scanner

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

type Protocol string

const (
	ProtoSOCKS5 Protocol = "socks5"
	ProtoHTTP   Protocol = "http"
)

type Endpoint struct {
	IP   netip.Addr
	Port int
}

type Result struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Protocol  Protocol  `json:"protocol,omitempty"`
	LatencyMS int64     `json:"latency_ms,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	Error     string    `json:"error,omitempty"`
}

func (r Result) OK() bool { return r.Error == "" && r.Protocol != "" }

type Config struct {
	Endpoints          []Endpoint
	Concurrency        int
	DialTimeout        time.Duration
	FingerprintTimeout time.Duration
	ProbeTimeout       time.Duration
	PortLanes          map[int][]Protocol
	UserAgent          string
	EmitFailures       bool
	OnProgress         func(completed, total int)
}

func (c Config) normalize() Config {
	if c.Concurrency <= 0 {
		c.Concurrency = 256
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 1200 * time.Millisecond
	}
	if c.FingerprintTimeout <= 0 {
		c.FingerprintTimeout = time.Second
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = 6 * time.Second
	}
	if c.UserAgent == "" {
		c.UserAgent = "tooska/1.0"
	}
	return c
}

var ErrNoEndpoints = errors.New("scanner: no endpoints to scan")

func Scan(ctx context.Context, cfg Config) <-chan Result {
	cfg = cfg.normalize()
	out := make(chan Result, 64)
	if len(cfg.Endpoints) == 0 {
		close(out)
		return out
	}
	if ctx == nil {
		ctx = context.Background()
	}
	go runScan(ctx, cfg, out)
	return out
}

func runScan(ctx context.Context, cfg Config, out chan<- Result) {
	defer close(out)

	total := len(cfg.Endpoints)
	jobs := make(chan Endpoint)
	var wg sync.WaitGroup
	var done int64
	var doneMu sync.Mutex

	emit := func(r Result) {
		select {
		case out <- r:
		case <-ctx.Done():
		}
	}

	tickProgress := func() {
		if cfg.OnProgress == nil {
			return
		}
		doneMu.Lock()
		done++
		n := int(done)
		doneMu.Unlock()
		cfg.OnProgress(n, total)
	}

	workers := cfg.Concurrency
	if workers > total {
		workers = total
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				if ctx.Err() != nil {
					tickProgress()
					continue
				}
				for _, res := range probeEndpoint(ctx, cfg, ep) {
					if res.OK() || cfg.EmitFailures {
						emit(res)
					}
				}
				tickProgress()
			}
		}()
	}

	feed := func() {
		defer close(jobs)
		for _, ep := range cfg.Endpoints {
			select {
			case jobs <- ep:
			case <-ctx.Done():
				return
			}
		}
	}
	go feed()

	wg.Wait()
}
