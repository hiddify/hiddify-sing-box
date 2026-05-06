package tooska

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hiddify/tooska/scanner"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TooskaOutboundOptions](registry, C.TypeTooska, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	ctx    context.Context

	options    option.TooskaOutboundOptions
	upstream   N.Dialer
	cache      adapter.CacheFile
	pool       *pool
	candidates []scanner.Endpoint
	scanGate   scanGate

	started atomic.Bool
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.TooskaOutboundOptions) (adapter.Outbound, error) {
	candidates, err := parseCandidates(options.Targets, options.Ports)
	if err != nil {
		return nil, err
	}

	if options.Concurrency <= 0 {
		options.Concurrency = 256
	}
	if options.PoolSize <= 0 {
		options.PoolSize = 16
	}
	if options.UserAgent == "" {
		options.UserAgent = "tooska/1.0"
	}

	upstream, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, err
	}

	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeTooska, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:     logger,
		ctx:        ctx,
		options:    options,
		upstream:   upstream,
		pool:       newPool(),
		candidates: candidates,
	}, nil
}

func (h *Outbound) PreStart() error {
	h.cache = service.FromContext[adapter.CacheFile](h.ctx)
	h.pool.load(h.cache, h.Tag())
	return nil
}

func (h *Outbound) PostStart() error {
	go h.runScan(h.ctx, "bootstrap")
	return nil
}

func (h *Outbound) Close() error { return nil }

func (h *Outbound) IsReady() bool { return h.pool.workingCount() > 0 }

func (h *Outbound) DisplayType() string {
	base := C.ProxyDisplayName(h.Type())
	if !h.started.Load() {
		return base + " ⚠️ Connecting..."
	}
	return fmt.Sprint(base, " ✔️ ", h.pool.workingCount(), " endpoints")
}

func (h *Outbound) markStarted() {
	if h.started.CompareAndSwap(false, true) {
		h.logger.InfoContext(h.ctx, "tooska first endpoint validated, outbound is ready")
		monitoring.Get(h.ctx).TestNow(h.Tag())
	}
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if !h.IsReady() {
		go h.runScan(h.ctx, "on-demand")
		return nil, E.New("tooska: no working endpoint, scanner is still warming up")
	}
	h.logger.InfoContext(ctx, "tooska outbound connection to ", destination)
	return h.dialThroughPool(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("tooska: UDP is not supported")
}

func durationOr(d *badoption.Duration, fallback time.Duration) time.Duration {
	if d == nil {
		return fallback
	}
	if v := d.Build(); v > 0 {
		return v
	}
	return fallback
}
