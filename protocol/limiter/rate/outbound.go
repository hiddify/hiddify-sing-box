package rate

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.RateLimiterOutboundOptions](registry, C.TypeRateLimiter, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx         context.Context
	outbound    adapter.OutboundManager
	connection  adapter.ConnectionManager
	logger      logger.ContextLogger
	strategy    RateStrategy
	outboundTag string
	detour      adapter.Outbound
	router      *route.Router
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.RateLimiterOutboundOptions) (adapter.Outbound, error) {
	if options.Strategy == "" {
		return nil, E.New("missing strategy")
	}
	if options.Route.Final == "" {
		return nil, E.New("missing final outbound")
	}
	var strategy RateStrategy
	var err error
	switch options.Strategy {
	case "users":
		usersStrategies := make(map[string]RateStrategy, len(options.Users))
		for _, user := range options.Users {
			userStrategy, err := CreateStrategy(user.Strategy, user.ConnectionType, int(user.Count), user.Interval.Build())
			if err != nil {
				return nil, err
			}
			usersStrategies[user.Name] = userStrategy
		}
		strategy = NewUsersRateStrategy(usersStrategies)
	case "manager":
		strategy = NewManagerRateStrategy()
	default:
		strategy, err = CreateStrategy(options.Strategy, options.ConnectionType, int(options.Count), options.Interval.Build())
		if err != nil {
			return nil, err
		}
	}
	logFactory := service.FromContext[log.Factory](ctx)
	r := route.NewRouter(ctx, logFactory, F.ToString("router/", C.TypeRateLimiter, "[", tag, "]"), options.Route, option.DNSOptions{})
	err = r.Initialize(options.Route.Rules, options.Route.RuleSet)
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:     outbound.NewAdapter(C.TypeRateLimiter, tag, nil, []string{}),
		ctx:         ctx,
		outbound:    service.FromContext[adapter.OutboundManager](ctx),
		connection:  service.FromContext[adapter.ConnectionManager](ctx),
		logger:      logger,
		outboundTag: options.Route.Final,
		strategy:    strategy,
		router:      r,
	}
	return outbound, nil
}

func (h *Outbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		detour, loaded := h.outbound.Outbound(h.outboundTag)
		if !loaded {
			return E.New("outbound not found: ", h.outboundTag)
		}
		h.detour = detour
	}
	return h.router.Start(stage, scope)
}

func (h *Outbound) References() []string {
	return h.router.References()
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := h.strategy.request(ctx, adapter.ContextFrom(ctx)); err != nil {
		return nil, err
	}
	return h.detour.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := h.strategy.request(ctx, adapter.ContextFrom(ctx)); err != nil {
		return nil, err
	}
	return h.detour.ListenPacket(ctx, destination)
}

func (h *Outbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if err := h.strategy.request(ctx, &metadata); err != nil {
		h.logger.ErrorContext(ctx, err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Outbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if err := h.strategy.request(ctx, &metadata); err != nil {
		h.logger.ErrorContext(ctx, err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Outbound) GetStrategy() RateStrategy {
	return h.strategy
}
