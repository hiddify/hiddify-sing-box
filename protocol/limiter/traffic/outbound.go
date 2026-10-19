package traffic

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TrafficLimiterOutboundOptions](registry, C.TypeTrafficLimiter, NewOutbound)
}

var _ adapter.Lifecycle = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx         context.Context
	outbound    adapter.OutboundManager
	connection  adapter.ConnectionManager
	logger      logger.ContextLogger
	strategy    TrafficStrategy
	outboundTag string
	detour      adapter.Outbound
	router      *route.Router
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrafficLimiterOutboundOptions) (adapter.Outbound, error) {
	if options.Route.Final == "" {
		return nil, E.New("missing final outbound")
	}
	strategy := NewManagerTrafficStrategy()
	logFactory := service.FromContext[log.Factory](ctx)
	r := route.NewRouter(ctx, logFactory, F.ToString("router/", C.TypeTrafficLimiter, "[", tag, "]"), options.Route, option.DNSOptions{})
	err := r.Initialize(options.Route.Rules, options.Route.RuleSet)
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:     outbound.NewAdapter(C.TypeTrafficLimiter, tag, nil, []string{}),
		ctx:         ctx,
		outbound:    service.FromContext[adapter.OutboundManager](ctx),
		connection:  service.FromContext[adapter.ConnectionManager](ctx),
		logger:      logger,
		strategy:    strategy,
		outboundTag: options.Route.Final,
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
	conn, err := h.detour.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	wrappedConn, err := h.strategy.wrapConn(ctx, conn, adapter.ContextFrom(ctx), true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return wrappedConn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.detour.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	wrappedConn, err := h.strategy.wrapPacketConn(ctx, conn, adapter.ContextFrom(ctx), true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return wrappedConn, nil
}

func (h *Outbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	wrappedConn, err := h.strategy.wrapConn(ctx, conn, &metadata, false)
	if err != nil {
		if err.Error() != "traffic limit exceeded" {
			h.logger.ErrorContext(ctx, err)
		}
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	h.router.RouteConnectionEx(ctx, wrappedConn, metadata, onClose)
}

func (h *Outbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	packetConn, err := h.strategy.wrapPacketConn(ctx, bufio.NewNetPacketConn(conn), &metadata, false)
	if err != nil {
		if err.Error() != "traffic limit exceeded" {
			h.logger.ErrorContext(ctx, err)
		}
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	h.router.RoutePacketConnectionEx(ctx, bufio.NewPacketConn(packetConn), metadata, onClose)
}

func (h *Outbound) GetStrategy() TrafficStrategy {
	return h.strategy
}
