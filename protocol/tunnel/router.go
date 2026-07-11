package tunnel

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type Router struct {
	adapter.Router
	logger  logger.ContextLogger
	handler func(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) error
}

func NewRouter(router adapter.Router, logger logger.ContextLogger, handler func(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) error) *Router {
	return &Router{Router: router, logger: logger, handler: handler}
}

func (r *Router) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return r.handler(ctx, conn, metadata, func(error) {})
}

func (r *Router) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return os.ErrInvalid
}

func (r *Router) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if err := r.handler(ctx, conn, metadata, onClose); err != nil {
		r.logger.ErrorContext(ctx, err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
	}
}

func (r *Router) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.logger.ErrorContext(ctx, os.ErrInvalid)
	N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
}
