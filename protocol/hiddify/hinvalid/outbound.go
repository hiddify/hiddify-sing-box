package hinvalid

import (
	"context"
	"net"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HInvalidOptions](registry, C.TypeHInvalidConfig, New)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger         logger.ContextLogger
	InvalidOptions option.HInvalidOptions
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, invalidOptions option.HInvalidOptions) (adapter.Outbound, error) {
	return &Outbound{
		Adapter:        outbound.NewAdapter(C.TypeHInvalidConfig, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		logger:         logger,
		InvalidOptions: invalidOptions,
	}, nil
}

func (h *Outbound) Type() string {
	return C.TypeHInvalidConfig
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	h.logger.InfoContext(ctx, "blocked connection to ", destination)
	return nil, syscall.EPERM
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "blocked packet connection to ", destination)
	return nil, syscall.EPERM
}
