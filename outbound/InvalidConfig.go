package outbound

import (
	"context"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.Outbound = (*InvalidConfig)(nil)

type InvalidConfig struct {
	myOutboundAdapter
	err error
}

func NewInvalidConfig(logger log.ContextLogger, tag string, err error) *InvalidConfig {
	return &InvalidConfig{
		myOutboundAdapter{
			protocol: C.TypeInvalidConfig,
			network:  []string{N.NetworkUDP, N.NetworkTCP},
			logger:   logger,
			tag:      tag,
		},
		err,
	}
}
func (h *InvalidConfig) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	h.logger.InfoContext(ctx, "InvalidConfiged connection to ", destination)
	h.logger.ErrorContext(ctx, h.tag, h.err)
	return nil, io.EOF
}

func (h *InvalidConfig) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "InvalidConfiged packet connection to ", destination)
	h.logger.ErrorContext(ctx, h.tag, h.err)
	return nil, io.EOF
}

func (h *InvalidConfig) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	conn.Close()
	h.logger.InfoContext(ctx, "InvalidConfiged connection to ", metadata.Destination)
	return nil
}

func (h *InvalidConfig) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	conn.Close()
	h.logger.InfoContext(ctx, "InvalidConfiged packet connection to ", metadata.Destination)
	return nil
}

func (h *InvalidConfig) Type() string {
	return h.err.Error()
}
