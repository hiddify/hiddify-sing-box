//go:build !with_bond

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerBondInbound(registry *inbound.Registry) {
	inbound.Register[option.BondInboundOptions](registry, C.TypeBond, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BondInboundOptions) (adapter.Inbound, error) {
		return nil, E.New(`Bond is not included in this build, rebuild with -tags with_bond`)
	})
}

func registerBondOutbound(registry *outbound.Registry) {
	outbound.Register[option.BondOutboundOptions](registry, C.TypeBond, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BondOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`Bond is not included in this build, rebuild with -tags with_bond`)
	})
}
