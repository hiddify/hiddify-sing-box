//go:build !with_masque

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerMASQUEOutbound(registry *outbound.Registry) {
	outbound.Register[option.MASQUEOutboundOptions](registry, C.TypeMASQUE, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`MASQUE outbound is not included in this build, rebuild with -tags with_masque`)
	})
}
