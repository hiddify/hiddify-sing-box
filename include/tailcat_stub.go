//go:build with_tailscale && !with_tailcat

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

func registerTailcatInbound(registry *inbound.Registry) {
	inbound.Register[option.TailcatInboundOptions](registry, C.TypeTailcat, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TailcatInboundOptions) (adapter.Inbound, error) {
		return nil, E.New(`Tailcat is not included in this build, rebuild with -tags with_tailcat`)
	})
}

func registerTailcatOutbound(registry *outbound.Registry) {
	outbound.Register[option.TailcatOutboundOptions](registry, C.TypeTailcat, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TailcatOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`Tailcat is not included in this build, rebuild with -tags with_tailcat`)
	})
}
