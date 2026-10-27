//go:build with_bond

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/bond"
)

func registerBondInbound(registry *inbound.Registry) {
	bond.RegisterInbound(registry)
}

func registerBondOutbound(registry *outbound.Registry) {
	bond.RegisterOutbound(registry)
}
