//go:build with_wireguard

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/warp"
)

func registerWarpEndpoint(registry *endpoint.Registry) {
	warp.RegisterWARPEndpoint(registry)
}
