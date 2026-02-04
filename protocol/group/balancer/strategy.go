package balancer

import "github.com/sagernet/sing-box/adapter"

type Strategy interface {
	UpdateOutboundsInfo(outbounds map[string]*adapter.URLTestHistory)
	Select(metadata *adapter.InboundContext, touch bool) adapter.Outbound
	Now() string
}
