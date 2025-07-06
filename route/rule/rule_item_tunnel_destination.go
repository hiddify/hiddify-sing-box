package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*TunnelDestinationItem)(nil)

type TunnelDestinationItem struct {
	destinations   []string
	destinationMap map[string]bool
}

func NewTunnelDestinationItem(destinations []string) *TunnelDestinationItem {
	rule := &TunnelDestinationItem{destinations, make(map[string]bool)}
	for _, destination := range destinations {
		rule.destinationMap[destination] = true
	}
	return rule
}

func (r *TunnelDestinationItem) Match(metadata *adapter.InboundContext) bool {
	return r.destinationMap[metadata.TunnelDestination]
}

func (r *TunnelDestinationItem) String() string {
	if len(r.destinations) == 1 {
		return F.ToString("tunnel_destination=", r.destinations[0])
	} else {
		return F.ToString("tunnel_destination=[", strings.Join(r.destinations, " "), "]")
	}
}
