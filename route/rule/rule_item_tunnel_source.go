package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*TunnelSourceItem)(nil)

type TunnelSourceItem struct {
	sources   []string
	sourceMap map[string]bool
}

func NewTunnelSourceItem(sources []string) *TunnelSourceItem {
	rule := &TunnelSourceItem{sources, make(map[string]bool)}
	for _, source := range sources {
		rule.sourceMap[source] = true
	}
	return rule
}

func (r *TunnelSourceItem) Match(metadata *adapter.InboundContext) bool {
	return r.sourceMap[metadata.TunnelSource]
}

func (r *TunnelSourceItem) String() string {
	if len(r.sources) == 1 {
		return F.ToString("tunnel_source=", r.sources[0])
	} else {
		return F.ToString("tunnel_source=[", strings.Join(r.sources, " "), "]")
	}
}
