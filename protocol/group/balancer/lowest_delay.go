package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type LowestDelay struct {
	outbounds        []adapter.Outbound
	selectedOutbound adapter.Outbound
	idxMutex         sync.Mutex
}

func NewLowestDelay(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *LowestDelay {
	return &LowestDelay{
		outbounds:        outbounds,
		selectedOutbound: outbounds[0],
	}
}

var _ Strategy = (*LowestDelay)(nil)

func (s *LowestDelay) Now() string {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()

	return s.selectedOutbound.Tag()
}
func (s *LowestDelay) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) {
	min, _ := getMinDelay(s.outbounds, history)

	s.idxMutex.Lock()
	s.selectedOutbound = min
	s.idxMutex.Unlock()
}
func (s *LowestDelay) Select(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()
	return s.selectedOutbound
}
