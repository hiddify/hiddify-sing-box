package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type LowestDelay struct {
	outbounds       []adapter.Outbound
	sortedOutbounds []adapter.Outbound
	idxMutex        sync.Mutex
}

func NewLowestDelay(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *LowestDelay {
	return &LowestDelay{
		outbounds:       outbounds,
		sortedOutbounds: outbounds,
	}
}

var _ Strategy = (*LowestDelay)(nil)

func (s *LowestDelay) Now() string {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()

	if len(s.sortedOutbounds) > 0 {
		return s.sortedOutbounds[0].Tag()
	}

	return ""
}
func (s *LowestDelay) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) {
	sortedOutbounds := sortOutboundsByDelay(s.outbounds, history)

	s.idxMutex.Lock()
	s.sortedOutbounds = sortedOutbounds
	s.idxMutex.Unlock()

}
func (s *LowestDelay) Select(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()

	for _, proxy := range s.sortedOutbounds {
		return proxy
	}

	return nil
}
