package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

var _ Strategy = (*RoundRobin)(nil)

type RoundRobin struct {
	outbounds            []adapter.Outbound
	sortedOutbounds      []adapter.Outbound
	maxAcceptableIndex   int
	idx                  int
	idxMutex             sync.Mutex
	delayAcceptableRatio float64
}

func NewRoundRobin(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *RoundRobin {
	return &RoundRobin{
		outbounds:            outbounds,
		sortedOutbounds:      outbounds,
		delayAcceptableRatio: options.DelayAcceptableRatio,
	}
}

func (s *RoundRobin) Now() string {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()
	return s.sortedOutbounds[0].Tag()
}

func (s *RoundRobin) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) {
	sortedOutbounds := sortOutboundsByDelay(s.outbounds, history)
	acceptableIndex := getAcceptableIndex(sortedOutbounds, history, s.delayAcceptableRatio)

	s.idxMutex.Lock()
	s.sortedOutbounds = sortedOutbounds
	s.maxAcceptableIndex = acceptableIndex
	s.idxMutex.Unlock()
}

func (s *RoundRobin) Select(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()

	i := 1
	length := s.maxAcceptableIndex + 1
	if length == 0 {
		return nil
	}
	id := (s.idx + i) % length
	proxy := s.sortedOutbounds[id]
	if touch {
		s.idx = id
	}
	return proxy

}
