package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

var _ Strategy = (*RoundRobin)(nil)

type RoundRobin struct {
	outbounds map[string][]adapter.Outbound

	sortedOutbounds map[string][]adapter.Outbound

	maxAcceptableIndex   map[string]int
	idx                  map[string]int
	mu                   sync.Mutex
	delayAcceptableRatio float64
}

func NewRoundRobin(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *RoundRobin {
	cOutbounds := convertOutbounds(outbounds)
	acceptable := map[string]int{}
	idx := map[string]int{}
	for net, outs := range cOutbounds {
		acceptable[net] = len(outs) - 1
		idx[net] = 0
	}
	return &RoundRobin{
		outbounds: cOutbounds,

		sortedOutbounds:      cOutbounds,
		maxAcceptableIndex:   acceptable,
		delayAcceptableRatio: options.DelayAcceptableRatio,
		idx:                  idx,
	}
}

func (s *RoundRobin) Now() string {
	// s.idxMutex.Lock()
	// defer s.idxMutex.Unlock()
	return ""
}

func (s *RoundRobin) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	sortedOutbounds := sortOutboundsByDelay(s.outbounds, history)
	acceptableIndex := getAcceptableIndex(sortedOutbounds, history, s.delayAcceptableRatio)

	s.mu.Lock()
	changed := false
	for net, ix := range acceptableIndex {
		changed = changed || ix != s.maxAcceptableIndex[net]
	}

	s.sortedOutbounds = sortedOutbounds
	s.maxAcceptableIndex = acceptableIndex
	s.mu.Unlock()
	return changed
}

func (s *RoundRobin) Select(metadata adapter.InboundContext, net string, touch bool) adapter.Outbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	if net != N.NetworkTCP && net != N.NetworkUDP {
		net = N.NetworkTCP
	}
	i := 1
	length := s.maxAcceptableIndex[net] + 1
	if length == 0 {
		return nil
	}
	id := (s.idx[net] + i) % length
	proxy := s.sortedOutbounds[net][id]
	if touch {
		s.idx[net] = id
	}
	return proxy

}
