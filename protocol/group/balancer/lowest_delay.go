package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

type LowestDelay struct {
	outbounds        map[string][]adapter.Outbound
	udpOutbounds     []adapter.Outbound
	selectedOutbound map[string]adapter.Outbound
	tolerance        uint16 // a member takes the selection when faster by more than this

	mu sync.Mutex
}

func NewLowestDelay(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *LowestDelay {
	couts := convertOutbounds(outbounds)
	tolerance := options.Tolerance
	if tolerance == 0 {
		tolerance = defaultTolerance
	}
	return &LowestDelay{
		outbounds: couts,
		selectedOutbound: map[string]adapter.Outbound{
			N.NetworkUDP: couts[N.NetworkUDP][0],
			N.NetworkTCP: couts[N.NetworkTCP][0],
		},
		tolerance: tolerance,
	}
}

var _ Strategy = (*LowestDelay)(nil)

func (s *LowestDelay) Now() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.selectedOutbound[N.NetworkTCP].Tag()
}

// UpdateOutboundsInfo keeps the selected member while it answers, unless another one is faster
// by more than the tolerance. A selected member that failed its test is left for the fastest
// live one; when no member is live, the selection stays.
func (s *LowestDelay) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	min, delays := getMinDelay(s.outbounds, history)

	s.mu.Lock()
	changed := false
	for net, best := range min {
		current := s.selectedOutbound[net]
		if best == nil || best.Tag() == current.Tag() || delays[net] >= monitoring.TimeoutDelay {
			continue
		}
		currentDelay := getTagDelay(current.Tag(), history)
		if currentDelay < monitoring.TimeoutDelay && uint32(delays[net])+uint32(s.tolerance) >= uint32(currentDelay) {
			continue
		}
		s.selectedOutbound[net] = best
		changed = true
	}
	s.mu.Unlock()
	return changed
}
func (s *LowestDelay) Select(metadata adapter.InboundContext, net string, touch bool) adapter.Outbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	if net != N.NetworkTCP && net != N.NetworkUDP {
		net = N.NetworkTCP
	}
	return s.selectedOutbound[net]

}
