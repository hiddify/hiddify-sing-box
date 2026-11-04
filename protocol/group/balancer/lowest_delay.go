package balancer

import (
	"sync"
	"time" //H

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/log" //H
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

type LowestDelay struct {
	outbounds        map[string][]adapter.Outbound
	udpOutbounds     []adapter.Outbound
	selectedOutbound map[string]adapter.Outbound
	tolerance        uint16            // a member takes the selection when faster by more than this ...
	toleranceRatio   float64           // ... and than this share of the selected member's delay
	logger           log.ContextLogger // H: the LOWEST log, set by the balancer; nil in tests
	tag              string            // H: the group's tag, for the log
	heldSince        time.Time         // H: the cycle the hold was last logged for, see logHold
	lastRival        string            // H: the faster member last logged as rejected, see logKeep
	switchedAt       time.Time         // H: when a member with a real ping took the selection, see minStay
	stay             time.Duration     // H: how long that member stays while it answers, minStay

	mu sync.Mutex
}

func NewLowestDelay(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *LowestDelay {
	couts := convertOutbounds(outbounds)
	tolerance := options.Tolerance
	if tolerance == 0 {
		tolerance = defaultTolerance
	}
	ratio := options.ToleranceRatio
	if ratio <= 0 {
		ratio = defaultToleranceRatio
	}
	return &LowestDelay{
		outbounds: couts,
		selectedOutbound: map[string]adapter.Outbound{
			N.NetworkUDP: couts[N.NetworkUDP][0],
			N.NetworkTCP: couts[N.NetworkTCP][0],
		},
		tolerance:      tolerance,
		toleranceRatio: ratio,
		stay:           minStay, //H
	}
}

var _ Strategy = (*LowestDelay)(nil)

func (s *LowestDelay) Now() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.selectedOutbound[N.NetworkTCP].Tag()
}

// UpdateOutboundsInfo keeps the selected member while its real ping answers, unless another real
// ping is faster by more than the tolerance and than tolerance_ratio of the selected member's
// delay. A member that took the selection with a real ping stays for minStay while it answers,
// whatever comes in: the first cycle's results arrive one by one, and the selection hopped at
// each faster one. A selected member that failed its test is left for the fastest live one; when
// no member is live, the selection stays. A ping cached from the previous run decides nothing: it
// only orders the members until the real pings arrive, so a cached pick is left for the first real
// ping that works, however slow, and for a better cached one, and a cached ping never takes a
// member whose real ping answers.
func (s *LowestDelay) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	min, delays := getMinDelay(s.outbounds, history) // real pings first, then cached ones

	s.mu.Lock()
	changed := false
	for net, best := range min {
		current := s.selectedOutbound[net]
		if best == nil || best.Tag() == current.Tag() || delays[net] >= monitoring.TimeoutDelay {
			continue
		}
		currentHis, bestHis := history[current.Tag()], history[best.Tag()]                 //H
		currentMeasured, bestMeasured := measuredDelay(currentHis), measuredDelay(bestHis) //H
		threshold := SelectedThreshold(currentHis, s.tolerance, s.toleranceRatio)          //H: none for a cached pick
		if answers(currentHis) {                                                           //H: its real ping answers: only a real ping, faster by the tolerance, after the stay
			if !answers(bestHis) { //H
				s.logKeep(net, current, best, history, "a cached ping does not take a real one") //H
				continue                                                                         //H
			} //H
			if since := time.Since(s.switchedAt); !s.switchedAt.IsZero() && since < s.stay { //H
				s.logKeep(net, current, best, history, "chosen ", since.Round(time.Second), " ago, stays ", s.stay) //H
				continue                                                                                            //H
			} //H
			if uint32(bestMeasured)+threshold >= uint32(currentMeasured) { //H
				s.logKeep(net, current, best, history, "not faster by more than ", threshold, " ms") //H
				continue
			}
		} //H
		s.logSwitch(net, current, best, history, currentMeasured, bestMeasured, threshold) //H
		s.selectedOutbound[net] = best
		if answers(bestHis) && net == N.NetworkTCP { //H: a real ping: it stays a while
			s.switchedAt = time.Now() //H
		} //H
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
