package balancer

import (
	"math"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/contrab/maphash"
)

type ConsistentHashing struct {
	outbounds            []adapter.Outbound
	delays               map[string]uint16
	hash                 maphash.Hasher[string]
	maxRetry             int
	maxAcceptableDelay   uint16
	idxMutex             sync.Mutex
	delayAcceptableRatio float64
}

func NewConsistentHashing(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *ConsistentHashing {
	return &ConsistentHashing{
		outbounds:            outbounds,
		hash:                 maphash.NewHasher[string](),
		maxRetry:             options.MaxRetry,
		delayAcceptableRatio: options.DelayAcceptableRatio,
	}
}

var _ Strategy = (*ConsistentHashing)(nil)

func (s *ConsistentHashing) Now() string {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()
	return s.outbounds[0].Tag()
}
func (s *ConsistentHashing) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) {
	_, minDelay := getMinDelay(s.outbounds, history)
	acceptableDelay := uint16(math.Max(100, float64(minDelay)) * s.delayAcceptableRatio)
	delayMap := getDelayMap(history)

	s.idxMutex.Lock()
	s.delays = delayMap
	s.maxAcceptableDelay = acceptableDelay
	s.idxMutex.Unlock()
}
func (g *ConsistentHashing) Select(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	g.idxMutex.Lock()
	defer g.idxMutex.Unlock()
	key := g.hash.Hash(getKey(metadata))
	buckets := int32(len(g.outbounds))
	for i := 0; i < g.maxRetry; i, key = i+1, key+1 {
		idx := jumpHash(key, buckets)
		proxy := g.outbounds[idx]
		if g.Alive(proxy) {
			return proxy
		}
	}

	// when availability is poor, traverse the entire list to get the available nodes
	for _, proxy := range g.outbounds {
		if g.Alive(proxy) {
			return proxy
		}
	}
	idx := jumpHash(key, buckets)
	return g.outbounds[idx]

}

func (s *ConsistentHashing) Alive(proxy adapter.Outbound) bool {
	if delay, ok := s.delays[proxy.Tag()]; ok {
		return delay <= s.maxAcceptableDelay
	}
	return false

}
