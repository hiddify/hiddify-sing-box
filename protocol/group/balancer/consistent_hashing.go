package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/contrab/maphash"
)

type ConsistentHashing struct {
	outbounds            []adapter.Outbound
	sortedOutbounds      []adapter.Outbound
	hash                 maphash.Hasher[string]
	maxRetry             int
	maxAcceptableIndex   int
	idxMutex             sync.Mutex
	delayAcceptableRatio float64
}

func NewConsistentHashing(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *ConsistentHashing {
	return &ConsistentHashing{
		outbounds:            outbounds,
		sortedOutbounds:      outbounds,
		hash:                 maphash.NewHasher[string](),
		maxRetry:             options.MaxRetry,
		delayAcceptableRatio: options.DelayAcceptableRatio,
	}
}

var _ Strategy = (*ConsistentHashing)(nil)

func (s *ConsistentHashing) Now() string {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()
	return s.sortedOutbounds[0].Tag()
}
func (s *ConsistentHashing) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) {
	sortedOutbounds := sortOutboundsByDelay(s.outbounds, history)
	acceptableIndex := getAcceptableIndex(sortedOutbounds, history, s.delayAcceptableRatio)

	s.idxMutex.Lock()
	s.sortedOutbounds = sortedOutbounds
	s.maxAcceptableIndex = acceptableIndex
	s.idxMutex.Unlock()
}
func (g *ConsistentHashing) Select(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	key := g.hash.Hash(getKey(metadata))
	buckets := int32(g.maxAcceptableIndex + 1)
	for i := 0; i < g.maxRetry; i, key = i+1, key+1 {
		idx := jumpHash(key, buckets)
		proxy := g.outbounds[idx]
		// if g.AliveForTestUrl(proxy) {
		return proxy
		// }
	}

	// when availability is poor, traverse the entire list to get the available nodes
	for _, proxy := range g.outbounds {
		// if g.AliveForTestUrl(proxy) {
		return proxy
		// }
	}

	return g.outbounds[0]

}
