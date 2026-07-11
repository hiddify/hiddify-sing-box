package balancer

import (
	"math"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/contrab/maphash"
)

type ConsistentHashing struct {
	outbounds            map[string][]adapter.Outbound
	delays               map[string]uint16
	hash                 maphash.Hasher[string]
	maxRetry             int
	maxAcceptableDelay   map[string]uint16
	mu                   sync.Mutex
	delayAcceptableRatio float64
}

func NewConsistentHashing(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *ConsistentHashing {
	cOutbounds := convertOutbounds(outbounds)

	return &ConsistentHashing{
		outbounds:            cOutbounds,
		hash:                 maphash.NewHasher[string](),
		maxRetry:             options.MaxRetry,
		delayAcceptableRatio: options.DelayAcceptableRatio,
	}
}

var _ Strategy = (*ConsistentHashing)(nil)

func (s *ConsistentHashing) Now() string {
	return ""
}
func (s *ConsistentHashing) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	_, minDelay := getMinDelay(s.outbounds, history)
	delayMap := getDelayMap(history)
	res := map[string]uint16{}
	for net, d := range minDelay {
		acceptableDelay := uint16(math.Max(100, float64(d)) * s.delayAcceptableRatio)
		res[net] = acceptableDelay
	}
	s.mu.Lock()
	s.delays = delayMap
	s.maxAcceptableDelay = res
	s.mu.Unlock()
	return true
}
func (g *ConsistentHashing) Select(metadata adapter.InboundContext, net string, touch bool) adapter.Outbound {
	g.mu.Lock()
	defer g.mu.Unlock()
	if net != N.NetworkTCP && net != N.NetworkUDP {
		net = N.NetworkTCP
	}
	key := g.hash.Hash(getKey(&metadata))
	buckets := int32(len(g.outbounds[net]))
	for i := 0; i < g.maxRetry; i, key = i+1, key+1 {
		idx := jumpHash(key, buckets)
		proxy := g.outbounds[net][idx]
		if g.Alive(proxy, net) {
			return proxy
		}
	}

	// when availability is poor, traverse the entire list to get the available nodes
	for _, proxy := range g.outbounds[net] {
		if g.Alive(proxy, net) {
			return proxy
		}
	}
	idx := jumpHash(key, buckets)
	return g.outbounds[net][idx]

}

func (s *ConsistentHashing) Alive(proxy adapter.Outbound, net string) bool {
	if delay, ok := s.delays[proxy.Tag()]; ok {
		return delay <= s.maxAcceptableDelay[net]
	}
	return false

}
