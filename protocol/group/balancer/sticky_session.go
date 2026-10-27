package balancer

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

type StickySession struct {
	outbounds          map[string][]adapter.Outbound
	hash               maphash.Hasher[string]
	maxRetry           int
	delays             map[string]uint16
	maxAcceptableDelay map[string]uint16

	mu                   sync.Mutex
	delayAcceptableRatio float64
	lruCache             *freelru.Cache[uint64, int]
	alive                map[string]string // members within the acceptable delay, per network
}

func NewStickySession(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *StickySession {
	lruCache := common.Must1(freelru.New[uint64, int](1000, maphash.NewHasher[uint64]().Hash32, true))
	lruCache.SetLifetime(options.TTL.Build())
	cOutbounds := convertOutbounds(outbounds)
	return &StickySession{
		outbounds:            cOutbounds,
		lruCache:             lruCache,
		hash:                 maphash.NewHasher[string](),
		maxRetry:             options.MaxRetry,
		delayAcceptableRatio: acceptableRatio(options),
	}
}

var _ Strategy = (*StickySession)(nil)

func (s *StickySession) Select(metadata adapter.InboundContext, net string, touch bool) adapter.Outbound {
	s.mu.Lock()
	defer s.mu.Unlock()

	if net != N.NetworkTCP && net != N.NetworkUDP {
		net = N.NetworkTCP
	}
	key := s.hash.Hash(getKeyWithSrcAndDst(&metadata))
	outbounds := s.outbounds[net]
	length := int32(len(outbounds))
	idx, has := s.lruCache.Get(key)
	if !has || idx >= len(outbounds) {
		has = false
		idx = int(jumpHash(key+uint64(time.Now().UnixNano()), length))
	}

	pick := idx
	if !s.Alive(outbounds[pick], net) {
		pick = -1
		// a new random seed per session, stepped on each retry so every retry draws again
		seed := key + uint64(time.Now().UnixNano())
		for i := 0; i < s.maxRetry; i++ {
			candidate := int(jumpHash(seed+uint64(i)+1, length))
			if s.Alive(outbounds[candidate], net) {
				pick = candidate
				break
			}
		}
		// when availability is poor, traverse the entire list to get the available nodes
		for i := 0; pick < 0 && i < len(outbounds); i++ {
			if s.Alive(outbounds[i], net) {
				pick = i
			}
		}
		if pick < 0 {
			pick = idx
		}
	}
	if !has || pick != idx {
		s.lruCache.Add(key, pick)
	}
	return outbounds[pick]
}

func (s *StickySession) Now() string {
	return ""
}
func (s *StickySession) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	_, minDelay := getMinDelay(s.outbounds, history)
	delayMap := getDelayMap(history)
	res := map[string]uint16{}
	for net, d := range minDelay {
		res[net] = getMaxAcceptableDelay(d, s.delayAcceptableRatio)
	}
	alive := aliveSet(s.outbounds, delayMap, res)
	s.mu.Lock()
	changed := aliveSetChanged(s.alive, alive) // not every update: interrupt_exist_connections would close all connections each time
	s.delays = delayMap
	s.maxAcceptableDelay = res
	s.alive = alive
	s.mu.Unlock()
	return changed
}

func (s *StickySession) Alive(proxy adapter.Outbound, net string) bool {
	if delay, ok := s.delays[proxy.Tag()]; ok {
		return delay <= s.maxAcceptableDelay[net]
	}
	return false

}
