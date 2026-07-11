package balancer

import (
	"math"
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
	lruCache             *freelru.ShardedLRU[uint64, int]
}

func NewStickySession(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *StickySession {
	lruCache := common.Must1(freelru.NewSharded[uint64, int](1000, maphash.NewHasher[uint64]().Hash32))
	lruCache.SetLifetime(options.TTL.Build())
	cOutbounds := convertOutbounds(outbounds)
	return &StickySession{
		outbounds:            cOutbounds,
		lruCache:             lruCache,
		hash:                 maphash.NewHasher[string](),
		maxRetry:             options.MaxRetry,
		delayAcceptableRatio: options.DelayAcceptableRatio,
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
	length := len(s.outbounds[net])
	idx, has := s.lruCache.Get(key)
	if !has || idx >= length {
		idx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
	}

	nowIdx := idx
	for i := 1; i < s.maxRetry; i++ {
		proxy := s.outbounds[net][nowIdx]
		if s.Alive(proxy, net) {
			if !has || nowIdx != idx {
				s.lruCache.Add(key, nowIdx)
			}

			return proxy
		} else {
			nowIdx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
		}
	}

	s.lruCache.Add(key, nowIdx)
	return s.outbounds[net][nowIdx]

}

func (s *StickySession) Now() string {
	return ""
}
func (s *StickySession) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
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

func (s *StickySession) Alive(proxy adapter.Outbound, net string) bool {
	if delay, ok := s.delays[proxy.Tag()]; ok {
		return delay <= s.maxAcceptableDelay[net]
	}
	return false

}
