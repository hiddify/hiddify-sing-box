package balancer

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

type StickySession struct {
	outbounds          []adapter.Outbound
	hash               maphash.Hasher[string]
	maxRetry           int
	delays             map[string]uint16
	maxAcceptableDelay uint16

	idxMutex             sync.Mutex
	delayAcceptableRatio float64
	lruCache             *freelru.Cache[uint64, int]
}

func NewStickySession(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *StickySession {
	lruCache := common.Must1(freelru.NewSharded[uint64, int](1000, maphash.NewHasher[uint64]().Hash32))
	lruCache.SetLifetime(options.TTL.Build())
	return &StickySession{
		outbounds:            outbounds,
		lruCache:             lruCache,
		hash:                 maphash.NewHasher[string](),
		maxRetry:             options.MaxRetry,
		delayAcceptableRatio: options.DelayAcceptableRatio,
	}
}

var _ Strategy = (*StickySession)(nil)

func (s *StickySession) Select(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()
	key := s.hash.Hash(getKeyWithSrcAndDst(metadata))
	length := len(s.outbounds)
	idx, has := s.lruCache.Get(key)
	if !has || idx >= length {
		idx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
	}

	nowIdx := idx
	for i := 1; i < s.maxRetry; i++ {
		proxy := s.outbounds[nowIdx]
		if s.Alive(proxy) {
			if !has || nowIdx != idx {
				s.lruCache.Add(key, nowIdx)
			}

			return proxy
		} else {
			nowIdx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
		}
	}

	s.lruCache.Add(key, nowIdx)
	return s.outbounds[nowIdx]

}

var _ Strategy = (*ConsistentHashing)(nil)

func (s *StickySession) Now() string {
	s.idxMutex.Lock()
	defer s.idxMutex.Unlock()
	return s.outbounds[0].Tag()
}
func (s *StickySession) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) {
	acceptableDelay := uint16(float64(getMinDelay(history)) * s.delayAcceptableRatio)
	delayMap := getDelayMap(history)

	s.idxMutex.Lock()
	s.delays = delayMap
	s.maxAcceptableDelay = acceptableDelay
	s.idxMutex.Unlock()
}

func (s *StickySession) Alive(proxy adapter.Outbound) bool {
	if delay, ok := s.delays[proxy.Tag()]; ok {
		return delay <= s.maxAcceptableDelay
	}
	return false

}
