package dnspool

import (
	"encoding/json"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

const (
	// MinScore and MaxScore bound a resolver's score.
	MinScore = -10
	MaxScore = 10
)

// History is the saved score of each resolver, from MinScore to MaxScore: a resolver that passed
// its tests scores high and is tried first next time. It is kept in the cache file under a key
// the tunnel chooses.
type History struct {
	mu           sync.Mutex
	ResolverRate map[string]int `json:"resolver_rate"`
}

// NewHistory returns an empty history.
func NewHistory() *History {
	return &History{ResolverRate: make(map[string]int)}
}

// LoadHistory reads the history saved under key, or returns an empty one.
func LoadHistory(cache adapter.CacheFile, key string) *History {
	history := NewHistory()
	if cache == nil {
		return history
	}
	saved := cache.LoadBinary(key)
	if saved == nil {
		return history
	}
	var content struct {
		ResolverRate map[string]int `json:"resolver_rate"`
	}
	if err := json.Unmarshal(saved.Content, &content); err != nil || content.ResolverRate == nil {
		return history
	}
	history.ResolverRate = content.ResolverRate
	return history
}

// Save writes the history under key. A nil cache is ignored.
func (h *History) Save(cache adapter.CacheFile, key string, log logger.Logger) {
	if cache == nil {
		return
	}
	h.mu.Lock()
	content, err := json.Marshal(struct {
		ResolverRate map[string]int `json:"resolver_rate"`
	}{h.ResolverRate})
	h.mu.Unlock()
	if err != nil {
		if log != nil {
			log.Error("failed to marshal resolver history: ", err)
		}
		return
	}
	_ = cache.SaveBinary(key, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content})
}

// Score returns a resolver's score, 0 when unknown.
func (h *History) Score(address string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ResolverRate[address]
}

// Record adds delta to a resolver's score. A success (positive delta) first forgets earlier
// failures, so a resolver that works again is not held back by its past; the result stays
// between MinScore and MaxScore.
func (h *History) Record(address string, delta int) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	score := h.ResolverRate[address]
	if delta > 0 && score < 0 {
		score = 0
	}
	score += delta
	if score > MaxScore {
		score = MaxScore
	}
	if score < MinScore {
		score = MinScore
	}
	h.ResolverRate[address] = score
	return score
}

// Sort orders candidates for testing: shuffled, then built-in ones first, then by score from
// high to low. Resolvers that worked before are tried first; among equals the order is random,
// so the same few are not hammered every start.
func (h *History) Sort(candidates []Candidate) {
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.Auto != b.Auto {
			return a.Auto
		}
		return h.ResolverRate[a.Address] > h.ResolverRate[b.Address]
	})
}
