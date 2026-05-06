package tooska

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/hiddify/tooska/scanner"
)

const (
	scoreFloor = -10
	scoreCap   = 10
	scoreHit   = 1
	scoreMiss  = 1
)

func historyKey(tag string) string { return "tooska_endpoints_" + tag }

type poolEntry struct {
	IP        string           `json:"ip"`
	Port      int              `json:"port"`
	Protocol  scanner.Protocol `json:"protocol,omitempty"`
	Score     int              `json:"score"`
	LatencyMS int64            `json:"latency_ms,omitempty"`
	LastCheck time.Time        `json:"last_check,omitempty"`
}

func (e *poolEntry) key() string { return joinHostPort(e.IP, e.Port) }
func (e *poolEntry) ok() bool    { return e.Score >= 0 && e.Protocol != "" }

type pool struct {
	mu      sync.RWMutex
	entries map[string]*poolEntry
}

func newPool() *pool { return &pool{entries: map[string]*poolEntry{}} }

func (p *pool) load(cache adapter.CacheFile, tag string) {
	if cache == nil {
		return
	}
	saved := cache.LoadBinary(historyKey(tag))
	if saved == nil {
		return
	}
	var dump []*poolEntry
	if err := json.Unmarshal(saved.Content, &dump); err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range dump {
		if e == nil || e.IP == "" {
			continue
		}
		if e.Score < scoreFloor {
			e.Score = scoreFloor
		} else if e.Score > scoreCap {
			e.Score = scoreCap
		}
		p.entries[e.key()] = e
	}
}

func (p *pool) save(cache adapter.CacheFile, tag string) {
	if cache == nil {
		return
	}
	p.mu.RLock()
	dump := make([]*poolEntry, 0, len(p.entries))
	for _, e := range p.entries {
		dump = append(dump, e)
	}
	p.mu.RUnlock()
	content, err := json.Marshal(dump)
	if err != nil {
		return
	}
	_ = cache.SaveBinary(historyKey(tag), &adapter.SavedBinary{
		LastUpdated: time.Now(),
		Content:     content,
	})
}

// recordHit resets a negative score to zero before incrementing — same
// rule the dnstt resolver pool uses, so a previously-bad endpoint that
// just came back online climbs the queue without clawing back from -10.
func (p *pool) recordHit(r scanner.Result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := joinHostPort(r.IP, r.Port)
	e, ok := p.entries[key]
	if !ok {
		e = &poolEntry{IP: r.IP, Port: r.Port}
		p.entries[key] = e
	}
	if e.Score < 0 {
		e.Score = 0
	}
	e.Score += scoreHit
	if e.Score > scoreCap {
		e.Score = scoreCap
	}
	if r.Protocol != "" {
		e.Protocol = r.Protocol
	}
	if r.LatencyMS > 0 {
		e.LatencyMS = r.LatencyMS
	}
	e.LastCheck = time.Now()
}

func (p *pool) recordMiss(ip string, port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := joinHostPort(ip, port)
	e, ok := p.entries[key]
	if !ok {
		e = &poolEntry{IP: ip, Port: port}
		p.entries[key] = e
	}
	e.Score -= scoreMiss
	if e.Score < scoreFloor {
		e.Score = scoreFloor
	}
	e.LastCheck = time.Now()
}

func (p *pool) score(ip string, port int) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e, ok := p.entries[joinHostPort(ip, port)]; ok {
		return e.Score
	}
	return 0
}

func (p *pool) working(limit int) []poolEntry {
	p.mu.RLock()
	out := make([]poolEntry, 0, len(p.entries))
	for _, e := range p.entries {
		if e.ok() {
			out = append(out, *e)
		}
	}
	p.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].LatencyMS != out[j].LatencyMS {
			if out[i].LatencyMS == 0 {
				return false
			}
			if out[j].LatencyMS == 0 {
				return true
			}
			return out[i].LatencyMS < out[j].LatencyMS
		}
		return out[i].key() < out[j].key()
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (p *pool) workingCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, e := range p.entries {
		if e.ok() {
			n++
		}
	}
	return n
}
