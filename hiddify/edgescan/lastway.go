package edgescan

import (
	"context"
	"maps"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"
)

// A last way is checked with LastWayAttempts handshakes, each within LastWayTimeout: one lost
// packet does not send the start to a full search, and a way that is gone costs a few seconds.
const (
	LastWayAttempts = 2
	LastWayTimeout  = 3 * time.Second
)

// A LastWay is the way through that worked last for a kind of scanner: the target it connected
// to (none for a way that is only a method) and the methods it used (a noise, a tunnel, a Psiphon
// protocol), on the network it was on.
// The next start tries it first, before it names the network or scans: a quick check of it is
// enough to connect, and the search for a better way goes on once it is connected. The store
// keeps one per key, saved with the books, for Lifetime.
type LastWay struct {
	Network string            `json:"n,omitempty"`
	Target  Target            `json:"t"`
	Methods map[string]string `json:"m,omitempty"`
	At      time.Time         `json:"at"`
}

// Method is the value of a method of the way, "" when it has none.
func (w LastWay) Method(name string) string {
	return w.Methods[name]
}

// LastWay returns the way through kept under key, unless it is older than Lifetime.
func (s *Store) LastWay(key string) (LastWay, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	way, found := s.lastWays[key]
	if !found || time.Since(way.At) > Lifetime {
		return LastWay{}, false
	}
	way.Methods = maps.Clone(way.Methods)
	return way, true
}

// RememberWay keeps way under key, as the way through that worked last; the caller saves the
// store.
func (s *Store) RememberWay(key string, way LastWay) {
	if way.At.IsZero() {
		way.At = time.Now()
	}
	way.Methods = maps.Clone(way.Methods)
	s.access.Lock()
	defer s.access.Unlock()
	if s.lastWays == nil {
		s.lastWays = make(map[string]LastWay)
	}
	s.lastWays[key] = way
}

// ForgetWay drops the way kept under key: it no longer works.
func (s *Store) ForgetWay(key string) {
	s.access.Lock()
	defer s.access.Unlock()
	delete(s.lastWays, key)
}

// TryLastWay checks target with probe (see LastWayAttempts) and returns the handshake time.
func TryLastWay(ctx context.Context, probe Probe, target netip.AddrPort) (time.Duration, error) {
	var err error
	for range LastWayAttempts {
		attemptCtx, cancel := context.WithTimeout(ctx, LastWayTimeout)
		var rtt time.Duration
		rtt, err = probe(attemptCtx, target)
		cancel()
		if err == nil {
			return rtt, nil
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
	}
	return 0, err
}

// Better reports whether found is better than the target in use, which has score on the network
// and answered in rtt: another target with a higher score, or as good a score and a handshake in
// less than two thirds of the time. A working way is not dropped for a small gain.
func Better(found Result, current netip.AddrPort, score rating.Score, rtt time.Duration) bool {
	if found.AddrPort == current {
		return false
	}
	if found.Score != score {
		return found.Score > score
	}
	return rtt > 0 && found.RTT > 0 && found.RTT*3 < rtt*2
}
