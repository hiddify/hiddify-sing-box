package balancer

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	N "github.com/sagernet/sing/common/network"
)

// The LOWEST log: what lowest-delay decides and why, for TCP (UDP decides the same way), when the
// balancer gave the strategy its logger. A member kept as the fastest is not logged: that is the
// steady state, once per group event.

// pingOf is a member's result for the log: "17 ms", "cached 17 ms", "failed", "untested".
func pingOf(his *adapter.URLTestHistory) string {
	if his == nil {
		return monitoring.DelayString(0, false)
	}
	return monitoring.DelayString(his.Delay, his.IsFromCache)
}

func (s *LowestDelay) logs(net string) bool {
	return s.logger != nil && net == N.NetworkTCP
}

// logKeep: a faster member was rejected for the selected one, for the reason in why; once per
// rival, not on every group event while it stays the fastest.
func (s *LowestDelay) logKeep(net string, current, best adapter.Outbound, history map[string]*adapter.URLTestHistory, why ...any) {
	if !s.logs(net) || s.lastRival == best.Tag() {
		return
	}
	s.lastRival = best.Tag()
	args := []any{"LOWEST ", s.tag, ": keeps ", current.Tag(), " ", pingOf(history[current.Tag()]), " (fastest: ", best.Tag(), " ", pingOf(history[best.Tag()]), "): "}
	s.logger.Info(append(args, why...)...)
}

// logSwitch: best takes the selection from current, which had the penalised delay currentDelay
// against best's bestDelay and the threshold.
func (s *LowestDelay) logSwitch(net string, current, best adapter.Outbound, history map[string]*adapter.URLTestHistory, currentDelay, bestDelay uint16, threshold uint32) {
	if !s.logs(net) {
		return
	}
	s.lastRival = ""
	his := history[current.Tag()]
	var why []any
	switch {
	case his == nil || his.Delay == 0:
		why = []any{"the selected one has no result yet"}
	case his.Delay >= monitoring.TimeoutDelay:
		why = []any{"the selected one failed its test"}
	case his.IsFromCache:
		why = []any{"a real ping takes a cached pick: a cached ping only orders the members"}
	default:
		why = []any{"faster by ", currentDelay - bestDelay, " ms, more than the tolerance of ", threshold, " ms"}
	}
	args := []any{"LOWEST ", s.tag, ": switch ", current.Tag(), " ", pingOf(his), " -> ", best.Tag(), " ", pingOf(history[best.Tag()]), ": "}
	s.logger.Info(append(args, why...)...)
}

// logHold: the selection is kept while the cycle that started at since has not tested it; once
// per cycle. s.mu is held.
func (s *LowestDelay) logHold(since time.Time) {
	if s.logger == nil || s.heldSince.Equal(since) {
		return
	}
	s.heldSince = since
	s.logger.Info("LOWEST ", s.tag, ": keeps ", s.selectedOutbound[N.NetworkTCP].Tag(), " while the cycle has not tested it")
}
