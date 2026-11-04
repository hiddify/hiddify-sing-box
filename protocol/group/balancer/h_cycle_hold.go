package balancer

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
)

// While a regular test cycle of the schedule runs (not the first one after start, nor one after a
// network change, whose results are taken as they come), its results arrive one by one, and a strategy that took each at once
// moved its selection many times in one cycle: lowest-delay jumped to whichever member had just
// answered fastest, and round robin re-ranked its members each time. A strategy that can hold
// keeps the members it uses while they still answer in this run, and chooses with all the results
// when the cycle ends (monitoring tells every group). A member in use that fails, or that has no
// result of this run yet (at start, the cached or the first member), is replaced at once by the
// best one known so far, until the cycle ends and the best of all is chosen.
//
// Lowest-delay holds only until the cycle has tested the member in use: a result of this cycle
// for it and for a faster member is a fair comparison, and holding past it kept a member chosen
// while the fast one did not answer (a failed test, a miss) for the whole cycle, long after the
// fast one answered again. Round robin holds the whole cycle.
type cycleHolder interface {
	// inUseAnswers reports whether every member the strategy uses now has a result of this run
	// that worked, and, for a strategy that holds only until then, none of this cycle (since).
	inUseAnswers(history map[string]*adapter.URLTestHistory, since time.Time) bool
}

// answers is whether a member has a result of this run that worked.
func answers(his *adapter.URLTestHistory) bool {
	return his != nil && monitoring.Worked(his.Delay, his.IsFromCache)
}

// holdsDuringCycle reports whether the strategy keeps its members for now: a cycle runs and the
// members it uses answer.
func holdsDuringCycle(cycleRunning bool, since time.Time, strategy Strategy, history map[string]*adapter.URLTestHistory) bool {
	if !cycleRunning {
		return false
	}
	holder, ok := strategy.(cycleHolder)
	return ok && holder.inUseAnswers(history, since)
}

func (s *LowestDelay) inUseAnswers(history map[string]*adapter.URLTestHistory, since time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, selected := range s.selectedOutbound {
		if selected == nil {
			return false
		}
		his := history[selected.Tag()]
		if !answers(his) || !his.Time.Before(since) {
			return false
		}
	}
	s.logHold(since)
	return true
}

func (s *RoundRobin) inUseAnswers(history map[string]*adapter.URLTestHistory, _ time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for net, outs := range s.sortedOutbounds {
		for i := 0; i <= s.maxAcceptableIndex[net] && i < len(outs); i++ {
			if !answers(history[outs[i].Tag()]) {
				return false
			}
		}
	}
	return true
}
