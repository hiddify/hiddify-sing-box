package monitoring

import (
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

var errTestNeverReturned = errors.New("URL test did not return: the outbound ignores its deadline")

// workedLocked reports a result of this run that worked; s.mu is held.
func (s *outboundState) workedLocked() bool {
	return Worked(s.history.Delay, s.from_cache)
}

// handResult gives a task's outcome to what waits for it (a cycle's stage), without blocking.
func (m *OutboundMonitoring) handResult(task *testTask, outcome testOutcome) {
	if task.resultCh == nil {
		return
	}
	select {
	case task.resultCh <- outcome:
	default:
	}
}

// testHardLimit is how long a worker waits for one test: the URL test and the IP lookup, each
// with its own deadline, and one more test after a network reset. An outbound whose dial ignores
// its deadline would otherwise hold the worker, and the cycle waiting for the result, for good;
// a few of them, and nothing is tested again.
func (m *OutboundMonitoring) testHardLimit(task *testTask) time.Duration {
	test := m.urlTestTimeout
	if task.staged {
		test = m.onDemand[len(m.onDemand)-1]
	}
	factor := time.Duration(1)
	if state, ok := m.reg().outbounds[task.outboundTag]; ok {
		factor = m.timeoutFactor(state.outbound)
	}
	return factor * (2*test + m.urlTestTimeout + 2*networkResetWait)
}

// settle records a test's result, once: the first of its result and of giving up on it counts,
// the other is dropped. It applies the result, hands it to what waits for it, publishes it at
// once when the test was asked for, and tests again what was measured through the outbound
// while it did not work.
//
// worked says whether the outbound had a result of this run that worked, before this test.
func (m *OutboundMonitoring) settle(task *testTask, state *outboundState, history adapter.URLTestHistory, err error, worked bool) {
	if !task.settled.CompareAndSwap(false, true) {
		m.logger.Debug("outbound ", task.outboundTag, " URL test returned after it was given up on; dropped")
		return
	}
	outcome := testOutcome{
		outboundTag: task.outboundTag,
		history:     history,
		err:         err,
		cycleID:     task.cycleID,
		priority:    task.priority,
	}
	m.applyResult(outcome)
	if task.priority { // asked for, so wanted now: past the debounce, as a selection is
		m.flushSelectionEvents(task.outboundTag)
	}
	if err == nil && !worked { // it works now; what was measured through it did not
		m.retestDependents(task.outboundTag, make(map[string]bool))
	}
	m.handResult(task, outcome)
}

// settleLate gives up on a test that did not return within testHardLimit: it counts as failed,
// the worker moves on, and the test's own result, if it ever comes, is dropped.
func (m *OutboundMonitoring) settleLate(task *testTask, state *outboundState) {
	m.logger.Warn("outbound ", task.outboundTag, " URL test did not return in ", m.testHardLimit(task), ": counted as failed")
	state.mu.Lock()
	worked := state.workedLocked()
	state.mu.Unlock()
	m.settle(task, state, adapter.URLTestHistory{Time: time.Now(), Delay: TimeoutDelay}, errTestNeverReturned, worked)
}

// applyInterim records what a test knows before it is done: the delay the URL test measured,
// before the IP lookup that follows it (the ping shows at once, the IP comes when the lookup is
// done), or a staged test's miss at its first mark, tentative: the app shows the outbound as
// unavailable for now, while the groups keep its last confirmed result (see confirmed). The
// result is stored and the groups told, at once for a test that was asked for; the queue marks
// stay for settle.
func (m *OutboundMonitoring) applyInterim(task *testTask, state *outboundState, history adapter.URLTestHistory, tentative bool) {
	if task.settled.Load() {
		return
	}
	state.mu.Lock()
	if !tentative && state.history.Delay != history.Delay {
		m.cacheDirty.Store(true)
	}
	if !state.tentative {
		state.confirmed = state.history
		state.confirmed.IsFromCache = state.from_cache
	}
	state.history.Delay = history.Delay
	state.history.Time = history.Time
	if !tentative { // the URL test answered: the error of an earlier test is gone with it
		state.history.Error = ""
	}
	state.from_cache = false
	state.tentative = tentative
	if !tentative {
		m.history.StoreURLTestHistory(task.outboundTag, &state.history)
	}
	groupTags := state.groupTags
	state.mu.Unlock()
	m.emitGroupEvent(groupTags)
	if task.priority {
		m.flushSelectionEvents(task.outboundTag)
	}
}

// confirmed is what a group reads of a member: a staged test's tentative miss is swapped for
// the member's last confirmed result, so no group takes it for dead, or moves away from it and
// cuts its connections, on a miss that its next attempt may answer. The catch-all group, which
// the app reads, sees the miss as it is. A member with no result of this run (none, or only the
// one cached from the previous run) has nothing to keep: the miss is all this run knows of it,
// and the groups see it, so lowest-delay leaves a cached pick that does not answer for one that
// does. It used to keep the cached result, marked as fresh, and stay on a member the app showed
// as not responding while others worked.
func (m *OutboundMonitoring) confirmed(groupTag, outboundTag string, his *adapter.URLTestHistory) *adapter.URLTestHistory {
	if groupTag == "" || his == nil {
		return his
	}
	state, ok := m.reg().outbounds[outboundTag]
	if !ok {
		return his
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.tentative {
		return his
	}
	if !Worked(state.confirmed.Delay, state.confirmed.IsFromCache) {
		return his
	}
	last := state.confirmed
	last.IsFromCache = false
	return &last
}

// testError is the error a URL test failed with, as the history keeps it for the app; empty when
// the test worked.
func testError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
