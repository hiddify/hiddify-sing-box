package monitoring

import (
	"errors"
)

// joinRunningTest is what a test asked for while another test of the same outbound runs: it waits
// for that one and takes its result as its own, instead of a second URL test beside it. Two tests
// at once pinged the proxy twice, and the one that ended last wrote the result, so a late failure
// replaced a fresh answer and the groups left the member; a tap on the proxy, or its selection
// during the cycle's test of it, did that.
func (m *OutboundMonitoring) joinRunningTest(task *testTask, state *outboundState) {
	state.mu.Lock()
	done := state.testDone
	state.mu.Unlock()
	m.logger.Info("MONITORING test ", task.outboundTag, ": ", task.reason, ": a test of it runs, taking its result")
	select {
	case <-m.ctx.Done():
		return
	case <-done:
	}
	state.mu.Lock()
	if task.priority {
		state.priorityQueued = false
	} else {
		state.queued = false
		state.enqueuedCycle = 0
	}
	history := state.history
	state.mu.Unlock()
	var err error
	if history.Error != "" || history.Delay >= TimeoutDelay {
		err = errors.New(history.Error)
	}
	m.handResult(task, testOutcome{outboundTag: task.outboundTag, history: history, err: err, cycleID: task.cycleID, priority: task.priority})
}
