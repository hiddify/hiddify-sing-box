package transport

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

// defaultSequentialMemberFloor is the least a server is waited for when the query's time is
// shared among the servers still to ask.
const defaultSequentialMemberFloor = 2 * time.Second

// groupSequential keeps what the sequential mode learnt: a server that failed is asked after the
// others for error_ttl, so a dead first server does not open every query, and each server gets
// a bounded share of the query's time, so one that hangs cannot spend the whole of it: before,
// a TCP server whose port was black-holed took the full DNS timeout and the query failed without
// the servers behind it ever being asked.
type groupSequential struct {
	errorTTL      time.Duration
	memberTimeout time.Duration

	access      sync.Mutex
	failedUntil map[string]time.Time
}

func newGroupSequential(options option.GroupDNSServerOptions) *groupSequential {
	sequential := &groupSequential{
		errorTTL:      time.Duration(options.ErrorTTL),
		memberTimeout: time.Duration(options.MemberTimeout),
		failedUntil:   make(map[string]time.Time),
	}
	if sequential.errorTTL <= 0 {
		sequential.errorTTL = defaultGroupErrorTTL
	}
	return sequential
}

func (s *groupSequential) reset() {
	s.access.Lock()
	defer s.access.Unlock()
	clear(s.failedUntil)
}

// order is the servers to ask, in order: the ones that did not fail recently first, as listed,
// then the ones that did, as listed, so every server is still asked when the healthy ones fail.
func (s *groupSequential) order(tags []string) []string {
	s.access.Lock()
	defer s.access.Unlock()
	now := time.Now()
	ordered := make([]string, 0, len(tags))
	var failed []string
	for _, tag := range tags {
		if now.Before(s.failedUntil[tag]) {
			failed = append(failed, tag)
		} else {
			ordered = append(ordered, tag)
		}
	}
	return append(ordered, failed...)
}

func (s *groupSequential) record(tag string, outcome groupOutcome) {
	s.access.Lock()
	defer s.access.Unlock()
	switch outcome {
	case groupAccepted:
		delete(s.failedUntil, tag)
	case groupFailed:
		s.failedUntil[tag] = time.Now().Add(s.errorTTL)
	}
}

// budget is how long the next server is waited for, with left servers still to ask: member_timeout
// when set, else the time left shared among them, at least the floor; never past the deadline.
func (s *groupSequential) budget(ctx context.Context, left int) time.Duration {
	remaining := C.DNSTimeout
	if deadline, loaded := ctx.Deadline(); loaded {
		remaining = time.Until(deadline)
	}
	budget := s.memberTimeout
	if budget <= 0 {
		budget = max(remaining/time.Duration(max(left, 1)), defaultSequentialMemberFloor)
	}
	return min(budget, remaining)
}

func (t *GroupTransport) exchangeSequential(ctx context.Context, transportManager adapter.DNSTransportManager, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	collector := groupCollector{transport: t}
	order := t.sequential.order(t.serverTags)
	for i, tag := range order {
		memberContext, cancel := context.WithTimeout(ctx, t.sequential.budget(ctx, len(order)-i))
		result := t.exchangeOne(memberContext, transportManager, tag, message)
		cancel()
		if result.err != nil && ctx.Err() != nil {
			t.finishCanceled(ctx, &collector, callback)
			return
		}
		if result.err != nil && memberContext.Err() != nil {
			result.err = E.Cause(result.err, "waiting for ", tag)
		}
		response, outcome := collector.classify(ctx, result, false)
		t.sequential.record(tag, outcome)
		if outcome == groupAccepted {
			callback(response, nil)
			return
		}
	}
	callback(collector.finish())
}
