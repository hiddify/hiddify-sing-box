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

const (
	defaultGroupErrorTTL = time.Minute
	defaultGroupWinTTL   = 10 * time.Minute
)

// groupModes keeps the record the stable and fastest modes choose by. A server
// that fails is skipped for error_ttl. The current server is asked first, with
// half of the time left; when it fails, the healthy servers not yet asked race
// and the winner becomes the current server. In stable mode the current server
// stays until it fails; in fastest mode it stays for win_ttl, and the next query
// races all healthy servers again to find the fastest.
type groupModes struct {
	fastest  bool
	errorTTL time.Duration
	winTTL   time.Duration

	access       sync.Mutex
	failedUntil  map[string]time.Time
	current      string
	currentUntil time.Time // fastest mode only
}

func newGroupModes(options option.GroupDNSServerOptions) *groupModes {
	modes := &groupModes{
		fastest:     options.Mode == C.DNSGroupModeFastest,
		errorTTL:    time.Duration(options.ErrorTTL),
		winTTL:      time.Duration(options.WinTTL),
		failedUntil: make(map[string]time.Time),
	}
	if modes.errorTTL <= 0 {
		modes.errorTTL = defaultGroupErrorTTL
	}
	if modes.winTTL <= 0 {
		modes.winTTL = defaultGroupWinTTL
	}
	return modes
}

func (m *groupModes) reset() {
	m.access.Lock()
	defer m.access.Unlock()
	clear(m.failedUntil)
	m.current = ""
	m.currentUntil = time.Time{}
}

// preferred returns the server to ask alone first, or "" to race at once.
func (m *groupModes) preferred(tags []string) string {
	m.access.Lock()
	defer m.access.Unlock()
	now := time.Now()
	if m.current != "" && now.Before(m.failedUntil[m.current]) {
		m.current = ""
	}
	if m.fastest {
		if m.current != "" && now.Before(m.currentUntil) {
			return m.current
		}
		return ""
	}
	if m.current != "" {
		return m.current
	}
	for _, tag := range tags {
		if !now.Before(m.failedUntil[tag]) {
			return tag
		}
	}
	return ""
}

// candidates returns the servers to race: the healthy ones not asked yet, or,
// when every one of them failed recently, all of them not asked yet.
func (m *groupModes) candidates(tags []string, asked string) []string {
	m.access.Lock()
	defer m.access.Unlock()
	now := time.Now()
	var healthy, rest []string
	for _, tag := range tags {
		if tag == asked {
			continue
		}
		if now.Before(m.failedUntil[tag]) {
			rest = append(rest, tag)
		} else {
			healthy = append(healthy, tag)
		}
	}
	if len(healthy) > 0 {
		return healthy
	}
	return rest
}

func (m *groupModes) record(tag string, outcome groupOutcome, elected bool) {
	m.access.Lock()
	defer m.access.Unlock()
	switch outcome {
	case groupAccepted:
		delete(m.failedUntil, tag)
		if elected {
			m.current = tag
			m.currentUntil = time.Now().Add(m.winTTL)
		}
	case groupFailed:
		m.failedUntil[tag] = time.Now().Add(m.errorTTL)
		if m.current == tag {
			m.current = ""
		}
	}
}

func (t *GroupTransport) exchangeModes(ctx context.Context, transportManager adapter.DNSTransportManager, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	collector := groupCollector{transport: t}
	preferred := t.modes.preferred(t.serverTags)
	if preferred != "" {
		if response, accepted := t.exchangeFirst(ctx, transportManager, &collector, preferred, message); accepted {
			callback(response, nil)
			return
		}
	}
	if ctx.Err() != nil {
		t.finishCanceled(ctx, &collector, callback)
		return
	}
	candidates := t.modes.candidates(t.serverTags, preferred)
	if len(candidates) == 0 {
		callback(collector.finish())
		return
	}
	response, accepted := t.race(ctx, transportManager, &collector, candidates, message)
	if accepted {
		callback(response, nil)
		return
	}
	if ctx.Err() != nil {
		t.finishCanceled(ctx, &collector, callback)
		return
	}
	callback(collector.finish())
}

func (t *GroupTransport) finishCanceled(ctx context.Context, collector *groupCollector, callback func(response *mDNS.Msg, err error)) {
	if collector.fallback != nil {
		callback(collector.fallback, nil)
	} else {
		callback(nil, ctx.Err())
	}
}

// exchangeFirst asks one server with half of the time left, so the others
// still have time to answer when it does not.
func (t *GroupTransport) exchangeFirst(ctx context.Context, transportManager adapter.DNSTransportManager, collector *groupCollector, tag string, message *mDNS.Msg) (*mDNS.Msg, bool) {
	budget := C.DNSTimeout
	if deadline, loaded := ctx.Deadline(); loaded {
		budget = time.Until(deadline)
	}
	firstContext, cancel := context.WithTimeout(ctx, budget/2)
	defer cancel()
	result := t.exchangeOne(firstContext, transportManager, tag, message)
	if result.err != nil && ctx.Err() != nil {
		return nil, false
	}
	if result.err != nil && firstContext.Err() != nil {
		result.err = E.Cause(result.err, "first try of ", tag)
	}
	response, outcome := collector.classify(ctx, result, false)
	t.modes.record(tag, outcome, !t.modes.fastest) // a stable group keeps the server it reached
	return response, outcome == groupAccepted
}

func (t *GroupTransport) exchangeOne(ctx context.Context, transportManager adapter.DNSTransportManager, tag string, message *mDNS.Msg) groupResult {
	transport, loaded := transportManager.Transport(tag)
	if !loaded {
		return groupResult{nil, tag, E.New("DNS server not found: ", tag)}
	}
	resultCh := make(chan groupResult, 1)
	transport.ExchangeAsync(adapter.OverrideContext(ctx), message.Copy(), func(response *mDNS.Msg, err error) {
		resultCh <- groupResult{response, tag, err}
	})
	select {
	case result := <-resultCh:
		return result
	case <-ctx.Done():
		return groupResult{nil, tag, ctx.Err()}
	}
}

// race asks the servers at once; the first accepted answer wins and makes its
// server the current one.
func (t *GroupTransport) race(ctx context.Context, transportManager adapter.DNSTransportManager, collector *groupCollector, tags []string, message *mDNS.Msg) (*mDNS.Msg, bool) {
	raceContext, cancel := context.WithCancel(ctx)
	defer cancel()
	resultCh := make(chan groupResult, len(tags))
	for _, tag := range tags {
		go func() {
			resultCh <- t.exchangeOne(raceContext, transportManager, tag, message)
		}()
	}
	for range tags {
		var result groupResult
		select {
		case <-ctx.Done():
			return nil, false
		case result = <-resultCh:
		}
		if result.err != nil && ctx.Err() != nil {
			return nil, false
		}
		response, outcome := collector.classify(ctx, result, true)
		t.modes.record(result.tag, outcome, true)
		if outcome == groupAccepted {
			return response, true
		}
	}
	return nil, false
}
