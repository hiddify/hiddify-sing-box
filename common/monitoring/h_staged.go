package monitoring

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/common/json/badoption"
)

// defaultOnDemandTimeouts: unavailable for now after 1 s, tried again at 1 s and 3 s, final at 10 s.
var defaultOnDemandTimeouts = []time.Duration{time.Second, 3 * time.Second, 10 * time.Second}

// onDemandTimeouts is the option's list, rising and without zeros, or the default.
func onDemandTimeouts(options badoption.Listable[badoption.Duration]) []time.Duration {
	var marks []time.Duration
	for _, d := range options {
		if v := d.Build(); v > 0 && (len(marks) == 0 || v > marks[len(marks)-1]) {
			marks = append(marks, v)
		}
	}
	if len(marks) == 0 {
		return defaultOnDemandTimeouts
	}
	return marks
}

// stagedURLTest is the URL test of a test asked for: a tap on a proxy, a selection. The first
// attempt starts at once. When it fails, or has not answered by the first mark, the outbound
// shows as unavailable for now (tentative, see confirmed); at the first mark a second attempt
// starts beside the first, and so at every mark but the last, which is the deadline of them all. The first answer from any attempt
// wins at once, however late, and the others are dropped; when every attempt has failed and no
// more are due, it is over without waiting for the deadline.
func (m *OutboundMonitoring) stagedURLTest(parent context.Context, link string, out adapter.Outbound, interim func(adapter.URLTestHistory, bool)) (uint16, error) {
	marks := m.onDemand
	ctx, cancel := context.WithTimeout(parent, marks[len(marks)-1])
	defer cancel()
	type result struct {
		delay uint16
		err   error
	}
	results := make(chan result, len(marks))
	attempt := func() {
		go func() {
			delay, err := urltest.URLTest(ctx, link, out)
			results <- result{delay, err}
		}()
	}
	start := time.Now()
	attempt()
	launched, failed := 1, 0
	next := 0 // the mark the next attempt starts at; the last mark starts none
	missed := false
	miss := func() { // unavailable for now: the first attempt failed, or has not answered by the first mark
		if missed || interim == nil {
			return
		}
		missed = true
		interim(adapter.URLTestHistory{Time: time.Now(), Delay: TimeoutDelay}, true)
	}
	var (
		err   error
		timer *time.Timer
	)
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		var due <-chan time.Time
		if next < len(marks)-1 {
			if timer == nil {
				timer = time.NewTimer(time.Until(start.Add(marks[next])))
			}
			due = timer.C
		}
		select {
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
			return TimeoutDelay, err
		case r := <-results:
			if r.err == nil && r.delay > 0 && r.delay < TimeoutDelay {
				return r.delay, nil
			}
			failed++
			if r.err != nil {
				err = r.err
			}
			if failed == launched && next >= len(marks)-1 {
				return TimeoutDelay, err
			}
			miss()
		case <-due:
			timer = nil
			miss()
			attempt()
			launched++
			next++
		}
	}
}
