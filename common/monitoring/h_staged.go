package monitoring

import (
	"context"
	"fmt"
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
// shows as unavailable for now (tentative, see confirmed). An attempt that failed is tried again
// at the next mark, and so at every mark but the last, which is the deadline of them all; an
// attempt still running at a mark is left to answer, so a slow proxy is pinged once, not three
// times. The first answer wins at once, however late; when the last attempt has failed and no
// mark is left to try at, it is over without waiting for the deadline.
//
// The first mark is for an outbound nothing is known of: no result of this run, or only the one
// cached from the previous run, so that the app shows something of it within a second. An
// outbound that worked in this run (worked) keeps its result past the first mark instead of
// showing as unavailable after one slow answer, and its stages start at the second mark.
func (m *OutboundMonitoring) stagedURLTest(parent context.Context, link string, out adapter.Outbound, interim func(adapter.URLTestHistory, bool), worked bool) (uint16, error) {
	marks := m.onDemand
	if worked && len(marks) > 1 {
		marks = marks[1:]
	}
	ctx, cancel := context.WithTimeout(parent, marks[len(marks)-1])
	defer cancel()
	type result struct {
		delay uint16
		err   error
	}
	results := make(chan result, 1)
	attempt := func() {
		go func() {
			delay, err := urltest.URLTest(ctx, link, out)
			results <- result{delay, err}
		}()
	}
	start := time.Now()
	m.logger.Info("MONITORING test ", out.Tag(), ": in stages ", fmt.Sprint(marks), " (worked before: ", worked, ")")
	attempt()
	running := true
	next := 0 // the mark the next attempt may start at; the last mark starts none
	missed := false
	miss := func() { // unavailable for now: the attempt failed, or has not answered by the first mark
		if missed || interim == nil {
			return
		}
		missed = true
		m.logger.Info("MONITORING ", out.Tag(), ": no answer after ", time.Since(start).Round(time.Millisecond), ": unavailable for now")
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
			running = false
			if r.err != nil {
				err = r.err
			}
			if next >= len(marks)-1 { // no mark left to try at
				return TimeoutDelay, err
			}
			miss()
		case <-due:
			timer = nil
			miss()
			if !running { // the attempt failed: another one, at this mark
				m.logger.Info("MONITORING ", out.Tag(), ": the attempt failed, another at ", marks[next])
				attempt()
				running = true
			}
			next++
		}
	}
}
