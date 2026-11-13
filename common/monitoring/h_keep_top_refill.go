package monitoring

import (
	"slices"
	"sort"
	"time"
)

// After a pick, keep top fills the places that come free, without testing the outbounds at rest
// all the time:
//
//   - A kept outbound stops answering when keepTopDeadAfter tests in a row failed: after the first
//     it is tested once more, keepTopRetestAfter later.
//   - With a count, a kept outbound that stops answering starts a pick that only fills its place:
//     it keeps the ones that answer, tests the ones at rest in the order of their last pings, and
//     ends as soon as count answer. With answering, the one that stopped only goes to rest.
//   - While fewer are kept than may be (count, or with answering all of them) and others rest,
//     the ones at rest are tested again keepTopRecheckWait after the last time: 10 minutes, then
//     30, then 1, 2, 4 and every 6 hours while none of them answers, and from 10 minutes again
//     once one does.
//   - An outbound at rest that answers a test asked for by its tag (the user tests the list) is
//     used at once, while there is a place for it.

// keepTopRecheckWait is how long after going through the outbounds at rest they are gone through
// again, by how many times in a row that brought none back.
var keepTopRecheckWait = func(rechecks int) time.Duration { // a variable for the tests
	waits := []time.Duration{10 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour}
	return waits[min(max(rechecks, 0), len(waits)-1)]
}

// keepTopDeadAfter is how many tests in a row a kept outbound must fail before it counts as not
// answering: one failed test is often a lost packet, and its place would go to a slower one.
const keepTopDeadAfter = 2

// keepTopRetestAfter is how long after a kept outbound's first failed test it is tested once
// more, not to wait for the next cycle.
var keepTopRetestAfter = 5 * time.Second // a variable for the tests

// failedOnce reports a failed test that does not count yet: fewer than keepTopDeadAfter in a row.
func (p *topPing) failedOnce() bool {
	return pingTimedOut(p.Delay) && p.fails > 0 && p.fails < keepTopDeadAfter
}

// keepTopOnceMoreLocked asks for one more test of a kept outbound whose test failed, when that
// failure does not count yet.
func (m *OutboundMonitoring) keepTopOnceMoreLocked(tag string, ping *topPing) {
	k := &m.keepTop
	if _, kept := k.kept[tag]; !kept || k.picking || !ping.failedOnce() {
		return
	}
	time.AfterFunc(keepTopRetestAfter, func() {
		if m.ctx.Err() == nil {
			m.TestOutbounds([]string{tag}, "keep top: once more before it rests")
		}
	})
}

// keepTopRoomLocked is how many more outbounds may be kept beside the ones that are, and the
// ones at rest that may take those places: not the ones of another country.
func (m *OutboundMonitoring) keepTopRoomLocked() (room int, resting []string) {
	k := &m.keepTop
	if !k.on || k.picking || k.kept == nil {
		return 0, nil
	}
	room = k.count
	for tag := range k.kept {
		if _, guest := k.guests[tag]; !guest {
			room--
		}
	}
	if room <= 0 {
		return 0, nil
	}
	for _, tag := range k.tags {
		if _, is := k.kept[tag]; is {
			continue
		}
		if !outsideCountries(k.countries, k.countryLocked(tag), false) {
			resting = append(resting, tag)
		}
	}
	return room, resting
}

func (k *keepTopState) countryLocked(tag string) string {
	if ping := k.pings[tag]; ping != nil && ping.Country != "" {
		return ping.Country
	}
	return proxyCountry(tag, nil)
}

// keepTopBackLocked are the outbounds at rest that answered a test in the last recentResult, the
// fastest first, as many as there are places for.
func (m *OutboundMonitoring) keepTopBackLocked(now time.Time) []string {
	k := &m.keepTop
	room, resting := m.keepTopRoomLocked()
	var back []string
	for _, tag := range resting {
		ping := k.pings[tag]
		if ping == nil || ping.pick != k.pick || !pingAlive(ping.Delay) || now.Sub(time.Unix(ping.Time, 0)) >= recentResult {
			continue
		}
		if !outsideCountries(k.countries, k.countryLocked(tag), true) {
			back = append(back, tag)
		}
	}
	sort.SliceStable(back, func(i, j int) bool {
		return k.pings[back[i]].Delay < k.pings[back[j]].Delay
	})
	return slices.Clip(back[:min(room, len(back))])
}

// keepTopRecheckLocked sets when the outbounds at rest are tested again, or that they are not,
// and returns what the timer waits for: at when it is set, else that time.
func (m *OutboundMonitoring) keepTopRecheckLocked(at time.Time) time.Time {
	k := &m.keepTop
	room, resting := m.keepTopRoomLocked()
	if room <= 0 || len(resting) == 0 {
		k.recheckAt = time.Time{}
		return at
	}
	if k.recheckAt.IsZero() {
		k.recheckAt = time.Now().Add(keepTopRecheckWait(k.rechecks))
	}
	if at.IsZero() {
		return k.recheckAt
	}
	return at
}
