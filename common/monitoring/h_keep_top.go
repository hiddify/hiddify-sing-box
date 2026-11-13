package monitoring

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// Keep top (experimental.monitoring.keep_top): of the lazy outbounds, the monitoring uses only
// the fastest few, and the one a selector has selected. The others rest (h_parked.go): they are
// not tested, no group sees them, and so they are never created. Nothing in the config changes
// while it picks, so nothing is reloaded and no connection is cut: an outbound that goes to rest
// is closed when its connections end.
//
// It does not test them all to find the fastest: it goes through them a few at a time, a stage
// (h_keep_top_plan.go). A stage uses the best found so far and the next batch still to test, in
// the order the cycles test in: by their last ping, fastest first, the ones never tested between
// them, the ones that failed last. As each ping comes in, the one that does not answer, or is too
// slow for the top, goes back to rest, and the next one takes its place in the batch: a proxy
// that takes its whole timeout holds its own place, not the others'. With quick the pick ends once
// the ones left were slower the last time, else when all were tested. A hot reload keeps the pick
// while the kept outbounds are still there, unchanged, and one of them answers; otherwise, and
// when every kept outbound has timed out, a new pick goes through them again.
//
// Outbounds that are not lazy are not its business: they run and are tested as without it.

// topOrder is what a step of keep top is for, beside going on with the pick.
type topOrder struct {
	restart bool     // a new pick: every kept outbound timed out, or one of them was replaced
	keep    []string // the kept outbounds to go on with; nil for all
	// asIs: the kept outbounds stay whatever their pings say; only the pinned ones join them
	asIs bool
	// fill: the new pick only fills the places that are free, and ends once they are
	fill bool
	// add: outbounds at rest that answered a test just now, to keep beside the kept ones
	add []string
}

// keepTopState is what keep top does: nothing (no options, or nothing to leave out), a pick
// under way, or the outbounds kept.
type keepTopState struct {
	access  sync.Mutex
	options *option.KeepTopOptions // nil: off
	// the lazy outbounds, in the config's order, and the instance each one's ping is of
	tags   []string
	owners map[string]adapter.Outbound
	pings  map[string]*topPing
	// on: there is something to leave out. Then: the count and countries of the last step,
	on        bool
	count     int
	countries []string
	kept      map[string]struct{} // nil until the pick is over
	// guests are the kept ones that the pick did not choose: they are used because they are
	// pinned, or selected, and only as long as they are
	guests  map[string]struct{}
	picking bool                 // a pick is under way: loaded is a stage of it
	pick    uint64               // the pick: a ping of it is not tested again in it
	pickSeq uint64               // the last pick given a number
	round   int                  // how many times in a row all were gone through with no answer
	hold    time.Time            // with round above 0: the next stage waits until then, or an answer
	loaded  []string             // the outbounds in use: the others rest
	batch   []string             // the ones of loaded the stage tests
	batchAt map[string]time.Time // when each of batch came into it
	timer   *time.Timer          // the deadline of a test of the batch, the end of the hold, or recheckAt
	// After the pick, while fewer are kept than may be and others rest (h_keep_top_refill.go):
	fill      bool      // the pick under way only fills the free places
	had       int       // how many of the kept answered when that pick began
	rechecks  int       // how many times in a row the ones at rest were gone through for nothing
	recheckAt time.Time // when they are gone through again
}

// KeepTopSearching reports a first pick still going through the outbounds: the ones in use all
// failing does not mean that none works, while there are others to test.
func (m *OutboundMonitoring) KeepTopSearching() bool {
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	return k.on && k.picking && k.round == 0
}

// KeepTopPicking reports a pick under way, the first or a later one: which outbounds stay in use
// is not settled yet.
func (m *OutboundMonitoring) KeepTopPicking() bool {
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	return k.on && k.picking
}

// SetKeepTop changes the keep top options of a running monitoring (hot reload); nil turns it off.
func (m *OutboundMonitoring) SetKeepTop(options *option.KeepTopOptions) {
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	k.options = options
	m.parkLazy.Store(options != nil)
	if options == nil {
		m.keepTopStopLocked()
		if m.started {
			m.emitAllGroupEvents(m.reg())
		}
		return
	}
	changed := m.keepTopRefreshLocked(m.reg())
	m.keepTopStepLocked(topOrder{restart: changed})
}

// keepTopStart is the first step, before the first cycle, which then tests the first stage.
func (m *OutboundMonitoring) keepTopStart() {
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	if k.options == nil {
		return
	}
	m.keepTopRefreshLocked(m.reg())
	m.keepTopStepLocked(topOrder{})
}

// keepTopReload follows a hot reload of the outbounds: registry is the new one.
func (m *OutboundMonitoring) keepTopReload(registry *monitoringRegistry) {
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	if k.options == nil {
		return
	}
	changed := m.keepTopRefreshLocked(registry)
	m.keepTopStepLocked(topOrder{restart: changed})
}

// keepTopNoted takes the result of a test of tag, and what follows from it.
func (m *OutboundMonitoring) keepTopNoted(tag string) {
	if !m.parkLazy.Load() {
		return
	}
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	if _, managed := k.owners[tag]; !managed || !k.on {
		return
	}
	state := m.getState(tag)
	if state == nil || state.outbound != k.owners[tag] {
		return
	}
	state.mu.Lock()
	history, fromCache := state.history, state.from_cache
	state.mu.Unlock()
	if fromCache || history.Delay == 0 {
		return
	}
	ping := k.pings[tag]
	if ping == nil {
		ping = &topPing{}
		k.pings[tag] = ping
	}
	ping.Delay, ping.Time, ping.pick = int32(history.Delay), history.Time.Unix(), k.pick
	if pingTimedOut(ping.Delay) {
		ping.Delay = timeoutPing
		ping.fails++
		m.keepTopOnceMoreLocked(tag, ping)
	} else {
		ping.Good = ping.Delay
		ping.fails = 0
	}
	if country := proxyCountry(tag, &history); country != "" {
		ping.Country = country
	}
	m.keepTopEvaluateLocked()
}

// keepTopEvaluate looks at what changed without a test: a selection, the stage's deadline.
func (m *OutboundMonitoring) keepTopEvaluate() {
	if !m.parkLazy.Load() || m.ctx.Err() != nil {
		return
	}
	k := &m.keepTop
	k.access.Lock()
	defer k.access.Unlock()
	m.keepTopEvaluateLocked()
}

// keepTopEvaluateLocked moves the pick to its next stage once this one's pings are in, starts a
// new pick once every kept outbound timed out, drops the kept ones that stopped answering (with
// answering), and takes the outbound a selector selected out of rest.
func (m *OutboundMonitoring) keepTopEvaluateLocked() {
	k := &m.keepTop
	if !k.on || (!k.picking && k.kept == nil) {
		return
	}
	defer m.keepTopArmLocked()
	pinned := m.keepTopPinnedLocked()
	var order topOrder
	step := false
	switch {
	case k.picking:
		step = m.keepTopStageOverLocked(time.Now())
	default:
		now := time.Now()
		delays := make(map[string]int32, len(k.kept))
		dead, deadOthers, alive := 0, 0, 0
		for tag := range k.kept {
			if ping := k.pings[tag]; ping != nil && ping.pick != 0 && !ping.failedOnce() {
				delays[tag] = ping.Delay
				if pingTimedOut(ping.Delay) {
					dead++
					// one that is used only because it is, or was, pinned takes no place
					if _, guest := k.guests[tag]; !guest && !slices.Contains(pinned, tag) {
						deadOthers++
					}
				} else if _, guest := k.guests[tag]; !guest && pingAlive(ping.Delay) {
					alive++
				}
			} else {
				delays[tag] = 0
			}
		}
		switch {
		case dead == len(k.kept):
			step, order.restart = true, true
			m.logger.Info("KEEP TOP every kept outbound timed out, looking for others")
		case k.options.Answering:
			// the kept ones that answer, also after the pick; but the pinned: they are used,
			// answering or not
			for _, tag := range pinned {
				delete(delays, tag)
			}
			if keep := withoutTimedOut(delays); keep != nil {
				dropped := len(delays) - len(keep)
				for _, tag := range pinned {
					if _, is := k.kept[tag]; is {
						keep = append(keep, tag)
					}
				}
				step, order.keep = true, keep
				m.logger.Info("KEEP TOP ", dropped, " of the ", len(k.kept), " kept outbounds stopped answering, they rest")
			}
		case deadOthers > 0:
			// one of the fastest few stopped answering: another takes its place
			step, order.restart, order.fill = true, true, true
			k.had = alive
			m.logger.Info("KEEP TOP ", deadOthers, " of the ", len(k.kept), " kept outbounds stopped answering, looking for others in their place")
		}
		if !step && !k.recheckAt.IsZero() && !now.Before(k.recheckAt) {
			if room, resting := m.keepTopRoomLocked(); room > 0 && len(resting) > 0 {
				step, order.restart, order.fill = true, true, true
				k.had = alive
				k.rechecks++
				m.logger.Info("KEEP TOP ", room, " more may be kept: testing the ", len(resting), " at rest again")
			}
		}
		if !step {
			if back := m.keepTopBackLocked(now); len(back) > 0 {
				step, order.add = true, back
				m.logger.Info("KEEP TOP ", len(back), " outbounds at rest answer again, they are used")
			}
		}
	}
	if !step {
		for _, tag := range pinned {
			if !slices.Contains(k.loaded, tag) {
				step, order.asIs = true, true
				break
			}
		}
	}
	if !step && !k.picking {
		// one that was used only because it was pinned, or selected, is so no longer
		for tag := range k.guests {
			if !slices.Contains(pinned, tag) {
				step, order.asIs = true, true
				break
			}
		}
	}
	if step {
		m.keepTopStepLocked(order)
	}
}

// keepTopRefreshLocked reads the lazy outbounds of registry. An outbound that is new, or was
// replaced, has no ping of this run: its last result, cached, only orders the tests. It reports
// whether a kept outbound was replaced or is gone.
func (m *OutboundMonitoring) keepTopRefreshLocked(registry *monitoringRegistry) bool {
	k := &m.keepTop
	if k.owners == nil {
		k.owners = make(map[string]adapter.Outbound)
	}
	if k.pings == nil {
		k.pings = make(map[string]*topPing)
	}
	var tags []string
	changed := false
	for _, outbound := range m.outboundManager.Outbounds() {
		tag := outbound.Tag()
		state := registry.outbounds[tag]
		if _, isLazy := outbound.(adapter.LazyOutbound); !isLazy || state == nil || state.outbound != outbound {
			continue
		}
		tags = append(tags, tag)
		if k.owners[tag] == outbound {
			continue
		}
		if _, was := k.kept[tag]; was {
			changed = true
		}
		k.owners[tag] = outbound
		state.mu.Lock()
		history := state.history
		state.mu.Unlock()
		delete(k.pings, tag)
		if history.Delay != 0 {
			ping := &topPing{Delay: int32(history.Delay), Time: history.Time.Unix(), Good: int32(history.LastGood), Country: proxyCountry(tag, &history)}
			if pingTimedOut(ping.Delay) {
				ping.Delay = timeoutPing
			} else {
				ping.Good = ping.Delay
			}
			k.pings[tag] = ping
		}
	}
	for tag := range k.owners {
		if !slices.Contains(tags, tag) {
			if _, was := k.kept[tag]; was {
				changed = true
			}
			delete(k.owners, tag)
			delete(k.pings, tag)
		}
	}
	k.tags = tags
	return changed
}

// keepTopStopLocked forgets the pick: nothing rests.
func (m *OutboundMonitoring) keepTopStopLocked() {
	k := &m.keepTop
	k.on, k.kept, k.picking, k.round, k.hold, k.loaded, k.batch = false, nil, false, 0, time.Time{}, nil, nil
	k.guests = nil
	k.fill, k.had, k.rechecks, k.recheckAt = false, 0, 0, time.Time{}
	if k.timer != nil {
		k.timer.Stop()
	}
}

// keepTopPinnedLocked are the lazy outbounds a selector has selected, and the ones the options
// pin, sorted: what the user chose is used, whatever its ping, beside the fastest.
func (m *OutboundMonitoring) keepTopPinnedLocked() []string {
	k := &m.keepTop
	var pinned []string
	if k.options != nil {
		for _, tag := range k.options.Pinned {
			if _, managed := k.owners[tag]; managed && !slices.Contains(pinned, tag) {
				pinned = append(pinned, tag)
			}
		}
	}
	for _, outbound := range m.outboundManager.Outbounds() {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			continue
		}
		if _, selects := group.(interface{ SelectOutbound(tag string) bool }); !selects {
			continue // a group that chooses by itself chooses among the ones in use
		}
		selected := group.Selected(N.NetworkTCP)
		if selected == nil {
			continue
		}
		if _, managed := k.owners[selected.Tag()]; managed && !slices.Contains(pinned, selected.Tag()) {
			pinned = append(pinned, selected.Tag())
		}
	}
	slices.Sort(pinned)
	return pinned
}

// keepTopStageOverLocked reports whether the stage can move on: an outbound of its batch has
// its result, or had keepTopStageWait without one and counts as not answering. After a round with
// no answer the next stage also waits for its time, or for an outbound to answer.
func (m *OutboundMonitoring) keepTopStageOverLocked(now time.Time) bool {
	k := &m.keepTop
	tested := func(tag string) *topPing {
		if ping := k.pings[tag]; ping != nil && ping.pick == k.pick {
			return ping
		}
		return nil
	}
	wait := keepTopStageWait(len(k.batch))
	moved, late := len(k.batch) == 0, 0
	for _, tag := range k.batch {
		if tested(tag) != nil {
			moved = true
			continue
		}
		if now.Sub(k.batchAt[tag]) < wait {
			continue
		}
		ping := k.pings[tag]
		if ping == nil {
			ping = &topPing{}
			k.pings[tag] = ping
		}
		ping.Delay, ping.Time, ping.pick = timeoutPing, now.Unix(), k.pick
		moved = true
		late++
	}
	if late > 0 {
		m.logger.Warn("KEEP TOP ", late, " outbounds have no result after ", wait, ": counted as not answering")
	}
	if !moved {
		return false
	}
	if k.round == 0 || !now.Before(k.hold) {
		return true
	}
	for _, tag := range k.loaded {
		if ping := tested(tag); ping != nil && pingAlive(ping.Delay) {
			country := ping.Country
			if country == "" {
				country = proxyCountry(tag, nil)
			}
			if !outsideCountries(k.countries, country, true) {
				return true
			}
		}
	}
	return false
}

// keepTopArmLocked sets the timer for what a stage waits for: the first deadline of the tests of
// its batch, else the end of its hold.
func (m *OutboundMonitoring) keepTopArmLocked() {
	k := &m.keepTop
	var at time.Time
	if k.on && k.picking {
		wait := keepTopStageWait(len(k.batch))
		for _, tag := range k.batch {
			if ping := k.pings[tag]; ping == nil || ping.pick != k.pick {
				if deadline := k.batchAt[tag].Add(wait); at.IsZero() || deadline.Before(at) {
					at = deadline
				}
			}
		}
		if at.IsZero() && k.round > 0 {
			at = k.hold
		}
	}
	at = m.keepTopRecheckLocked(at)
	if at.IsZero() {
		if k.timer != nil {
			k.timer.Stop()
		}
		return
	}
	wait := max(time.Until(at), 10*time.Millisecond)
	if k.timer == nil {
		k.timer = time.AfterFunc(wait, m.keepTopEvaluate)
	} else {
		k.timer.Reset(wait)
	}
}

// keptStillGood reports whether none of the kept outbounds timed out and one of them answers,
// by their pings of this run. A kept outbound that died is replaced by a new pick, which keeps
// the ones that answer while it finds the others.
func keptStillGood(kept map[string]struct{}, pings map[string]*topPing) bool {
	alive := false
	for tag := range kept {
		ping := pings[tag]
		if ping == nil || ping.pick == 0 {
			continue
		}
		if pingTimedOut(ping.Delay) {
			return false
		}
		if pingAlive(ping.Delay) {
			alive = true
		}
	}
	return alive
}

// trimKept is the count fastest of the kept outbounds by the pings they already have, and the
// pinned ones beside them.
func trimKept(kept map[string]struct{}, count int, pinned []string, pings map[string]*topPing) map[string]struct{} {
	tags := make([]string, 0, len(kept))
	delays := make(map[string]int32, len(kept))
	for tag := range kept {
		if slices.Contains(pinned, tag) {
			continue
		}
		tags = append(tags, tag)
		if ping := pings[tag]; ping != nil && ping.pick != 0 {
			delays[tag] = ping.Delay
		}
	}
	// the ones that answer first, the fastest of them first
	sort.Slice(tags, func(i, j int) bool {
		a, b := delays[tags[i]], delays[tags[j]]
		if pingAlive(a) != pingAlive(b) {
			return pingAlive(a)
		}
		if a != b {
			return a < b
		}
		return tags[i] < tags[j]
	})
	var inKept []string
	for _, tag := range pinned {
		if _, is := kept[tag]; is {
			inKept = append(inKept, tag)
		}
	}
	if len(tags) > count {
		tags = tags[:count]
	}
	trimmed := make(map[string]struct{}, count)
	for _, tag := range withPinned(tags, inKept) {
		trimmed[tag] = struct{}{}
	}
	return trimmed
}

// keepTopStepLocked decides which of the lazy outbounds are used from here on, and puts the
// others to rest: the kept ones while they are good, else the next stage of the pick under way,
// or the first of a new one.
func (m *OutboundMonitoring) keepTopStepLocked(order topOrder) {
	k := &m.keepTop
	defer m.keepTopArmLocked()
	options := k.options
	tags := k.tags
	total := len(tags)
	count := options.Count
	countries := normalizeCountries(options.Countries)
	// every outbound may be kept: the pick drops only the ones that do not answer, or of another
	// country
	if options.Answering || count <= 0 {
		count = total
	}
	if total == 0 || (total <= count && !options.Answering && len(countries) == 0) {
		// nothing to leave out
		was := k.on
		m.keepTopStopLocked()
		m.setActive(tags)
		if was {
			m.logger.Info("KEEP TOP using all ", total, " lazy outbounds")
		}
		return
	}
	now := time.Now()
	// warm: there is a pick, or its result, to go on from
	warm := k.on && (k.picking || k.kept != nil)
	pinned := m.keepTopPinnedLocked()
	current := struct {
		count     int
		countries []string
		kept      map[string]struct{}
		picking   bool
		pick      uint64
		round     int
		hold      time.Time
		loaded    []string
		batch     []string
	}{k.count, k.countries, k.kept, k.picking, k.pick, k.round, k.hold, k.loaded, k.batch}
	k.on, k.count, k.countries = true, count, countries
	k.kept, k.picking, k.round, k.hold, k.batch = nil, false, 0, time.Time{}, nil
	fill := k.fill
	k.fill = false
	apply := func(loaded []string, what string) {
		batchAt := make(map[string]time.Time, len(k.batch))
		for _, tag := range k.batch {
			if at, was := k.batchAt[tag]; was && warm && k.pick == current.pick {
				batchAt[tag] = at
			} else {
				batchAt[tag] = now
			}
		}
		k.batchAt = batchAt
		changed := !warm || !slices.Equal(loaded, current.loaded)
		k.loaded = loaded
		woken := m.setActive(loaded)
		// the ones of the batch that were in use already did not come out of rest, which is
		// what tests the others
		if m.started {
			cycleID := max(m.cycleSeq.Load(), 1)
			for _, tag := range k.batch {
				asked := warm && k.pick == current.pick && slices.Contains(current.batch, tag) // by the step that put it in the batch
				if ping := k.pings[tag]; !asked && !slices.Contains(woken, tag) && (ping == nil || ping.pick != k.pick) {
					m.enqueueTask(&testTask{outboundTag: tag, cycleID: cycleID, reason: "keep top goes through it"})
				}
			}
		}
		switch {
		case !changed:
		case k.picking && warm && current.picking && k.pick == current.pick:
			m.logger.Debug("KEEP TOP ", what) // one of many steps of a pick
		default:
			m.logger.Info("KEEP TOP ", what)
		}
		// the pings so far order the next run's tests, also when this run ends without a close
		// (the iOS extension is killed, not stopped)
		if m.started && m.cacheDirty.Swap(false) {
			_ = m.saveHistory()
		}
	}

	// the same outbounds stay while they are good; fewer of them, the fastest of those, with no
	// new pings; more of them, a new pick finds the others
	kept := current.kept
	if order.keep != nil && kept != nil {
		kept = make(map[string]struct{}, len(order.keep))
		for _, tag := range order.keep {
			if _, is := current.kept[tag]; is {
				kept[tag] = struct{}{}
			}
		}
	}
	if warm && !order.restart && len(kept) > 0 && count <= current.count && slices.Equal(current.countries, countries) {
		kept = cloneSet(kept)
		guests := make(map[string]struct{})
		for tag := range k.guests {
			if _, is := kept[tag]; !is {
				continue
			}
			if slices.Contains(pinned, tag) {
				guests[tag] = struct{}{}
			} else {
				delete(kept, tag) // no longer pinned, and the pick did not choose it: back to rest
			}
		}
		for _, tag := range pinned {
			if _, is := kept[tag]; !is {
				// selected, or pinned, while it rested: it is used, beside the fastest
				kept[tag] = struct{}{}
				guests[tag] = struct{}{}
			}
		}
		for _, tag := range order.add {
			if _, managed := k.owners[tag]; managed {
				kept[tag] = struct{}{}
				delete(guests, tag)
			}
		}
		// no more than count beside the pinned: fewer are asked for, or one is no longer pinned
		others := make(map[string]struct{}, len(kept))
		for tag := range kept {
			if !slices.Contains(pinned, tag) {
				others[tag] = struct{}{}
			}
		}
		if len(others) > count {
			kept = trimKept(kept, count, pinned, k.pings)
			for tag := range others {
				if _, is := kept[tag]; !is {
					delete(others, tag)
				}
			}
		}
		// a pinned one is used whatever its ping: it is the others that must be good
		if order.asIs || keptStillGood(others, k.pings) {
			k.kept, k.pick, k.guests = kept, current.pick, guests
			if len(order.add) > 0 {
				k.rechecks = 0
			}
			loaded := make([]string, 0, len(kept))
			for tag := range kept {
				loaded = append(loaded, tag)
			}
			slices.Sort(loaded)
			apply(loaded, fmt.Sprint("using ", len(loaded), " of the ", total, " lazy outbounds"))
			return
		}
	}

	var loading []string
	if warm && !order.restart && current.picking && current.count == count && slices.Equal(current.countries, countries) {
		// the pick under way goes on
		k.pick, k.round, k.hold, loading = current.pick, current.round, current.hold, current.batch
		k.fill = fill
	} else {
		k.fill = order.fill
		if !order.fill {
			k.had = 0
		}
		k.pickSeq++
		k.pick = k.pickSeq
		if warm {
			// the outbounds in use that answer need no other test, and stay while the pick
			// finds the others; nor do the ones in use tested just now, whatever the answer:
			// it is their failing that starts a new pick. Nor one whose test has given its
			// result and is still ending: a new test of it would join that one, and bring
			// nothing
			for _, tag := range tags {
				ping := k.pings[tag]
				if ping == nil || current.pick == 0 || ping.pick != current.pick {
					continue
				}
				inUse := slices.Contains(current.loaded, tag)
				switch {
				case inUse && (pingAlive(ping.Delay) || now.Sub(time.Unix(ping.Time, 0)) < recentResult):
					ping.pick = k.pick
				case m.keepTopTestEnding(tag):
					ping.pick = k.pick
				}
			}
		}
	}
	input := topPlanInput{
		tags: tags, pings: k.pings, pick: k.pick, count: count, batch: options.Batch, countries: countries,
		quick: options.Quick, pinned: pinned, loading: loading, now: now, fill: k.fill,
	}
	if input.batch == 0 {
		input.batch = keepTopBatchDefault
	}
	plan := planKeepTop(input)
	again := ""
	if plan.exhausted {
		// none answered: through them again, from the ones that worked before, and not faster
		// than keepTopRoundWait
		k.pickSeq++
		k.pick = k.pickSeq
		k.round++
		k.hold = now.Add(keepTopRoundWait(k.round))
		k.fill = false
		input.pick, input.loading, input.fill = k.pick, nil, false
		plan = planKeepTop(input)
		again = "none of them answered, going through them again: "
	}
	if plan.best > 0 {
		k.round, k.hold = 0, time.Time{}
	}
	k.batch = plan.batch
	where := ""
	if len(countries) > 0 {
		where = " in " + strings.Join(countries, " ")
	}
	switch {
	case plan.exhausted:
		// none may be kept: all of other countries. The groups need outbounds to use: the ones
		// they have, else the first to test.
		k.picking = true
		var loaded []string
		if warm {
			for _, tag := range current.loaded {
				if slices.Contains(tags, tag) {
					loaded = append(loaded, tag)
				}
			}
		}
		if len(loaded) == 0 {
			loaded = testOrder(tags, k.pings)
			if len(loaded) > input.batch && input.batch > 0 {
				loaded = loaded[:input.batch]
			}
		}
		for _, tag := range pinned {
			if !slices.Contains(loaded, tag) {
				loaded = append(loaded, tag)
			}
		}
		apply(loaded, fmt.Sprint("none of the ", total, " lazy outbounds can be kept", where, ", using ", len(loaded), " of them"))
	case plan.final:
		k.kept = make(map[string]struct{}, len(plan.load))
		for _, tag := range plan.load {
			k.kept[tag] = struct{}{}
		}
		k.guests = make(map[string]struct{})
		for _, tag := range plan.load[min(plan.best, len(plan.load)):] { // the pinned, after the best
			k.guests[tag] = struct{}{}
		}
		how := "keeping "
		switch {
		case plan.early && k.fill:
			how = "the free places are filled: keeping "
		case plan.early:
			how = "the rest were slower by their last pings: keeping "
		}
		if plan.best > k.had {
			k.rechecks = 0 // it found some: the next look at the ones at rest is the first again
		}
		k.fill = false
		apply(plan.load, fmt.Sprint(how, len(plan.load), " of the ", total, " lazy outbounds", where, ", the others rest"))
	default:
		k.picking = true
		apply(plan.load, fmt.Sprint(again, "testing ", len(plan.batch), " of the ", total, " lazy outbounds beside the ", plan.best, " best so far", where, ", ", plan.left, " more to come"))
	}
}

// keepTopTestEnding reports a test of tag that is still marked as running: when keep top has its
// result already, the test is in its last steps.
func (m *OutboundMonitoring) keepTopTestEnding(tag string) bool {
	state := m.getState(tag)
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.testing
}

func cloneSet(set map[string]struct{}) map[string]struct{} {
	clone := make(map[string]struct{}, len(set)+1)
	for tag := range set {
		clone[tag] = struct{}{}
	}
	return clone
}
