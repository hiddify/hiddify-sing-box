package monitoring

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// Keep top goes through a large profile in stages (see h_keep_top.go). A pick uses only the best
// found so far and the next few still to test: a stage. When the stage's pings are in, the ones
// that do not answer and the ones too slow for the top go back to rest, and the next few come.
// planKeepTop decides a stage from the pings alone, so a reload in the middle of a pick goes on
// where it was.

// keepTopBatchDefault is how many outbounds a stage tests when keep_top.batch is not set: what
// the monitoring tests at once by default, so a stage of dead proxies takes one test timeout.
const keepTopBatchDefault = defaultWorkerCount

// maxPing is the first delay that is no ping: a real delay is 0 < delay < maxPing, a test that
// failed is timeoutPing.
const (
	maxPing     = 65000
	timeoutPing = int32(TimeoutDelay)
)

func pingAlive(delay int32) bool    { return delay > 0 && delay < maxPing }
func pingTimedOut(delay int32) bool { return delay >= maxPing }

// topPing is what keep top knows of an outbound's ping.
type topPing struct {
	Delay   int32  // the last result: a ping, or timeoutPing; 0 for none
	Time    int64  // when, in unix seconds
	Good    int32  // the last ping that answered, if any did
	Country string // where the proxy is (proxyCountry), when known
	// pick is the pick this result is of; 0 for one of a previous run, or of an outbound that
	// was replaced since: such a result orders the tests and decides nothing.
	pick uint64
	// fails is how many tests in a row failed: a kept outbound rests after keepTopDeadAfter
	fails int
}

// hint is what the ping was the last time, to tell whether the outbound may beat the ones that
// answered now: previousFailed when that test failed, 0 when there is none of the last
// previousMaxAge.
func (p *topPing) hint(now time.Time) int32 {
	switch {
	case p == nil, p.Delay == 0, now.Sub(time.Unix(p.Time, 0)) > previousMaxAge:
		return 0
	case pingTimedOut(p.Delay):
		return previousFailed
	default:
		return p.Delay
	}
}

const (
	// previousFailed is the hint of an outbound whose previous test failed.
	previousFailed = -1
	// previousMaxAge: an outbound not tested for longer is tested again before an early pick.
	previousMaxAge = 24 * time.Hour
)

// testOrder is the order to test tags in, as the cycles do (cycleOrder): the ones that answered
// the last time, fastest first, with the ones never tested taking every other place among them,
// then the ones that failed. Of those, the ones that answered before come first, fastest first:
// after a while without network every proxy has failed, and the ones that worked are still the
// ones to try. Ties keep the config's order.
func testOrder(tags []string, pings map[string]*topPing) []string {
	var answered, untested, failed []string
	for _, tag := range tags {
		switch ping := pings[tag]; {
		case ping == nil || ping.Delay == 0:
			untested = append(untested, tag)
		case pingTimedOut(ping.Delay):
			failed = append(failed, tag)
		default:
			answered = append(answered, tag)
		}
	}
	sort.SliceStable(answered, func(i, j int) bool {
		return pings[answered[i]].Delay < pings[answered[j]].Delay
	})
	sort.SliceStable(failed, func(i, j int) bool {
		a, b := pings[failed[i]].Good, pings[failed[j]].Good
		if (a > 0) != (b > 0) {
			return a > 0
		}
		return a < b
	})
	ordered := make([]string, 0, len(tags))
	for i := range max(len(answered), len(untested)) {
		if i < len(answered) {
			ordered = append(ordered, answered[i])
		}
		if i < len(untested) {
			ordered = append(ordered, untested[i])
		}
	}
	return append(ordered, failed...)
}

// topPlanInput is what a stage is decided from.
type topPlanInput struct {
	tags      []string            // the outbounds keep top manages, in the config's order
	pings     map[string]*topPing // what is known of them
	pick      uint64              // the pick under way: a ping of it needs no other test
	count     int                 // how many to keep
	batch     int                 // how many to test in a stage; 0 or less for all that are left
	countries []string            // keep_top.countries
	quick     bool                // keep_top.quick
	pinned    []string            // the ones a selector has selected: always in use
	loading   []string            // the batch of the stage before: what it still tests stays
	fill      bool                // the pick ends once count answer (h_keep_top_refill.go)
	now       time.Time
}

// topPlan is a stage of a pick, or its end.
type topPlan struct {
	load  []string // the outbounds to use: the best so far, then the batch
	batch []string // the ones of load still to test
	// final: load is the pick, nothing is left to test that could change it.
	final bool
	// exhausted: nothing answered and nothing is left to test; load is empty.
	exhausted bool
	early     bool // final before every outbound was tested (quick)
	best      int  // how many of load answered in this pick
	left      int  // how many are still to test after this stage
}

// planKeepTop decides what to use next in a pick: the count fastest of the outbounds tested in
// it, and the next batch of the others in testOrder. It is final once no other is left, or, with
// quick, once the ones left were slower the last time (pickTopEarly).
func planKeepTop(in topPlanInput) topPlan {
	known := make(map[string]*topPing, len(in.tags))
	var best, left []string
	for _, tag := range in.tags {
		ping := in.pings[tag]
		country := proxyCountry(tag, nil)
		if ping != nil && ping.Country != "" {
			country = ping.Country
		}
		if ping != nil && ping.pick == in.pick && in.pick != 0 {
			if pingAlive(ping.Delay) && !outsideCountries(in.countries, country, true) {
				known[tag] = ping
				best = append(best, tag)
			}
			continue
		}
		if outsideCountries(in.countries, country, false) {
			continue
		}
		if ping != nil {
			known[tag] = ping
		}
		left = append(left, tag)
	}
	sort.SliceStable(best, func(i, j int) bool {
		return known[best[i]].Delay < known[best[j]].Delay
	})
	if in.count > 0 && len(best) > in.count {
		best = best[:in.count]
	}
	var pinned []string
	for _, tag := range in.pinned {
		if slices.Contains(in.tags, tag) && !slices.Contains(pinned, tag) {
			pinned = append(pinned, tag)
		}
	}

	plan := topPlan{best: len(best)}
	switch {
	case len(left) == 0 && len(best) == 0:
		plan.exhausted = true
		return plan
	case len(left) == 0:
		plan.final = true
	case in.fill && len(best) >= in.count && in.count > 0:
		plan.final, plan.early = true, true
	case in.quick && len(best) >= in.count && in.count > 0:
		delays := make(map[string]int32, len(best)+len(left))
		hints := make(map[string]int32, len(left))
		for _, tag := range best {
			delays[tag] = known[tag].Delay
		}
		for _, tag := range left {
			delays[tag], hints[tag] = 0, known[tag].hint(in.now)
		}
		plan.final = pickTopEarly(delays, hints, in.count) != nil
		plan.early = plan.final
	}
	if plan.final {
		plan.load = withPinned(best, pinned)
		return plan
	}

	// what the stage before still tests stays, so its tests go on; then the next in order
	size := in.batch
	if size <= 0 || size > len(left) {
		size = len(left)
	}
	batch := make([]string, 0, size)
	for _, tag := range in.loading {
		if len(batch) < size && slices.Contains(left, tag) && !slices.Contains(batch, tag) {
			batch = append(batch, tag)
		}
	}
	for _, tag := range testOrder(left, known) {
		if len(batch) >= size {
			break
		}
		if !slices.Contains(batch, tag) {
			batch = append(batch, tag)
		}
	}
	plan.batch = batch
	plan.left = len(left) - len(batch)
	plan.load = append(slices.Clone(best), batch...)
	for _, tag := range pinned {
		if !slices.Contains(plan.load, tag) {
			plan.load = append(plan.load, tag)
		}
	}
	return plan
}

// pickTopEarly picks the count fastest of this pick before every outbound answered, once the
// others are not expected to beat them: count of them answered, every one without a previous ping
// of the last previousMaxAge was tested, and the slowest of those count is as fast as the fastest
// previous ping still to be tested. They are tested by previous ping, fastest first, with the
// untested ones between them (testOrder), so with a large subscription this comes after a few
// stages, not all of them. One whose previous test failed does not hold the pick. delays are this
// pick's pings (0 for one still to test), hints the previous ones (topPing.hint); nil until then.
func pickTopEarly(delays, hints map[string]int32, count int) []string {
	if count <= 0 {
		return nil
	}
	var alive []string
	best := int32(maxPing)
	for tag, delay := range delays {
		switch {
		case pingAlive(delay):
			alive = append(alive, tag)
		case pingTimedOut(delay):
		case hints[tag] == 0:
			return nil // never tested: it might be the fastest
		case hints[tag] > 0:
			best = min(best, hints[tag])
		}
	}
	if len(alive) < count {
		return nil
	}
	sort.Slice(alive, func(i, j int) bool {
		if delays[alive[i]] != delays[alive[j]] {
			return delays[alive[i]] < delays[alive[j]]
		}
		return alive[i] < alive[j]
	})
	alive = alive[:count]
	if delays[alive[count-1]] > best {
		return nil
	}
	return alive
}

// withPinned is pick, fastest first, then the pinned outbounds that are not in it: they are used
// beside the fastest, not in place of one. An outbound that exists only while something goes
// through it costs little, and the user who pinned a slow or a dead one still wants the fast
// ones for everything else.
func withPinned(pick []string, pinned []string) []string {
	for _, tag := range pinned {
		if !slices.Contains(pick, tag) {
			pick = append(pick, tag)
		}
	}
	return pick
}

// withoutTimedOut is the kept outbounds of delays but the ones whose last test timed out, when
// there are such and one of the others answers; nil otherwise: all of them timing out starts a
// new pick instead.
func withoutTimedOut(delays map[string]int32) []string {
	var keep []string
	dropped, alive := false, false
	for tag, delay := range delays {
		switch {
		case pingTimedOut(delay):
			dropped = true
			continue
		case pingAlive(delay):
			alive = true
		}
		keep = append(keep, tag)
	}
	if !dropped || !alive {
		return nil
	}
	slices.Sort(keep)
	return keep
}

// keepTopStageWait is how long a stage may take before the outbounds still without a result
// count as not answering: the monitoring tests ten at once, each for five seconds at most, and
// this is several times that, for a monitoring that is busy with something else.
func keepTopStageWait(batch int) time.Duration {
	return 20*time.Second + time.Duration((batch+9)/10)*10*time.Second
}

// keepTopRoundWait is how long to wait before going through the profile again when none of its
// outbounds answered, by how many times in a row that happened: without network a pick finds
// nothing, and testing the whole profile every few seconds until it is back would cost the
// battery.
func keepTopRoundWait(round int) time.Duration {
	if round <= 0 {
		return 0
	}
	return min(30*time.Second<<min(round-1, 4), 5*time.Minute)
}

// normalizeCountries is codes upper-cased, sorted and without repeats or blanks; nil for none.
func normalizeCountries(codes []string) []string {
	var out []string
	for _, code := range codes {
		if code = strings.ToUpper(strings.TrimSpace(code)); len(code) == 2 && !slices.Contains(out, code) {
			out = append(out, code)
		}
	}
	slices.Sort(out)
	return out
}

// proxyCountry is where a proxy is: the country of its IP, as the monitoring looked it up, else
// the flag in its tag; "" when neither tells.
func proxyCountry(tag string, history *adapter.URLTestHistory) string {
	if history != nil && history.IpInfo != nil && len(history.IpInfo.CountryCode) == 2 {
		return strings.ToUpper(history.IpInfo.CountryCode)
	}
	runes := []rune(tag)
	regional := func(r rune) bool { return r >= 0x1F1E6 && r <= 0x1F1FF }
	for i := 0; i+1 < len(runes); i++ {
		if regional(runes[i]) && regional(runes[i+1]) {
			return string([]rune{runes[i] - 0x1F1E6 + 'A', runes[i+1] - 0x1F1E6 + 'A'})
		}
	}
	return ""
}

// outsideCountries reports whether a proxy is left out by keep_top.countries: its country is
// another, or it was tested and where it is is still not known.
func outsideCountries(countries []string, country string, tested bool) bool {
	if len(countries) == 0 {
		return false
	}
	if country == "" {
		return tested
	}
	return !slices.Contains(countries, country)
}
