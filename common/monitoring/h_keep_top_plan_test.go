package monitoring

import (
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestH_KeepTopTestOrder(t *testing.T) {
	pings := map[string]*topPing{
		"a15": {Delay: 15}, "a10": {Delay: 10}, "a12": {Delay: 12},
		"failed": {Delay: timeoutPing}, "worked40": {Delay: timeoutPing, Good: 40}, "worked20": {Delay: timeoutPing, Good: 20},
	}
	tags := []string{"failed", "new1", "a15", "worked40", "new2", "a10", "new3", "worked20", "a12", "new4"}
	// as the monitoring: fastest first, the untested between them, the failed last; of the failed,
	// the ones that worked before first
	want := []string{"a10", "new1", "a12", "new2", "a15", "new3", "new4", "worked20", "worked40", "failed"}
	require.Equal(t, want, testOrder(tags, pings))
	require.Empty(t, testOrder(nil, pings))
}

// world is a profile whose proxies answer with the delays given (timeoutPing: not at all).
type world struct {
	tags   []string
	delays map[string]int32
}

func newWorld(n int, delay func(i int) int32) world {
	w := world{delays: make(map[string]int32)}
	for i := range n {
		tag := fmt.Sprintf("p%03d", i)
		w.tags = append(w.tags, tag)
		w.delays[tag] = delay(i)
	}
	return w
}

// runPick goes through a pick the way the core does: plan a stage, test its batch, plan again.
// It returns the pick and how many stages it took, and checks what holds at every stage.
func runPick(t *testing.T, w world, in topPlanInput) ([]string, int) {
	t.Helper()
	in.tags, in.now = w.tags, time.Now()
	if in.pings == nil {
		in.pings = make(map[string]*topPing)
	}
	tests := make(map[string]int)
	for stage := 1; ; stage++ {
		require.LessOrEqual(t, stage, len(w.tags)+2, "the pick ends")
		plan := planKeepTop(in)
		require.False(t, plan.exhausted && len(plan.load) > 0)
		if plan.exhausted {
			return nil, stage
		}
		limit := in.count + len(plan.batch)
		limit += len(in.pinned)
		require.LessOrEqual(t, len(plan.load), limit, "never more than the best and a batch run")
		if in.batch > 0 {
			require.LessOrEqual(t, len(plan.batch), in.batch)
		}
		seen := make(map[string]bool)
		for _, tag := range plan.load {
			require.False(t, seen[tag], "no proxy twice")
			seen[tag] = true
		}
		for _, tag := range in.pinned {
			require.Contains(t, plan.load, tag, "a pinned outbound is always in use")
		}
		if plan.final {
			require.Empty(t, plan.batch)
			return plan.load, stage
		}
		require.NotEmpty(t, plan.batch, "a stage that is not the last tests something")
		for _, tag := range plan.batch {
			tests[tag]++
			require.Equal(t, 1, tests[tag], "a proxy is tested once in a pick")
			ping := in.pings[tag]
			if ping == nil {
				ping = &topPing{}
				in.pings[tag] = ping
			}
			ping.Delay, ping.Time, ping.pick = w.delays[tag], in.now.Unix(), in.pick
			if pingAlive(ping.Delay) {
				ping.Good = ping.Delay
			}
		}
		in.loading = plan.batch
	}
}

// fastest are the count fastest proxies of the world that answer.
func (w world) fastest(count int) []string {
	var alive []string
	for _, tag := range w.tags {
		if pingAlive(w.delays[tag]) {
			alive = append(alive, tag)
		}
	}
	sort.SliceStable(alive, func(i, j int) bool { return w.delays[alive[i]] < w.delays[alive[j]] })
	if len(alive) > count {
		alive = alive[:count]
	}
	return alive
}

func TestH_KeepTopPlanFindsTheFastest(t *testing.T) {
	random := rand.New(rand.NewSource(7))
	for _, size := range []int{4, 11, 60, 300} {
		for _, batch := range []int{1, 3, 10, -1} {
			w := newWorld(size, func(i int) int32 {
				if random.Intn(3) == 0 {
					return timeoutPing
				}
				return int32(20 + random.Intn(900))
			})
			pick, stages := runPick(t, w, topPlanInput{pick: 1, count: 3, batch: batch})
			want := w.fastest(3)
			sort.Strings(want)
			sort.Strings(pick)
			require.Equal(t, want, pick, "size %d batch %d", size, batch)
			if batch < 0 {
				require.Equal(t, 2, stages, "all at once: one stage, then the pick")
			}
		}
	}
}

func TestH_KeepTopPlanNoneAnswers(t *testing.T) {
	w := newWorld(25, func(int) int32 { return timeoutPing })
	in := topPlanInput{pick: 1, count: 3, batch: 10}
	pick, stages := runPick(t, w, in)
	require.Nil(t, pick)
	require.Equal(t, 4, stages, "three stages of ten, then nothing left")
}

// with keep-top-quick and the pings of the last run, the pick ends after the first stage: the
// ones left were slower then
func TestH_KeepTopPlanQuickEndsEarly(t *testing.T) {
	w := newWorld(100, func(i int) int32 { return int32(50 + i) })
	pings := make(map[string]*topPing)
	for tag, delay := range w.delays {
		pings[tag] = &topPing{Delay: delay, Time: time.Now().Add(-time.Hour).Unix(), Good: delay}
	}
	pick, stages := runPick(t, w, topPlanInput{pick: 5, count: 3, batch: 10, quick: true, pings: pings})
	require.Equal(t, []string{"p000", "p001", "p002"}, pick)
	require.Equal(t, 2, stages)

	// a proxy never tested may be the fastest: it is tested before the pick ends, and it comes early
	delete(pings, "p090")
	for _, ping := range pings {
		ping.pick = 0
	}
	w.delays["p090"] = 5
	pick, stages = runPick(t, w, topPlanInput{pick: 6, count: 3, batch: 10, quick: true, pings: pings})
	require.Equal(t, []string{"p090", "p000", "p001"}, pick)
	require.Equal(t, 2, stages, "the untested one is in the first stage")

	// without quick every proxy is tested
	for _, ping := range pings {
		ping.pick = 0
	}
	_, stages = runPick(t, w, topPlanInput{pick: 7, count: 3, batch: 10, pings: pings})
	require.Equal(t, 11, stages)
}

func TestH_KeepTopPlanSelectedAndCountries(t *testing.T) {
	w := newWorld(30, func(i int) int32 { return int32(100 + i) })
	pick, _ := runPick(t, w, topPlanInput{pick: 1, count: 3, batch: 5, pinned: []string{"p029"}})
	require.Equal(t, []string{"p000", "p001", "p002", "p029"}, pick, "the pinned one is used beside the fastest")

	// keep-top-countries: by the flag in the name before the test, by the IP after it
	w = world{tags: []string{"🇩🇪 a", "🇺🇸 b", "c", "🇩🇪 d"}, delays: map[string]int32{"🇩🇪 a": 300, "🇺🇸 b": 10, "c": 20, "🇩🇪 d": 100}}
	pings := map[string]*topPing{}
	in := topPlanInput{pick: 1, count: 4, batch: 10, countries: []string{"DE"}, pings: pings}
	in.tags, in.now = w.tags, time.Now()
	plan := planKeepTop(in)
	require.Equal(t, []string{"🇩🇪 a", "c", "🇩🇪 d"}, plan.batch, "the one of another country is not loaded at all")
	pings["🇩🇪 a"] = &topPing{Delay: 300, pick: 1}
	pings["🇩🇪 d"] = &topPing{Delay: 100, pick: 1}
	pings["c"] = &topPing{Delay: 20, pick: 1, Country: "FR"} // its IP is elsewhere
	plan = planKeepTop(in)
	require.True(t, plan.final)
	require.Equal(t, []string{"🇩🇪 d", "🇩🇪 a"}, plan.load)
}

func TestH_KeepTopPlanGoesOnAfterAReload(t *testing.T) {
	w := newWorld(20, func(i int) int32 { return int32(100 + i) })
	in := topPlanInput{tags: w.tags, pings: map[string]*topPing{}, pick: 1, count: 2, batch: 4, now: time.Now()}
	first := planKeepTop(in)
	require.Equal(t, []string{"p000", "p001", "p002", "p003"}, first.batch)
	// two of the batch answered when a reload of the app builds the config again
	in.pings["p001"] = &topPing{Delay: 101, pick: 1}
	in.pings["p003"] = &topPing{Delay: 103, pick: 1}
	in.loading = first.batch
	second := planKeepTop(in)
	require.Equal(t, []string{"p000", "p002", "p004", "p005"}, second.batch, "the ones still tested stay, the batch is filled")
	require.Equal(t, []string{"p001", "p003", "p000", "p002", "p004", "p005"}, second.load)

	// an outbound that was replaced is another one: its ping is of no pick
	in.pings["p001"].pick = 0
	third := planKeepTop(in)
	require.Contains(t, third.batch, "p001")
}

func TestH_KeepTopWaits(t *testing.T) {
	require.Equal(t, 30*time.Second, keepTopStageWait(10))
	require.Equal(t, time.Duration(0), keepTopRoundWait(0))
	require.Equal(t, 30*time.Second, keepTopRoundWait(1))
	require.Equal(t, time.Minute, keepTopRoundWait(2))
	require.Equal(t, 5*time.Minute, keepTopRoundWait(50))
}

// socksServer is a SOCKS5 proxy on a local port whose answers are late by delay.
func TestH_KeepTopPickTopEarly(t *testing.T) {
	timeout := int32(maxPing)
	tests := []struct {
		name          string
		delays, hints map[string]int32
		count         int
		want          []string
	}{
		{"the rest were slower before",
			map[string]int32{"a": 80, "b": 60, "c": 0, "d": 0},
			map[string]int32{"a": 50, "b": 70, "c": 200, "d": 300}, 2, []string{"b", "a"}},
		{"one still to test was faster before",
			map[string]int32{"a": 80, "b": 60, "c": 0},
			map[string]int32{"a": 50, "b": 70, "c": 70}, 2, nil},
		{"as fast as the best still to test",
			map[string]int32{"a": 80, "b": 60, "c": 0},
			map[string]int32{"a": 50, "b": 70, "c": 80}, 2, []string{"b", "a"}},
		{"a never tested one is waited for",
			map[string]int32{"a": 80, "b": 60, "c": 0},
			map[string]int32{"a": 50, "b": 70}, 2, nil},
		{"a never tested one that answered counts",
			map[string]int32{"a": 80, "b": 60, "c": 30, "d": 0},
			map[string]int32{"a": 50, "b": 70, "d": 900}, 2, []string{"c", "b"}},
		{"failed before does not hold it",
			map[string]int32{"a": 80, "b": 60, "c": 0},
			map[string]int32{"a": 50, "b": 70, "c": previousFailed}, 2, []string{"b", "a"}},
		{"fewer than count answered",
			map[string]int32{"a": 80, "b": timeout, "c": 0},
			map[string]int32{"a": 50, "b": 70, "c": 900}, 2, nil},
		{"no count", map[string]int32{"a": 80}, map[string]int32{"a": 50}, 0, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pickTopEarly(test.delays, test.hints, test.count); !slices.Equal(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestH_KeepTopTopPingHint(t *testing.T) {
	now := time.Now()
	recent, old := now.Add(-time.Hour).Unix(), now.Add(-48*time.Hour).Unix()
	tests := []struct {
		name string
		ping *topPing
		want int32
	}{
		{"none", nil, 0},
		{"pinged", &topPing{Time: recent, Delay: 120}, 120},
		{"timed out", &topPing{Time: recent, Delay: timeoutPing}, previousFailed},
		{"never tested", &topPing{}, 0},
		{"pinged two days ago", &topPing{Time: old, Delay: 120}, 0},
		{"timed out two days ago", &topPing{Time: old, Delay: timeoutPing}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.ping.hint(now); got != test.want {
				t.Fatalf("got %d, want %d", got, test.want)
			}
		})
	}
}

func TestH_KeepTopWithoutTimedOut(t *testing.T) {
	timeout := int32(maxPing)
	tests := []struct {
		name   string
		delays map[string]int32
		want   []string
	}{
		{"one stopped answering", map[string]int32{"a": 100, "b": timeout, "c": 0}, []string{"a", "c"}},
		{"all answer", map[string]int32{"a": 100, "b": 200}, nil},
		{"every one timed out: the whole list comes back instead", map[string]int32{"a": timeout, "b": timeout}, nil},
		{"none tested yet", map[string]int32{"a": 0, "b": timeout}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := withoutTimedOut(test.delays); !slices.Equal(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestH_KeepTopWithPinned(t *testing.T) {
	require.Equal(t, []string{"a", "b"}, withPinned([]string{"a", "b"}, nil))
	require.Equal(t, []string{"a", "b"}, withPinned([]string{"a", "b"}, []string{"b"}), "pinned among the fastest")
	require.Equal(t, []string{"a", "b", "x", "y"}, withPinned([]string{"a", "b"}, []string{"x", "b", "y"}), "beside the fastest, not in place of one")
}

func TestH_KeepTopCountries(t *testing.T) {
	require.Equal(t, []string{"DE", "GB", "US"}, normalizeCountries([]string{"us", " de", "GB", "us", "", "xyz"}))
	require.Nil(t, normalizeCountries(nil))
	require.Equal(t, "DE", proxyCountry("🇩🇪 12 - DE - VLESS", nil), "the flag in its name")
	require.Equal(t, "", proxyCountry("12 - VLESS", nil))
	countries := []string{"DE", "FR"}
	require.False(t, outsideCountries(nil, "US", true), "no countries: every proxy")
	require.False(t, outsideCountries(countries, "DE", true))
	require.True(t, outsideCountries(countries, "US", false), "another country is left out, tested or not")
	require.False(t, outsideCountries(countries, "", false), "not tested yet: it may be of one")
	require.True(t, outsideCountries(countries, "", true), "tested, and still of no known country")
}
