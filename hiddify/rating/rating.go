// Package rating is the one score Hiddify keeps for the things it chooses between: WARP endpoints,
// noises and tunnels, the resolvers of a DNS pool, the servers of a sequential DNS group.
//
// A score runs from Min (-10) to Max (10); 0 is unknown. A success adds a point and lifts the
// score to at least 1, so one answer puts a choice that kept failing ahead of every one that was
// never tried, and a choice that works again is not held back by its past. A failure takes a
// point, or more for a graded failure.
//
// Choices are ranked by score (Sort), or drawn in a weighted random order (Order): every 2.5
// points double the chance of coming first, so the best known choice is taken most often, the
// others still get their turn, and a choice that only worked on another day is tried again now
// and then instead of being written off for good.
package rating

import (
	"cmp"
	"math"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// Score is a rating from Min to Max.
type Score int

const (
	Min Score = -10
	Max Score = 10
)

// doubling is the number of points that double a choice's weight in Order.
const doubling = 2.5

// Clamp bounds value to Min..Max.
func Clamp(value int) Score {
	return Score(min(max(value, int(Min)), int(Max)))
}

// Add moves the score by delta: a positive delta counts from 0 when the score is below it (a
// success forgets the failures before it), a negative one from the score.
func (s Score) Add(delta int) Score {
	if delta > 0 && s < 0 {
		s = 0
	}
	return Clamp(int(s) + delta)
}

// Success is one point more, and at least 1.
func (s Score) Success() Score {
	return s.Add(1)
}

// Failure is one point less.
func (s Score) Failure() Score {
	return s.Add(-1)
}

// Weight is the score as a weight for Order: 1 at 0, 16 at Max, 1/16 at Min.
func (s Score) Weight() float64 {
	return math.Exp2(float64(Clamp(int(s))) / doubling)
}

// Sort returns items best first, items of equal score in their given order.
func Sort[T any](items []T, score func(T) Score) []T {
	sorted := slices.Clone(items)
	slices.SortStableFunc(sorted, func(a, b T) int {
		return cmp.Compare(score(b), score(a))
	})
	return sorted
}

// random is rand.Float64; tests replace it.
var random = rand.Float64

// Order returns items in a weighted random order, drawn one after the other without
// replacement: the chance of an item to come next is its weight over the weights of the items
// left (the Efraimidis–Spirakis method: each item draws u^(1/weight), largest first).
func Order[T any](items []T, score func(T) Score) []T {
	type keyed struct {
		item T
		key  float64
	}
	list := make([]keyed, len(items))
	for i, item := range items {
		// log(u)/weight orders as u^(1/weight); 1-random keeps u in (0, 1]
		list[i] = keyed{item, math.Log(1-random()) / score(item).Weight()}
	}
	slices.SortStableFunc(list, func(a, b keyed) int {
		return cmp.Compare(b.key, a.key)
	})
	ordered := make([]T, len(list))
	for i, entry := range list {
		ordered[i] = entry.item
	}
	return ordered
}

// Pick draws one item, by weight; false when items is empty.
func Pick[T any](items []T, score func(T) Score) (T, bool) {
	var zero T
	if len(items) == 0 {
		return zero, false
	}
	return Order(items, score)[0], true
}

// Policy tempers the failures of a Record.
type Policy struct {
	// FailureGap is the shortest time between two failures that count, so a burst of failures
	// (one outage) costs a single point.
	FailureGap time.Duration
	// A choice that succeeded within RecentWindow does not fall below RecentFloor.
	RecentWindow time.Duration
	RecentFloor  Score
}

// Record is a score with the time of its last success and its last counted failure, for
// choices that are saved.
type Record struct {
	Score       Score     `json:"score"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastFailure time.Time `json:"last_penalty,omitzero"`
}

// Success counts a success at now.
func (r *Record) Success(now time.Time) {
	r.Score = r.Score.Success()
	r.LastSuccess = now
}

// Failure counts a failure at now under policy, and reports whether it counted.
func (r *Record) Failure(now time.Time, policy Policy) bool {
	if policy.FailureGap > 0 && !r.LastFailure.IsZero() && now.Sub(r.LastFailure) < policy.FailureGap {
		return false
	}
	r.LastFailure = now
	r.Score = r.Score.Failure()
	if policy.RecentWindow > 0 && !r.LastSuccess.IsZero() && now.Sub(r.LastSuccess) <= policy.RecentWindow {
		r.Score = max(r.Score, policy.RecentFloor)
	}
	return true
}

// Table keeps the scores of choices in memory. It is safe for concurrent use; the zero value is
// ready.
type Table[K comparable] struct {
	access sync.Mutex
	scores map[K]Score
}

// Score is the score of key, 0 when unknown.
func (t *Table[K]) Score(key K) Score {
	t.access.Lock()
	defer t.access.Unlock()
	return t.scores[key]
}

// Add moves the score of key by delta (see Score.Add) and returns it.
func (t *Table[K]) Add(key K, delta int) Score {
	t.access.Lock()
	defer t.access.Unlock()
	if t.scores == nil {
		t.scores = make(map[K]Score)
	}
	score := t.scores[key].Add(delta)
	t.scores[key] = score
	return score
}

// Settle scores one attempt over several choices: winner succeeded, and the choices in failed
// failed before it. Without a winner nothing counts: when no choice works the network is the
// likely cause, not the choices.
func (t *Table[K]) Settle(winner K, failed []K) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.scores == nil {
		t.scores = make(map[K]Score)
	}
	t.scores[winner] = t.scores[winner].Success()
	for _, key := range failed {
		if key != winner {
			t.scores[key] = t.scores[key].Failure()
		}
	}
}

// Sort returns keys best first, keys of equal score in their given order.
func (t *Table[K]) Sort(keys []K) []K {
	t.access.Lock()
	defer t.access.Unlock()
	return Sort(keys, func(key K) Score { return t.scores[key] })
}

// Order returns keys in a weighted random order (see Order).
func (t *Table[K]) Order(keys []K) []K {
	t.access.Lock()
	defer t.access.Unlock()
	return Order(keys, func(key K) Score { return t.scores[key] })
}

// Reset forgets every score.
func (t *Table[K]) Reset() {
	t.access.Lock()
	defer t.access.Unlock()
	clear(t.scores)
}
