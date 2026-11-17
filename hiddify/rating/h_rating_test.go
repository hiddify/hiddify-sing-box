package rating

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestH_ScoreRules(t *testing.T) {
	var s Score
	for range 20 {
		s = s.Success()
	}
	require.Equal(t, Max, s, "successes stop at Max")
	for range 30 {
		s = s.Failure()
	}
	require.Equal(t, Min, s, "failures stop at Min")
	require.Equal(t, Score(1), s.Success(), "a success after failures gives 1")
	require.Equal(t, Score(3), Score(-4).Add(3), "a graded success counts from 0")
	require.Equal(t, Score(-7), Score(-3).Add(-4), "a graded failure counts from the score")
	require.Equal(t, Score(7), Score(10).Add(-3))
	require.Equal(t, Max, Score(9).Add(30))
}

func TestH_Weight(t *testing.T) {
	require.Equal(t, 1.0, Score(0).Weight())
	require.InDelta(t, 16, Max.Weight(), 1e-9)
	require.InDelta(t, 1.0/16, Min.Weight(), 1e-9)
	require.InDelta(t, 4, Score(5).Weight(), 1e-9, "every 2.5 points double the weight")
	require.Greater(t, Score(1).Weight(), Score(0).Weight())
}

func TestH_RecordPolicy(t *testing.T) {
	policy := Policy{FailureGap: time.Hour, RecentWindow: 7 * 24 * time.Hour, RecentFloor: -5}
	now := time.Now()
	var record Record
	record.Success(now)
	require.Equal(t, Score(1), record.Score)
	require.True(t, record.Failure(now, policy))
	require.False(t, record.Failure(now.Add(time.Minute), policy), "one failure per gap")
	require.Equal(t, Score(0), record.Score)
	for hour := 1; hour <= 30; hour++ {
		record.Failure(now.Add(time.Duration(hour)*time.Hour), policy)
	}
	require.Equal(t, Score(-5), record.Score, "a recent success holds the floor")
	later := now.Add(8 * 24 * time.Hour)
	for hour := range 10 {
		record.Failure(later.Add(time.Duration(hour)*time.Hour), policy)
	}
	require.Equal(t, Min, record.Score, "past the window it falls to the bottom")
}

func TestH_TableSettle(t *testing.T) {
	var table Table[string]
	table.Settle("good", []string{"bad", "good"})
	require.Equal(t, Score(1), table.Score("good"))
	require.Equal(t, Score(-1), table.Score("bad"))
	require.Equal(t, Score(0), table.Score("new"))
	require.Equal(t, []string{"good", "new", "bad"}, table.Sort([]string{"bad", "new", "good"}))
	table.Reset()
	require.Equal(t, Score(0), table.Score("good"))
}

// Order draws each item first with a chance of its weight over the sum of the weights.
func TestH_OrderIsWeighted(t *testing.T) {
	scores := map[string]Score{"best": 10, "unknown": 0, "worst": -10}
	items := []string{"worst", "unknown", "best"}
	first := map[string]int{}
	const trials = 20000
	for range trials {
		ordered := Order(items, func(item string) Score { return scores[item] })
		require.ElementsMatch(t, items, ordered)
		first[ordered[0]]++
	}
	total := 16 + 1 + 1.0/16
	require.InDelta(t, 16/total, float64(first["best"])/trials, 0.02)
	require.InDelta(t, 1/total, float64(first["unknown"])/trials, 0.02)
	require.Positive(t, first["worst"]+first["unknown"], "the others still get their turn")

	picked, ok := Pick([]string{"only"}, func(string) Score { return Min })
	require.True(t, ok)
	require.Equal(t, "only", picked)
	_, ok = Pick([]string(nil), func(string) Score { return 0 })
	require.False(t, ok)
}
