package edgescan

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"

	"github.com/stretchr/testify/require"
)

// Methods are rated per network and kept in the cache file; the noise saved before methods were
// rated becomes a well rated method.
func TestH_BookMethods(t *testing.T) {
	book := NewBook()
	now := time.Now()
	_, known := book.MethodScore("wifi/IR", NoiseMethod("dns-google"))
	require.False(t, known)
	book.SettleMethods("wifi/IR", NoiseMethod("dns-google"), []string{NoiseMethod(""), NoiseMethod("sip")}, now)
	score, known := book.MethodScore("wifi/IR", NoiseMethod("dns-google"))
	require.True(t, known)
	require.Equal(t, rating.Score(1), score)
	score, _ = book.MethodScore("wifi/IR", NoiseMethod("sip"))
	require.Equal(t, rating.Score(-1), score)
	_, known = book.MethodScore("lte/IR", NoiseMethod("dns-google"))
	require.False(t, known, "per network")

	content, err := book.MarshalJSON()
	require.NoError(t, err)
	loaded := NewBook()
	require.NoError(t, loaded.UnmarshalJSON(content))
	score, _ = loaded.MethodScore("wifi/IR", NoiseMethod("dns-google"))
	require.Equal(t, rating.Score(1), score, "kept in the cache file")

	legacy := NewBook()
	require.NoError(t, legacy.UnmarshalJSON([]byte(`{"wifi/IR":{"last_seen":"2026-01-01T00:00:00Z","records":{},"noise":"sip"}}`)))
	score, _ = legacy.MethodScore("wifi/IR", NoiseMethod("sip"))
	require.Equal(t, legacyNoiseScore, score)
	content, err = legacy.MarshalJSON()
	require.NoError(t, err)
	require.NotContains(t, string(content), `"noise"`)
}

// The best rated method comes first most often, never always.
func TestH_BookOrderMethods(t *testing.T) {
	book := NewBook()
	now := time.Now()
	for range 10 {
		book.SettleMethods("home", "good", []string{"bad"}, now)
		now = now.Add(2 * time.Hour)
	}
	methods := []string{"bad", "new", "good"}
	first := map[string]int{}
	for range 2000 {
		ordered := book.OrderMethods("home", methods, nil)
		require.ElementsMatch(t, methods, ordered)
		first[ordered[0]]++
	}
	require.Greater(t, first["good"], 1600)
	require.Positive(t, first["new"])
	require.Greater(t, first["new"], first["bad"])

	prior := func(method string) rating.Score {
		if method == "configured" {
			return rating.Max
		}
		return 0
	}
	first = map[string]int{}
	for range 1000 {
		first[book.OrderMethods("lte", []string{"configured", "other"}, prior)[0]]++
	}
	require.Greater(t, first["configured"], 850, "an unrated method counts as its prior")
}
