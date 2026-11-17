package warpscan

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/wireguard-go/hiddify"

	"github.com/stretchr/testify/require"
)

// Every preset builds its packets, as WireGuard noise and as AmneziaWG settings.
func TestH_NoisePresets(t *testing.T) {
	names := map[string]bool{}
	for _, preset := range NoisePresets {
		require.False(t, names[preset.Name], "unique name")
		names[preset.Name] = true
		noise := preset.WireGuard()
		require.NoError(t, noise.FakePacket.Validate(), preset.Name)
		packets, err := noise.FakePacket.Build()
		require.NoError(t, err, preset.Name)
		require.NotEmpty(t, packets, preset.Name)

		awg := preset.AWG(&option.AwgOptions{H1: "1"})
		require.True(t, awg.IsAvailble(), preset.Name)
		require.Equal(t, "1", awg.H1, "the other settings are kept")
		probe := AWGProbeNoise(awg)
		probePackets, err := probe.FakePacket.Build()
		require.NoError(t, err, preset.Name)
		want := len(preset.Noise.Packets) + int(preset.Noise.Count.To) // the AmneziaWG form sends the most packets
		require.Equal(t, want, len(probePackets), "%s: the probe sends what the AmneziaWG device sends", preset.Name)
	}
	_, found := NoisePresetByName("dns-google")
	require.True(t, found)
	_, found = NoisePresetByName("nope")
	require.False(t, found)
}

func TestH_NoisePresetAWG(t *testing.T) {
	sip, _ := NoisePresetByName("sip")
	awg := sip.AWG(&option.AwgOptions{Jc: 99, I3: "<r 1>"})
	require.Equal(t, 10, awg.Jc)
	require.Equal(t, 42, awg.Jmin)
	require.Equal(t, 224, awg.Jmax)
	require.Equal(t, sip.Noise.Packets[0], awg.I1)
	require.Empty(t, awg.I3, "the preset's packets replace the others")

	quic, _ := NoisePresetByName("quic")
	awg = quic.AWG(nil)
	require.Zero(t, awg.Jc)
	require.Equal(t, "<qi www.google.com>", awg.I1)

	noise := AWGProbeNoise(&option.AwgOptions{Jc: 2, Jmin: 10, Jmax: 20, I1: "<r 3>"})
	require.Equal(t, hiddify.NoiseModeRaw, noise.FakePacket.Mode)
	require.Equal(t, []string{"<r 3>"}, noise.FakePacket.Packets)
	require.False(t, AWGProbeNoise(&option.AwgOptions{}).FakePacket.Enabled)
}

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
