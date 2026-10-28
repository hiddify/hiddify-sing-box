package warpscan

import (
	"testing"

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

func TestH_BookNoise(t *testing.T) {
	book := NewBook()
	require.Empty(t, book.Noise("wifi/IR"))
	book.SetNoise("wifi/IR", "dns-google")
	require.Equal(t, "dns-google", book.Noise("wifi/IR"))
	content, err := book.MarshalJSON()
	require.NoError(t, err)
	loaded := NewBook()
	require.NoError(t, loaded.UnmarshalJSON(content))
	require.Equal(t, "dns-google", loaded.Noise("wifi/IR"), "kept in the cache file")
}
