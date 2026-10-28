package constant

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_DisplayConnecting(t *testing.T) {
	mark := DisplayConnecting()
	require.Contains(t, []string{" ⏳ Connecting...", " ⌛ Connecting..."}, mark)
	for _, frame := range HourglassFlip {
		base, got := SplitConnecting("WARP · WG" + connectingMark(frame))
		require.Equal(t, "WARP · WG", base)
		require.Equal(t, frame+" Connecting...", got)
	}
	base, got := SplitConnecting("WARP · WG")
	require.Equal(t, "WARP · WG", base)
	require.Empty(t, got)
	base, got = SplitConnecting("WARP · MASQUE · 🔍 162.159.198.1:443" + DisplayConnecting())
	require.Equal(t, "WARP · MASQUE · 🔍 162.159.198.1:443", base, "the scanner status stays in the base")
	require.NotEmpty(t, got)
}
