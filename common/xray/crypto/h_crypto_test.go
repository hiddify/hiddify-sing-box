package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_RandBetween(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(7), RandBetween(7, 7))
	seen := map[int64]bool{}
	for range 500 {
		v := RandBetween(10, 14)
		require.GreaterOrEqual(t, v, int64(10))
		require.Less(t, v, int64(14))
		seen[v] = true
		w := RandBetween(14, 10)
		require.GreaterOrEqual(t, w, int64(10))
		require.Less(t, w, int64(14))
	}
	require.Len(t, seen, 4)
	v := RandBetween(-5, -3)
	require.GreaterOrEqual(t, v, int64(-5))
	require.Less(t, v, int64(-3))
}
