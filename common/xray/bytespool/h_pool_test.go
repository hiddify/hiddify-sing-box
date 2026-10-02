package bytespool

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_GetPoolPicksSmallestFit(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		request int32
		index   int
	}{
		{0, 0},
		{1, 0},
		{2048, 0},
		{2049, 1},
		{8192, 1},
		{32768, 2},
		{32769, 3},
		{131072, 3},
	} {
		require.Same(t, &pool[c.index], GetPool(c.request), c.request)
		b := Alloc(c.request)
		require.GreaterOrEqual(t, len(b), int(poolSize[c.index]))
		Free(b)
	}
	require.Nil(t, GetPool(131073))
	b := Alloc(131073)
	require.Len(t, b, 131073)
	Free(make([]byte, 10))
}

func TestH_FreeRestoresFullLength(t *testing.T) {
	t.Parallel()
	b := Alloc(8192)
	Free(b[:10])
	for range 100 {
		got := Alloc(8192)
		require.GreaterOrEqual(t, len(got), 8192)
		Free(got)
	}
}
