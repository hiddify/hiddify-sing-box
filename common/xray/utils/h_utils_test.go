package utils

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_H2Base62Pad(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 10, 100, 1000} {
		pad := H2Base62Pad(n)
		require.Len(t, pad, int(float64(n)*h2packCorrectionFactor))
		for _, c := range pad {
			require.True(t, strings.ContainsRune(base62Chars, c))
		}
	}
	require.Len(t, H2Base62Pad(int64(80)), 99)
	require.Len(t, H2Base62Pad(int32(80)), 99)
}

func TestH_ChromeVersion(t *testing.T) {
	t.Parallel()
	v := ChromeVersion()
	require.GreaterOrEqual(t, v, 144)
	require.Equal(t, v, ChromeVersion())
	require.Contains(t, ChromeUA, "Chrome/"+strconv.Itoa(v)+".0.0.0")
	require.True(t, strings.HasPrefix(ChromeUA, "Mozilla/5.0 "))
}
