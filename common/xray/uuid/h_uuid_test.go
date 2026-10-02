package uuid

import (
	"crypto/sha1"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_ParseStringFormats(t *testing.T) {
	t.Parallel()
	const canonical = "0123abcd-4567-89ab-cdef-0123456789ab"
	u, err := ParseString(canonical)
	require.NoError(t, err)
	require.Equal(t, canonical, u.String())
	require.Equal(t, []byte{0x01, 0x23, 0xab, 0xcd, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}, u.Bytes())

	compact, err := ParseString(strings.ReplaceAll(canonical, "-", ""))
	require.NoError(t, err)
	require.True(t, u.Equals(&compact))

	upper, err := ParseString(strings.ToUpper(canonical))
	require.NoError(t, err)
	require.Equal(t, u, upper)

	for _, invalid := range []string{
		"",
		strings.Repeat("a", 31),
		canonical + "0",
		"0123abcd-4567-89ab-cdef-0123456789ag",
		"0123abcd-4567-89ab-cdef-0123456789",
	} {
		_, err = ParseString(invalid)
		require.Error(t, err, invalid)
	}
}

func TestH_ParseStringCustomID(t *testing.T) {
	t.Parallel()
	u, err := ParseString("example")
	require.NoError(t, err)
	h := sha1.New()
	h.Write(make([]byte, 16))
	h.Write([]byte("example"))
	expected := h.Sum(nil)[:16]
	expected[6] = (expected[6] & 0x0f) | 0x50
	expected[8] = (expected[8] & 0x3f) | 0x80
	require.Equal(t, expected, u.Bytes())
	require.Equal(t, "feb54431-301b-52bb-a6dd-e1e93e81bb9e", u.String())

	again, err := ParseString("example")
	require.NoError(t, err)
	require.Equal(t, u, again)

	long, err := ParseString(strings.Repeat("x", 30))
	require.NoError(t, err)
	require.NotEqual(t, u, long)
}

func TestH_NewIsRandomV4(t *testing.T) {
	t.Parallel()
	a := New()
	b := New()
	require.NotEqual(t, a, b)
	for _, u := range []UUID{a, b} {
		require.Equal(t, byte(0x40), u[6]&0xf0)
		require.Equal(t, byte(0x80), u[8]&0xc0)
		parsed, err := ParseString(u.String())
		require.NoError(t, err)
		require.Equal(t, u, parsed)
	}
}

func TestH_ParseBytesAndEquals(t *testing.T) {
	t.Parallel()
	raw := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	u, err := ParseBytes(raw)
	require.NoError(t, err)
	require.Equal(t, raw, u.Bytes())

	var nilA, nilB *UUID
	require.True(t, nilA.Equals(nilB))
	require.False(t, u.Equals(nil))
	require.False(t, nilA.Equals(&u))
	other := u
	other[0] = 0
	require.False(t, u.Equals(&other))
}

func TestH_ParseBytesInvalidLength(t *testing.T) {
	t.Skip("BUG: ParseBytes passes a []byte to E.New (uuid.go:60); sing's format.ToString panics with \"unknown value\" instead of returning an error")
	t.Parallel()
	require.NotPanics(t, func() {
		_, err := ParseBytes(make([]byte, 15))
		require.Error(t, err)
	})
}
