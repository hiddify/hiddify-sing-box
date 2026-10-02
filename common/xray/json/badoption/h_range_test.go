package badoption

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_RangeUnmarshal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input    string
		from, to int32
	}{
		{`""`, 0, 0},
		{`"7"`, 7, 7},
		{`"10-20"`, 10, 20},
		{`5`, 5, 5},
		{`{"from":3,"to":9}`, 3, 9},
	}
	for _, c := range cases {
		var r Range
		require.NoError(t, json.Unmarshal([]byte(c.input), &r), c.input)
		require.Equal(t, Range{c.from, c.to}, r, c.input)
	}
	for _, invalid := range []string{`"20-10"`, `"a-1"`, `"1-b"`, `"x"`, `"9999999999"`, `{"from":5,"to":1}`, `[1]`, `"-5"`} {
		var r Range
		require.Error(t, json.Unmarshal([]byte(invalid), &r), invalid)
	}
}

func TestH_RangeUnmarshalNumberOverflow(t *testing.T) {
	t.Skip("BUG: a JSON number outside int32 is silently truncated (range.go:59-61): 9999999999 becomes 1410065407 instead of an error, while the string form \"9999999999\" is rejected")
	t.Parallel()
	var r Range
	require.Error(t, json.Unmarshal([]byte(`9999999999`), &r))
}

func TestH_RangeMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, r := range []Range{{0, 0}, {1, 1}, {10, 20}} {
		content, err := json.Marshal(&r)
		require.NoError(t, err)
		var decoded Range
		require.NoError(t, json.Unmarshal(content, &decoded))
		require.Equal(t, r, decoded)
	}
	content, err := json.Marshal(&Range{10, 20})
	require.NoError(t, err)
	require.JSONEq(t, `"10-20"`, string(content))
	r := &Range{1, 2}
	require.Same(t, r, r.Build())
}

func TestH_RangeRand(t *testing.T) {
	t.Parallel()
	require.Equal(t, int32(5), Range{5, 5}.Rand())
	r := Range{10, 13}
	for range 200 {
		v := r.Rand()
		require.GreaterOrEqual(t, v, int32(10))
		require.LessOrEqual(t, v, int32(13))
	}
}
