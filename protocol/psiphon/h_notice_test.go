package psiphon

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// A Tunnels notice carries its count as a JSON number; anything else is not a count, where the
// type assertion it replaced panicked.
func TestH_NoticeCount(t *testing.T) {
	for _, test := range []struct {
		data  map[string]interface{}
		count float64
		ok    bool
	}{
		{map[string]interface{}{"count": float64(2)}, 2, true},
		{map[string]interface{}{"count": 3}, 3, true},
		{map[string]interface{}{"count": int64(1)}, 1, true},
		{map[string]interface{}{"count": json.Number("4")}, 4, true},
		{map[string]interface{}{"count": "2"}, 0, false},
		{map[string]interface{}{"count": nil}, 0, false},
		{map[string]interface{}{}, 0, false},
		{nil, 0, false},
	} {
		count, ok := noticeCount(test.data)
		require.Equal(t, test.ok, ok, "%v", test.data)
		require.Equal(t, test.count, count, "%v", test.data)
	}
}
