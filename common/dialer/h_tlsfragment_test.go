package dialer

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestH_TLSFragmentAsFinalMask(t *testing.T) {
	existing := &option.FinalMaskOptions{TCP: []option.FinalMaskItem{{Type: "header-custom"}}}
	merged, err := withTLSFragment(existing, option.TLSFragmentOptions{Enabled: true}, false)
	require.NoError(t, err)
	require.Len(t, merged.TCP, 2)
	require.Equal(t, "fragment", merged.TCP[0].Type, "the fragment mask is outermost")
	var settings map[string]string
	require.NoError(t, json.Unmarshal(merged.TCP[0].Settings, &settings))
	require.Equal(t, map[string]string{"packets": "tlshello", "length": "1-10", "delay": "0"}, settings)
	require.Len(t, existing.TCP, 1, "the outbound's own finalmask is not modified")

	merged, err = withTLSFragment(nil, option.TLSFragmentOptions{Enabled: true, Size: "5-9", Sleep: "1-3", Method: "range", Range: "1-3"}, false)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(merged.TCP[0].Settings, &settings))
	require.Equal(t, map[string]string{"packets": "1-3", "length": "5-9", "delay": "1-3"}, settings)

	unchanged, err := withTLSFragment(existing, option.TLSFragmentOptions{}, false)
	require.NoError(t, err)
	require.Same(t, existing, unchanged)

	_, err = withTLSFragment(nil, option.TLSFragmentOptions{Enabled: true}, true)
	require.ErrorContains(t, err, "TCP Fast Open")
	_, err = withTLSFragment(nil, option.TLSFragmentOptions{Enabled: true, Method: "range"}, false)
	require.Error(t, err)
	_, err = withTLSFragment(nil, option.TLSFragmentOptions{Enabled: true, Method: "split"}, false)
	require.Error(t, err)
}
