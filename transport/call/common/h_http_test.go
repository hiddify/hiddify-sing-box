package common

import (
	"testing"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A URL taken from a remote page that net/http cannot parse fails the request instead of
// crashing the app on a nil request.
func TestH_HttpGetBadURLIsAnError(t *testing.T) {
	var err error
	require.NotPanics(t, func() {
		_, err = HttpGet(N.SystemDialer, "http://2001:db8::1/")
	})
	require.Error(t, err)
}
