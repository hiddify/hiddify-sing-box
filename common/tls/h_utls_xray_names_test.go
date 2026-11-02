//go:build with_utls

package tls

import (
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// An Xray link's fp=hellochrome_120 used to fail the outbound with "unknown uTLS fingerprint".
func TestH_UTLSXrayFingerprintNames(t *testing.T) {
	id, err := uTLSClientHelloID("hellochrome_120")
	require.NoError(t, err)
	require.Equal(t, utls.HelloChrome_120, id)
	id, err = uTLSClientHelloID("HelloFirefox_148")
	require.NoError(t, err)
	require.Equal(t, utls.HelloFirefox_148, id)
	id, err = uTLSClientHelloID("chrome")
	require.NoError(t, err)
	require.Equal(t, utls.HelloChrome_Auto, id, "sing-box's own names first")
	_, err = uTLSClientHelloID("hellochrome_999")
	require.Error(t, err)
}
