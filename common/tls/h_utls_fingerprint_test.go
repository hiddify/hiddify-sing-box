//go:build with_utls

package tls

import (
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// github.com/metacubex/utls is replaced by Leadaxe/utls-lx, which has the Firefox 148 and
// Safari 26.3 ClientHellos with the hybrid key share that Xray v26.9.8+ REALITY servers require.
// chrome stays at Chrome 133.
func TestH_UTLSFingerprintVersions(t *testing.T) {
	for name, want := range map[string]utls.ClientHelloID{
		"chrome":  utls.HelloChrome_133,
		"firefox": utls.HelloFirefox_148,
		"safari":  utls.HelloSafari_26_3,
	} {
		id, err := uTLSClientHelloID(name)
		require.NoError(t, err)
		require.Equal(t, want, id, name)
	}
}
