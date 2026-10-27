//go:build with_tailscale

package tailscale

import (
	"testing"

	_ "github.com/sagernet/tailscale/control/controlhttp"
	"github.com/sagernet/tailscale/envknob"

	"github.com/stretchr/testify/require"
)

// The control connection goes straight to port 443: port 80 is a cleartext HTTP upgrade that
// filtered networks intercept or fingerprint. RegisterBool returns the knob controlhttp
// registered, so this checks the value the control client reads.
func TestH_ControlForcesNoise443(t *testing.T) {
	require.True(t, envknob.RegisterBool("TS_FORCE_NOISE_443")())
}
