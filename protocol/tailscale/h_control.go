//go:build with_tailscale

package tailscale

import (
	"os"

	"github.com/sagernet/tailscale/envknob"
)

// The control client tries a cleartext HTTP upgrade on port 80 first and falls back to port
// 443 only after a delay; filtered networks intercept or fingerprint port 80, so go straight to
// 443 (TLS around Noise) unless TS_FORCE_NOISE_443 is set in the environment. Port 80 is still
// used when the control server has no HTTPS URL.
func init() {
	if _, set := os.LookupEnv("TS_FORCE_NOISE_443"); !set {
		envknob.Setenv("TS_FORCE_NOISE_443", "true")
	}
}
