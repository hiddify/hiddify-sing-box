//go:build with_tailscale && with_gvisor

package tailscale

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_TailscaleLogoutBeforeStart(t *testing.T) {
	t.Parallel()
	require.ErrorContains(t, (&Endpoint{}).Logout(context.Background()), "not ready")
}

func TestH_TailscaleApplyExitNodeEmpty(t *testing.T) {
	t.Parallel()
	require.NoError(t, (&Endpoint{}).applyExitNode())
}
