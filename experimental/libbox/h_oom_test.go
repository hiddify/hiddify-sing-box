//go:build darwin || linux || windows

package libbox

import (
	"runtime/debug"
	"testing"

	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/stretchr/testify/require"
)

// With the OOM killer on, the Go memory limit is the one it derives from its limit, whoever sets
// it: Setup, or SetMemoryLimit at every start of the core. SetMemoryLimit put three quarters of it
// back (37.5 MB of an iOS extension's 50, against the OOM killer's 45).
func TestH_SetMemoryLimitKeepsTheOOMKillersLimit(t *testing.T) {
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(-1))
	defer ReloadSetupOptions(&SetupOptions{})

	ReloadSetupOptions(&SetupOptions{OomKillerEnabled: true, OomMemoryLimit: 50 << 20})
	want := int64(oomkiller.RuntimeMemoryLimit(50 << 20))
	require.Equal(t, want, debug.SetMemoryLimit(-1), "Setup")
	SetMemoryLimit(true)
	require.Equal(t, want, debug.SetMemoryLimit(-1), "a start keeps it")

	enabled, killerDisabled, limit := OOMKillerOptions()
	require.True(t, enabled)
	require.False(t, killerDisabled)
	require.Equal(t, uint64(50<<20), limit)

	// without the OOM killer, as before
	ReloadSetupOptions(&SetupOptions{OomMemoryLimit: 40 << 20})
	SetMemoryLimit(true)
	require.Equal(t, int64(30<<20), debug.SetMemoryLimit(-1))
}
