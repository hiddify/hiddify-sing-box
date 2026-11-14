package box_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func hProcsBox(t *testing.T, procs *option.HProcsOptions) (*box.Box, error) {
	t.Helper()
	return box.New(box.Options{
		Context: include.Context(context.Background()),
		Options: option.Options{
			Experimental: &option.ExperimentalOptions{Debug: &option.DebugOptions{Procs: procs}},
		},
	})
}

func hWaitProcs(t *testing.T, want int, what string) {
	t.Helper()
	require.Eventually(t, func() bool { return runtime.GOMAXPROCS(0) == want }, 3*time.Second, 5*time.Millisecond,
		"GOMAXPROCS is %d, want %d: %s", runtime.GOMAXPROCS(0), want, what)
}

// experimental.debug.procs: a started box runs on its least number of Go processors while it has
// little to do, and the runtime gets its own number back when the box closes.
func TestH_ProcsFollowTheBox(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Skip("needs two cores")
	}
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("HIDDIFY_PROCS", "")
	before := runtime.GOMAXPROCS(0)
	require.Greater(t, before, 1)

	instance, err := hProcsBox(t, &option.HProcsOptions{Enabled: true})
	require.NoError(t, err)
	require.Equal(t, before, runtime.GOMAXPROCS(0), "nothing changes before the box is started")
	require.NoError(t, instance.Start())
	hWaitProcs(t, 1, "a started box with nothing to do runs on one processor")
	require.NoError(t, instance.Close())
	require.Equal(t, before, runtime.GOMAXPROCS(0), "closing the box gives the runtime its number back")

	// min is the least it goes to
	instance, err = hProcsBox(t, &option.HProcsOptions{Enabled: true, Min: 2})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	hWaitProcs(t, 2, "min is 2")
	require.NoError(t, instance.Close())
	require.Equal(t, before, runtime.GOMAXPROCS(0))

	// off unless it is turned on
	for _, procs := range []*option.HProcsOptions{nil, {}, {Min: 1, Max: 2}} {
		instance, err = hProcsBox(t, procs)
		require.NoError(t, err)
		require.NoError(t, instance.Start())
		time.Sleep(50 * time.Millisecond)
		require.Equal(t, before, runtime.GOMAXPROCS(0), "not enabled: the processors are left alone")
		require.NoError(t, instance.Close())
	}
}

// A GOMAXPROCS in the environment is a number somebody chose, and HIDDIFY_PROCS=off turns the
// governor off whatever the config says: both leave the processors alone. HIDDIFY_PROCS=auto
// turns it on without the option.
func TestH_ProcsEnvironment(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Skip("needs two cores")
	}
	before := runtime.GOMAXPROCS(0)
	for name, value := range map[string]string{"GOMAXPROCS": "3", "HIDDIFY_PROCS": "off"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("GOMAXPROCS", "")
			t.Setenv("HIDDIFY_PROCS", "")
			t.Setenv(name, value)
			instance, err := hProcsBox(t, &option.HProcsOptions{Enabled: true})
			require.NoError(t, err)
			require.NoError(t, instance.Start())
			time.Sleep(50 * time.Millisecond)
			require.Equal(t, before, runtime.GOMAXPROCS(0))
			require.NoError(t, instance.Close())
		})
	}
	t.Run("HIDDIFY_PROCS=auto", func(t *testing.T) {
		t.Setenv("GOMAXPROCS", "")
		t.Setenv("HIDDIFY_PROCS", "auto")
		instance, err := hProcsBox(t, nil)
		require.NoError(t, err)
		require.NoError(t, instance.Start())
		hWaitProcs(t, 1, "turned on by the environment")
		require.NoError(t, instance.Close())
		require.Equal(t, before, runtime.GOMAXPROCS(0))
	})
}

// A procs option that cannot work fails when the config loads, and says what to change.
func TestH_ProcsOptionsAreChecked(t *testing.T) {
	for _, procs := range []*option.HProcsOptions{
		{Enabled: true, Min: 4, Max: 2},
		{Enabled: true, Min: -1},
		{Max: -2},
	} {
		_, err := hProcsBox(t, procs)
		require.ErrorContains(t, err, "debug.procs")
	}
	instance, err := hProcsBox(t, &option.HProcsOptions{Enabled: true, Min: 2, Max: 2})
	require.NoError(t, err)
	require.NoError(t, instance.Close())
}
