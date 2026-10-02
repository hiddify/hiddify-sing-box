package vision

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_HookContext(t *testing.T) {
	t.Parallel()
	base := context.Background()
	require.Equal(t, base, WithHook(base, nil))
	hook, ok := HookFromContext(base)
	require.False(t, ok)
	require.Nil(t, hook)
	//nolint:staticcheck
	hook, ok = HookFromContext(nil)
	require.False(t, ok)
	require.Nil(t, hook)

	var seen net.Conn
	ctx := WithHook(base, func(conn net.Conn) { seen = conn })
	hook, ok = HookFromContext(ctx)
	require.True(t, ok)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	hook(a)
	require.Same(t, a, seen)

	child, cancel := context.WithCancel(ctx)
	defer cancel()
	_, ok = HookFromContext(child)
	require.True(t, ok)
}
