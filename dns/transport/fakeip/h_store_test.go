package fakeip

// Adapted from reF1nd/sing-box 08fc1d8a (flushing the FakeIP cache).

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// Reset must clear the store it is using (memory by default) and restart allocation.
func TestH_StoreResetClearsMemoryStorage(t *testing.T) {
	t.Parallel()

	store := NewStore(context.Background(), logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fc00::/18"))
	require.NoError(t, store.Start())

	address4, err := store.Create("a.example.com", false)
	require.NoError(t, err)
	address6, err := store.Create("a.example.com", true)
	require.NoError(t, err)
	_, err = store.Create("b.example.com", false)
	require.NoError(t, err)

	require.NoError(t, store.Reset())

	_, loaded := store.Lookup(address4)
	require.False(t, loaded)
	_, loaded = store.Lookup(address6)
	require.False(t, loaded)

	newAddress4, err := store.Create("c.example.com", false)
	require.NoError(t, err)
	require.Equal(t, address4, newAddress4, "allocation restarts from the beginning of the range")
	newAddress6, err := store.Create("c.example.com", true)
	require.NoError(t, err)
	require.Equal(t, address6, newAddress6)
	domain, loaded := store.Lookup(newAddress4)
	require.True(t, loaded)
	require.Equal(t, "c.example.com", domain)
}
