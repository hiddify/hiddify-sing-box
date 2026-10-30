package cachefile

import (
	"context"
	"github.com/sagernet/sing-box/adapter/htest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func openTestCache(t *testing.T, options option.CacheFileOptions) *CacheFile {
	c := New(context.Background(), log.NewNOPFactory().NewLogger("cache"), options)
	require.NoError(t, htest.Start(c, adapter.StartStateInitialize))
	return c
}

func TestH_CacheFileWARPMASQUEFlags(t *testing.T) {
	dir := t.TempDir()
	c := New(context.Background(), log.NewNOPFactory().NewLogger("cache"), option.CacheFileOptions{Path: filepath.Join(dir, "a.db")})
	require.True(t, c.StoreWARPConfig(), "stored unless turned off")
	require.True(t, c.StoreMASQUEConfig(), "stored unless turned off")

	off := false
	c = New(context.Background(), log.NewNOPFactory().NewLogger("cache"), option.CacheFileOptions{
		Path:              filepath.Join(dir, "b.db"),
		StoreWARPConfig:   &off,
		StoreMASQUEConfig: &off,
	})
	require.False(t, c.StoreWARPConfig())
	require.False(t, c.StoreMASQUEConfig())

	var _ adapter.CacheFile = c
}

func TestH_CacheFileBinaryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	c := openTestCache(t, option.CacheFileOptions{Path: path})
	require.Nil(t, c.LoadBinary("outbound_monitoring_history"))

	updated := time.Unix(1700000000, 0)
	require.NoError(t, c.SaveBinary("outbound_monitoring_history", &adapter.SavedBinary{
		Content:     []byte(`{"outbound_data":{}}`),
		LastUpdated: updated,
		LastEtag:    "etag",
	}))
	loaded := c.LoadBinary("outbound_monitoring_history")
	require.NotNil(t, loaded)
	require.Equal(t, []byte(`{"outbound_data":{}}`), loaded.Content)
	require.Equal(t, "etag", loaded.LastEtag)
	require.True(t, updated.Equal(loaded.LastUpdated))
	require.Nil(t, c.LoadBinary("other"))

	require.NoError(t, c.SaveBinary("outbound_monitoring_history", &adapter.SavedBinary{Content: []byte("v2")}))
	require.Equal(t, []byte("v2"), c.LoadBinary("outbound_monitoring_history").Content)
	require.NoError(t, htest.Close(c))

	c = openTestCache(t, option.CacheFileOptions{Path: path})
	defer htest.Close(c)
	require.Equal(t, []byte("v2"), c.LoadBinary("outbound_monitoring_history").Content, "persisted across reopen")
}

func TestH_CacheFileBinaryWithCacheID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	c := openTestCache(t, option.CacheFileOptions{Path: path, CacheID: "profile-1"})
	require.NoError(t, c.SaveBinary("k", &adapter.SavedBinary{Content: []byte("one")}))
	require.NoError(t, htest.Close(c))

	c = openTestCache(t, option.CacheFileOptions{Path: path, CacheID: "profile-2"})
	require.Nil(t, c.LoadBinary("k"), "binaries are scoped by cache id")
	require.NoError(t, htest.Close(c))

	c = openTestCache(t, option.CacheFileOptions{Path: path, CacheID: "profile-1"})
	defer htest.Close(c)
	require.Equal(t, []byte("one"), c.LoadBinary("k").Content)
}
