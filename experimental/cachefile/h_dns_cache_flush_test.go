package cachefile

// Adapted from reF1nd/sing-box 1d089fcb (DNS cache issues).

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// A flush that fails (here a read-only database) must keep the entries in memory, not drop them.
func TestH_DNSCacheFlushFailurePreservesPendingValue(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "cache.db")
	database, err := bbolt.Open(databasePath, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, database.Close())
	database, err = bbolt.Open(databasePath, 0o600, &bbolt.Options{ReadOnly: true})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, database.Close())
	})
	cache := &CacheFile{
		DB:      database,
		logger:  logger.NOP(),
		pending: newPendingWrites(),
	}
	const (
		transportName = "local"
		questionName  = "example.com."
		questionType  = uint16(1)
	)
	rawMessage := []byte("pending")
	expireAt := time.Now().Add(time.Hour)
	cache.queueDNSCache(transportName, questionName, questionType, rawMessage, expireAt)

	cache.Flush()

	actualMessage, actualExpireAt, loaded := cache.LoadDNSCache(transportName, questionName, questionType)
	require.True(t, loaded)
	require.Equal(t, rawMessage, actualMessage)
	require.Equal(t, expireAt.Unix(), actualExpireAt.Unix())
}

