package daemon

// Hiddify accessors (//H): hiddify-core reads these to reach the running box's
// context-scoped services (monitoring, URL test history, cache file).

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

func (i *Instance) Context() context.Context {
	return i.ctx
}

func (i *Instance) UrlTestHistory() *urltest.HistoryStorage {
	return i.urlTestHistoryStorage
}

func (i *Instance) CacheFile() adapter.CacheFile {
	return i.cacheFile
}

func (s *StartedService) ReadStatus() *Status {
	return s.readStatus()
}
