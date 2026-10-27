package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type hFakeIPTransport struct {
	adapter.DNSTransport
	store adapter.FakeIPStore
}

func (t *hFakeIPTransport) Store() adapter.FakeIPStore { return t.store }

type hFakeIPTransportManager struct {
	adapter.DNSTransportManager
	transport adapter.FakeIPTransport
}

func (m *hFakeIPTransportManager) FakeIP() adapter.FakeIPTransport { return m.transport }

// /cache/fakeip/flush must clear the FakeIP store in use; with store_fakeip off that is the
// in-memory store, which the cache file reset never touched.
func TestH_FlushFakeIPClearsMemoryStore(t *testing.T) {
	store := fakeip.NewStore(context.Background(), logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	require.NoError(t, store.Start())
	address, err := store.Create("example.com", false)
	require.NoError(t, err)
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), &hFakeIPTransportManager{transport: &hFakeIPTransport{store: store}})
	recorder := httptest.NewRecorder()
	flushFakeip(ctx)(recorder, httptest.NewRequest(http.MethodPost, "/cache/fakeip/flush", nil))
	require.Equal(t, http.StatusNoContent, recorder.Code)
	_, loaded := store.Lookup(address)
	require.False(t, loaded, "the mapping survived the flush")
}
