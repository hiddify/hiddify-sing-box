package group

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// hHangingOutbound dials until its context ends and reports when that happens.
type hHangingOutbound struct {
	tag       string
	cancelled chan struct{}
}

func (h *hHangingOutbound) Type() string           { return "hanging" }
func (h *hHangingOutbound) Tag() string            { return h.tag }
func (h *hHangingOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (h *hHangingOutbound) Dependencies() []string { return nil }
func (h *hHangingOutbound) Status() adapter.Status { return adapter.StatusReady }

func (h *hHangingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	<-ctx.Done()
	select {
	case h.cancelled <- struct{}{}:
	default:
	}
	return nil, ctx.Err()
}

func (h *hHangingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

// Closing the group (on reload or shutdown) must stop its running tests instead of letting them
// run to the TCP timeout and write results for outbounds that may no longer exist.
func TestH_URLTestGroupCloseCancelsRunningTests(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWithPtr(ctx, urltest.NewHistoryStorage())
	hanging := &hHangingOutbound{tag: "hanging", cancelled: make(chan struct{}, 1)}
	group, err := NewURLTestGroup(ctx, nil, log.NewNOPFactory().Logger(), []adapter.Outbound{hanging}, "http://example.com/", 0, 0, 0, false)
	require.NoError(t, err)
	group.PostStart()
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, group.Close())
	select {
	case <-hanging.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the running URL test was not cancelled by Close")
	}
}
