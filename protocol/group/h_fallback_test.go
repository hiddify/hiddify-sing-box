package group

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hScriptedOutbound struct {
	tag   string
	works atomic.Bool
	dials atomic.Int32
}

func (o *hScriptedOutbound) Type() string           { return "scripted" }
func (o *hScriptedOutbound) Tag() string            { return o.tag }
func (o *hScriptedOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *hScriptedOutbound) Dependencies() []string { return nil }
func (o *hScriptedOutbound) Status() adapter.Status { return adapter.StatusReady }

func (o *hScriptedOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dials.Add(1)
	if !o.works.Load() {
		return nil, errors.New(o.tag + " is down")
	}
	client, server := net.Pipe()
	go server.Close()
	return client, nil
}

func (o *hScriptedOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.dials.Add(1)
	if !o.works.Load() {
		return nil, errors.New(o.tag + " is down")
	}
	return net.ListenPacket("udp", "127.0.0.1:0")
}

type hOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *hOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

func hFallback(t *testing.T, timeout time.Duration, members ...*hScriptedOutbound) *Fallback {
	t.Helper()
	manager := &hOutboundManager{outbounds: map[string]adapter.Outbound{}}
	var tags []string
	for _, member := range members {
		manager.outbounds[member.tag] = member
		tags = append(tags, member.tag)
	}
	group, err := NewFallback(context.Background(), nil, log.NewNOPFactory().NewLogger("fallback"), "fallback", option.FallbackOutboundOptions{Outbounds: tags, BlacklistTimeout: badoption.Duration(timeout)})
	require.NoError(t, err)
	fallback := group.(*Fallback)
	fallback.outbound = manager
	require.NoError(t, fallback.Start(adapter.StartStateStart, nil))
	return fallback
}

func hDial(t *testing.T, fallback *Fallback) error {
	t.Helper()
	conn, err := fallback.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	if err == nil {
		conn.Close()
	}
	return err
}

// The first member that connects is used; a failed one is skipped until its blacklist expires.
func TestH_FallbackOrderAndBlacklist(t *testing.T) {
	first, second := &hScriptedOutbound{tag: "first"}, &hScriptedOutbound{tag: "second"}
	second.works.Store(true)
	fallback := hFallback(t, 200*time.Millisecond, first, second)
	require.NoError(t, hDial(t, fallback))
	require.Equal(t, "second", fallback.Now())
	require.Equal(t, int32(1), first.dials.Load())

	// blacklisted: not dialled again while the second works
	require.NoError(t, hDial(t, fallback))
	require.Equal(t, int32(1), first.dials.Load())

	// after the timeout the first is tried again, and used once it works
	time.Sleep(250 * time.Millisecond)
	first.works.Store(true)
	require.NoError(t, hDial(t, fallback))
	require.Equal(t, "first", fallback.Now())
	require.Equal(t, int32(2), first.dials.Load())
}

// Blacklisted members are still tried, last, when the others fail.
func TestH_FallbackTriesBlacklistedLast(t *testing.T) {
	first, second := &hScriptedOutbound{tag: "first"}, &hScriptedOutbound{tag: "second"}
	second.works.Store(true)
	fallback := hFallback(t, time.Hour, first, second)
	require.NoError(t, hDial(t, fallback))
	second.works.Store(false)
	first.works.Store(true)
	require.NoError(t, hDial(t, fallback), "the blacklisted first is the last resort")
	require.Equal(t, "first", fallback.Now())
	require.Equal(t, []string{"first", "second"}, fallback.order(), "a success clears its blacklist entry")
}

// When every member fails, each error is reported.
func TestH_FallbackAllFail(t *testing.T) {
	first, second := &hScriptedOutbound{tag: "first"}, &hScriptedOutbound{tag: "second"}
	fallback := hFallback(t, time.Minute, first, second)
	err := hDial(t, fallback)
	require.ErrorContains(t, err, "first is down")
	require.ErrorContains(t, err, "second is down")
}

// A cancelled dial is not a failure of the member.
func TestH_FallbackCancelled(t *testing.T) {
	first := &hScriptedOutbound{tag: "first"}
	fallback := hFallback(t, time.Minute, first)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fallback.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	require.Error(t, err)
	require.Empty(t, fallback.blacklist)
}

func TestH_FallbackPacket(t *testing.T) {
	first, second := &hScriptedOutbound{tag: "first"}, &hScriptedOutbound{tag: "second"}
	second.works.Store(true)
	fallback := hFallback(t, time.Minute, first, second)
	conn, err := fallback.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.NoError(t, err)
	conn.Close()
	require.Equal(t, "second", fallback.Now())
	require.Equal(t, second, fallback.Selected(N.NetworkUDP))
	require.Equal(t, []string{"first", "second"}, fallback.References())
}
