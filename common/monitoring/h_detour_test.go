package monitoring

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestH_ResolveDetour(t *testing.T) {
	leaf := &fakeOutbound{tag: "leaf"}
	inner := &fakeGroup{fakeOutbound: fakeOutbound{tag: "auto"}, selected: leaf}
	outer := &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, selected: inner}
	require.Equal(t, "leaf", ResolveDetour(outer, N.NetworkUDP), "through nested groups")
	require.Equal(t, "leaf", ResolveDetour(leaf, N.NetworkUDP))
	require.Equal(t, "empty", ResolveDetour(&fakeGroup{fakeOutbound: fakeOutbound{tag: "empty"}}, N.NetworkUDP), "a group with no selection")

	loop := &fakeGroup{fakeOutbound: fakeOutbound{tag: "loop"}}
	loop.selected = loop
	require.Equal(t, "loop", ResolveDetour(loop, N.NetworkUDP), "a cycle ends")
}

func TestH_FollowDetourNeedsAGroup(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	require.False(t, FollowDetour(context.Background(), done, &fakeOutbound{tag: "leaf"}, N.NetworkUDP, func(DetourChange) {}), "an outbound does not move")
	group := &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, selected: &fakeOutbound{tag: "leaf"}}
	require.False(t, FollowDetour(context.Background(), done, group, N.NetworkUDP, func(DetourChange) {}), "no monitoring")
}

type fakeSelector struct{ fakeGroup }

func (s *fakeSelector) SelectOutbound(tag string) bool { return true }

func TestH_DetourMoveTellsWhoMoved(t *testing.T) {
	a, b := &fakeOutbound{tag: "a"}, &fakeOutbound{tag: "b"}
	auto := &fakeGroup{fakeOutbound: fakeOutbound{tag: "auto"}, selected: a}
	selector := &fakeSelector{fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, selected: auto}}

	before := detourPath(selector, N.NetworkUDP)
	auto.selected = b
	change, moved := detourMove(nil, before, detourPath(selector, N.NetworkUDP))
	require.True(t, moved)
	require.Equal(t, DetourChange{From: "a", To: "b", Automatic: true}, change, "the URL test inside the selector moved")

	before = detourPath(selector, N.NetworkUDP)
	selector.selected = a
	change, moved = detourMove(nil, before, detourPath(selector, N.NetworkUDP))
	require.True(t, moved)
	require.Equal(t, DetourChange{From: "b", To: "a"}, change, "the user moved the selector")

	_, moved = detourMove(nil, detourPath(selector, N.NetworkUDP), detourPath(selector, N.NetworkUDP))
	require.False(t, moved)
}

func TestH_SettleMoves(t *testing.T) {
	const settle = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	moves := make(chan DetourChange, 8)
	var broken atomic.Bool
	push := settleMoves(ctx, ctx.Done(), settle, broken.Load, func(change DetourChange) { moves <- change })
	expect := func(want DetourChange, within time.Duration) {
		t.Helper()
		select {
		case got := <-moves:
			require.Equal(t, want, got)
		case <-time.After(within):
			t.Fatalf("no move, want %+v", want)
		}
	}
	none := func(during time.Duration) {
		t.Helper()
		select {
		case got := <-moves:
			t.Fatalf("unexpected move %+v", got)
		case <-time.After(during):
		}
	}

	push(DetourChange{From: "a", To: "b"})
	expect(DetourChange{From: "a", To: "b"}, 100*time.Millisecond) // the user: at once

	start := time.Now()
	push(DetourChange{From: "b", To: "c", Automatic: true})
	push(DetourChange{From: "c", To: "d", Automatic: true})
	none(settle / 2)
	expect(DetourChange{From: "b", To: "d", Automatic: true}, settle) // joined, after settle
	require.GreaterOrEqual(t, time.Since(start), settle-50*time.Millisecond)

	push(DetourChange{From: "d", To: "e", Automatic: true})
	push(DetourChange{From: "e", To: "d", Automatic: true})
	none(settle + 100*time.Millisecond) // came back: nothing to do

	push(DetourChange{From: "d", To: "e", Automatic: true, FromFailed: true})
	expect(DetourChange{From: "d", To: "e", Automatic: true, FromFailed: true}, 100*time.Millisecond) // the member left had failed

	broken.Store(true)
	push(DetourChange{From: "e", To: "f", Automatic: true})
	expect(DetourChange{From: "e", To: "f", Automatic: true}, 100*time.Millisecond) // the tunnel does not work
}
