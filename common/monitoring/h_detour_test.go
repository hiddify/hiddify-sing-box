package monitoring

import (
	"context"
	"testing"

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
	require.False(t, FollowDetour(context.Background(), done, &fakeOutbound{tag: "leaf"}, N.NetworkUDP, func(string, string) {}), "an outbound does not move")
	group := &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, selected: &fakeOutbound{tag: "leaf"}}
	require.False(t, FollowDetour(context.Background(), done, group, N.NetworkUDP, func(string, string) {}), "no monitoring")
}
