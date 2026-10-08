package peeruser

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLookup(t *testing.T) {
	users := New([]Peer{
		{User: "office", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
		{User: "alice", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("fd00::2/128")}},
		{User: "", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")}},
	})
	require.Equal(t, "alice", users.Lookup(netip.MustParseAddr("10.0.0.2")), "most specific prefix wins")
	require.Equal(t, "alice", users.Lookup(netip.MustParseAddr("::ffff:10.0.0.2")), "4in6 is unmapped")
	require.Equal(t, "alice", users.Lookup(netip.MustParseAddr("fd00::2")))
	require.Equal(t, "office", users.Lookup(netip.MustParseAddr("10.0.0.9")))
	require.Empty(t, users.Lookup(netip.MustParseAddr("10.0.1.5")), "peer without user")
	require.Empty(t, users.Lookup(netip.MustParseAddr("192.168.1.1")))
	require.Empty(t, users.Lookup(netip.Addr{}))
}

func TestNoUsers(t *testing.T) {
	users := New([]Peer{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}})
	require.Nil(t, users)
	require.Empty(t, users.Lookup(netip.MustParseAddr("10.0.0.2")))
}
