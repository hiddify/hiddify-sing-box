package dns

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_IsBlockedIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr    netip.Addr
		blocked bool
	}{
		{netip.Addr{}, true},
		{netip.MustParseAddr("10.0.0.0"), true},
		{netip.MustParseAddr("10.10.34.35"), true},
		{netip.MustParseAddr("10.255.255.255"), true},
		{netip.MustParseAddr("2001:4188:2:600::1"), true},
		{netip.MustParseAddr("2001:4188:2:600:ffff:ffff:ffff:ffff"), true},
		{netip.MustParseAddr("2001:4188:2:601::1"), false},
		{netip.MustParseAddr("11.0.0.1"), false},
		{netip.MustParseAddr("9.255.255.255"), false},
		{netip.MustParseAddr("1.1.1.1"), false},
		{netip.MustParseAddr("192.168.1.1"), false},
		{netip.MustParseAddr("2606:4700:4700::1111"), false},
	}
	for _, c := range cases {
		require.Equal(t, c.blocked, IsBlockedIP(c.addr), c.addr.String())
	}
}

func TestH_FilterBlocked(t *testing.T) {
	t.Parallel()
	require.Nil(t, FilterBlocked(nil))

	empty := []netip.Addr{}
	out := FilterBlocked(empty)
	require.NotNil(t, out)
	require.Empty(t, out)

	input := []netip.Addr{
		netip.MustParseAddr("10.10.34.36"),
		netip.MustParseAddr("1.1.1.1"),
		{},
		netip.MustParseAddr("2001:4188:2:600::10"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	out = FilterBlocked(input)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}, out)
	require.Same(t, &input[0], &out[0], "filter should reuse the input backing array")

	allBlocked := FilterBlocked([]netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")})
	require.Empty(t, allBlocked)
}
