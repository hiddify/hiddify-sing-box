package net

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_ParseAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input  string
		family AddressFamily
		output string
	}{
		{"8.8.8.8", AddressFamilyIPv4, "8.8.8.8"},
		{"2001:4860:0:2001::68", AddressFamilyIPv6, "[2001:4860:0:2001::68]"},
		{"[2001:4860:0:2001::68]", AddressFamilyIPv6, "[2001:4860:0:2001::68]"},
		{"::ffff:1.2.3.4", AddressFamilyIPv4, "1.2.3.4"},
		{"example.com", AddressFamilyDomain, "example.com"},
		{" 1.2.3.4 ", AddressFamilyIPv4, "1.2.3.4"},
		{" example.com\t", AddressFamilyDomain, "example.com"},
		{"", AddressFamilyDomain, ""},
	}
	for _, c := range cases {
		addr := ParseAddress(c.input)
		require.Equal(t, c.family, addr.Family(), c.input)
		require.Equal(t, c.output, addr.String(), c.input)
	}
	require.True(t, AddressFamilyIPv4.IsIP())
	require.True(t, AddressFamilyIPv6.IsIPv6())
	require.False(t, AddressFamilyDomain.IsIP())
	require.True(t, AddressFamilyDomain.IsDomain())
	require.True(t, AddressFamilyIPv4.IsIPv4())
}

func TestH_IPAddress(t *testing.T) {
	t.Parallel()
	require.Equal(t, LocalHostIP, IPAddress(net.ParseIP("127.0.0.1")))
	require.Equal(t, AddressFamilyIPv6, LocalHostIPv6.Family())
	require.Equal(t, "[::1]", LocalHostIPv6.String())
	require.Nil(t, IPAddress([]byte{1, 2, 3}))
	require.Equal(t, net.IP{10, 0, 0, 1}, IPAddress([]byte{10, 0, 0, 1}).IP())
	require.Panics(t, func() { LocalHostIP.Domain() })
	require.Panics(t, func() { LocalHostIPv6.Domain() })
	require.Panics(t, func() { LocalHostDomain.IP() })
	require.Equal(t, "localhost", LocalHostDomain.Domain())
	require.Equal(t, AddressFamilyDomain, DomainAddress("1.1.1.1").Family())
}

func TestH_ParseDestination(t *testing.T) {
	t.Parallel()
	d, err := ParseDestination("tcp:127.0.0.1:443")
	require.NoError(t, err)
	require.Equal(t, TCPDestination(LocalHostIP, 443), d)
	require.Equal(t, "tcp:127.0.0.1:443", d.String())
	require.Equal(t, "127.0.0.1:443", d.NetAddr())
	require.True(t, d.IsValid())

	d, err = ParseDestination("udp:[::1]:53")
	require.NoError(t, err)
	require.Equal(t, UDPDestination(LocalHostIPv6, 53), d)
	require.Equal(t, "udp:[::1]:53", d.String())

	d, err = ParseDestination("unix:/tmp/sock")
	require.NoError(t, err)
	require.Equal(t, Network_UNIX, d.Network)
	require.Equal(t, "unix:/tmp/sock", d.String())

	d, err = ParseDestination("example.com:80")
	require.NoError(t, err)
	require.Equal(t, Network_Unknown, d.Network)
	require.False(t, d.IsValid())
	require.Equal(t, "unknown:", d.String())
	require.Equal(t, "example.com", d.Address.Domain())

	d, err = ParseDestination("tcp::8080")
	require.NoError(t, err)
	require.Equal(t, AnyIP, d.Address)
	require.Equal(t, Port(8080), d.Port)

	_, err = ParseDestination("tcp:127.0.0.1")
	require.Error(t, err)
	_, err = ParseDestination("tcp:127.0.0.1:70000")
	require.Error(t, err)
	_, err = ParseDestination("tcp:127.0.0.1:http")
	require.Error(t, err)
}

func TestH_RawNetAddrRoundTrip(t *testing.T) {
	t.Parallel()
	tcp := TCPDestination(LocalHostIP, 80)
	require.Equal(t, &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 80}, tcp.RawNetAddr())
	require.Equal(t, tcp, DestinationFromAddr(tcp.RawNetAddr()))

	udp := UDPDestination(LocalHostIPv6, 53)
	require.Equal(t, udp, DestinationFromAddr(udp.RawNetAddr()))

	unix := UnixDestination(DomainAddress("/tmp/x"))
	require.Equal(t, &net.UnixAddr{Name: "/tmp/x", Net: "unix"}, unix.RawNetAddr())
	require.Equal(t, unix, DestinationFromAddr(unix.RawNetAddr()))

	require.Nil(t, TCPDestination(DomainAddress("example.com"), 80).RawNetAddr())
	require.Nil(t, UDPDestination(DomainAddress("example.com"), 80).RawNetAddr())
	require.Nil(t, Destination{}.RawNetAddr())
	require.Panics(t, func() { DestinationFromAddr(&net.IPAddr{}) })
}

func TestH_Port(t *testing.T) {
	t.Parallel()
	require.Equal(t, Port(0x1234), PortFromBytes([]byte{0x12, 0x34}))
	p, err := PortFromInt(65535)
	require.NoError(t, err)
	require.Equal(t, uint16(65535), p.Value())
	_, err = PortFromInt(65536)
	require.Error(t, err)
	p, err = PortFromString("443")
	require.NoError(t, err)
	require.Equal(t, "443", p.String())
	for _, invalid := range []string{"", "-1", "abc", "65536", "99999999999"} {
		_, err = PortFromString(invalid)
		require.Error(t, err, invalid)
	}
	r := MemoryPortRange{From: 10, To: 20}
	require.True(t, r.Contains(10))
	require.True(t, r.Contains(20))
	require.False(t, r.Contains(9))
	require.False(t, r.Contains(21))
}

func TestH_Network(t *testing.T) {
	t.Parallel()
	require.Equal(t, "tcp", Network_TCP.SystemString())
	require.Equal(t, "udp", Network_UDP.SystemString())
	require.Equal(t, "unix", Network_UNIX.SystemString())
	require.Equal(t, "unknown", Network_Unknown.SystemString())
	require.True(t, HasNetwork([]Network{Network_TCP, Network_UDP}, Network_UDP))
	require.False(t, HasNetwork([]Network{Network_TCP}, Network_UDP))
	require.False(t, HasNetwork(nil, Network_TCP))
}
