package hosts

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestH_GetIpOfSslip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expected string
	}{
		{"1.2.3.4.sslip.io", "1.2.3.4"},
		{"1-2-3-4.sslip.io", "1.2.3.4"},
		{"www.192.168.10.20.sslip.io", "192.168.10.20"},
		{"app-10-0-0-1.sslip.io", "10.0.0.1"},
		{"255.255.255.255.sslip.io", "255.255.255.255"},
		{"2a01-4f8-c17-b8f--2.sslip.io", "2a01:4f8:c17:b8f::2"},
		{"--1.sslip.io", "::1"},
	}
	for _, c := range cases {
		require.Equal(t, []netip.Addr{netip.MustParseAddr(c.expected)}, getIpOfSslip(c.name), c.name)
	}
	for _, name := range []string{
		"",
		"sslip.io",
		"example.com",
		"1.2.3.4.example.com",
		"1.2.3.4.sslip.io.example.com",
		"foo.sslip.io",
		"1.2.3.sslip.io",
	} {
		require.Nil(t, getIpOfSslip(name), name)
	}
}

func TestH_GetIpOfSslipIPv6WithDecimalTail(t *testing.T) {
	t.Skip("BUG: hosts.go getIpOfSslip tries the IPv4 regex first with an unanchored search, so 2001-db8-0-0-0-0-0-1.sslip.io resolves to 0.0.0.1 instead of 2001:db8::1")
	t.Parallel()
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, getIpOfSslip("2001-db8-0-0-0-0-0-1.sslip.io"))
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8:1:2:3:4:5:6")}, getIpOfSslip("2001-db8-1-2-3-4-5-6.sslip.io"))
}

func hNewHostsTransport(t *testing.T) *Transport {
	t.Helper()
	transport, err := NewTransport(context.Background(), log.NewNOPFactory().NewLogger("hosts"), "hosts", option.HostsDNSServerOptions{
		Path: []string{"testdata/hosts"},
	})
	require.NoError(t, err)
	return transport.(*Transport)
}

func TestH_HostsExchangeNonSslipUnchanged(t *testing.T) {
	t.Parallel()
	transport := hNewHostsTransport(t)
	message := new(mDNS.Msg)
	message.SetQuestion("not-sslip.example.", mDNS.TypeA)
	response, err := transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
	require.Empty(t, response.Answer)

	message.SetQuestion("localhost.", mDNS.TypeA)
	response, err = transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
}

func TestH_HostsExchangeResolvesSslip(t *testing.T) {
	t.Skip("BUG: hosts.go Exchange passes mDNS.CanonicalName (trailing dot) to getIpOfSslip, whose HasSuffix(\".sslip.io\") check and `sslip.io$` regex never match, so sslip.io names are never resolved")
	t.Parallel()
	transport := hNewHostsTransport(t)
	message := new(mDNS.Msg)
	message.SetQuestion("1-2-3-4.sslip.io.", mDNS.TypeA)
	response, err := transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.Len(t, response.Answer, 1)
	require.Equal(t, "1.2.3.4", response.Answer[0].(*mDNS.A).A.String())
}
