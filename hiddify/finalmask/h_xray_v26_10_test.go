package finalmask

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/transport/internet/finalmask/udphop"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
)

// The masks and settings of Xray-core v26.10: xdns over DoH, noise "exp" and "script", udpHop.
func TestH_FinalMaskXray2610Settings(t *testing.T) {
	for _, content := range []string{
		`{"udp":[{"type":"xdns","settings":{"domains":[{"names":["t.example.com"]}],"resolvers":[{"addrs":["https://1.1.1.1/dns-query"],"tlsConfig":{"serverName":"cloudflare-dns.com","alpn":["h2"],"fingerprint":"chrome"}}]}}]}`,
		`{"udp":[{"type":"xdns","settings":{"domains":[{"names":["t.example.com"],"types":[16]}],"resolvers":[{"addrs":["https://1.1.1.1/dns-query"],"tlsConfig":{"serverName":"cloudflare-dns.com","alpn":["h3"]},"quicConfig":{"congestion":"bbr"}}]}}]}`,
		`{"udp":[{"type":"xdns","settings":{"domains":[{"names":["t.example.com"]}],"resolvers":[{"addrs":["8.8.8.8","tcp://9.9.9.9:53"],"worker":8}],"extraPoll":2}}]}`,
		`{"udp":[{"type":"noise","settings":{"noise":[{"type":"exp","packet":"<b 0x1700> <r 10-20> <t> <c>","delay":"5"}]}}]}`,
		`{"udp":[{"type":"udphop","settings":{"mode":"intervalRemote","interval":"10-20","remotePorts":"20000-20010,443"}}]}`,
	} {
		masks, err := Build(parseOptions(t, content))
		require.NoError(t, err, content)
		require.True(t, masks.HasUDP(), content)
	}

	masks, err := Build(parseOptions(t, `{"udp":[{"type":"udphop","settings":{"mode":"perConnRemote","remotePorts":"20000-20002,443","remoteIPs":["10.0.0.1","10.1.0.0/16"]}}]}`))
	require.NoError(t, err)
	hop := masks.udp[0].(*udphop.Config)
	require.Equal(t, []uint32{20000, 20001, 20002, 443}, hop.RemotePorts)
	require.Equal(t, []string{"10.0.0.1/32", "10.1.0.0/16"}, hop.RemoteIPs)
	require.Equal(t, int64(30), hop.IntervalMin)

	for _, content := range []string{
		`{"udp":[{"type":"udphop","settings":{"mode":"sometimes"}}]}`,
		`{"udp":[{"type":"udphop","settings":{"mode":"intervalLocal","interval":"1"}}]}`,
		`{"udp":[{"type":"noise","settings":{"noise":[{"type":"exp","packet":"<zz>"}]}}]}`,
		`{"udp":[{"type":"xdns","settings":{"domains":[{"names":["t.example.com"]}],"resolvers":[{"addrs":["ftp://8.8.8.8"]}]}}]}`,
		`{"udp":[{"type":"xdns","settings":{"domains":[{"names":["t.example.com"]}],"resolvers":[{"addrs":["https://1.1.1.1/dns-query"],"tlsConfig":{"allowInsecure":true}}]}}]}`,
	} {
		_, err := Build(parseOptions(t, content))
		require.Error(t, err, content)
	}
}

// Settings of Xray v26.7 to v26.9 become the current xdns form.
func TestH_FinalMaskXDNSLegacySettings(t *testing.T) {
	for _, test := range []struct {
		content   string
		domains   []string
		resolvers []string
	}{
		{`{"resolvers":["t.example.com+udp://8.8.8.8:53","t.example.com+udp://1.1.1.1:53"]}`, []string{"t.example.com"}, []string{"8.8.8.8:53", "1.1.1.1:53"}},
		{`{"domains":["t.example.com"]}`, []string{"t.example.com"}, nil},
		{`{"domains":[{"name":"t.example.com"}],"resolvers":[{"type":"tcp","addr":"8.8.8.8:53"}]}`, []string{"t.example.com"}, []string{"8.8.8.8:53"}},
	} {
		var settings xdnsSettings
		require.NoError(t, json.Unmarshal([]byte(test.content), &settings), test.content)
		message, err := settings.Build()
		require.NoError(t, err, test.content)
		config := message.(*xdns.Config)
		var domains, resolvers []string
		for _, domain := range config.Domains {
			domains = append(domains, domain.Name)
		}
		for _, resolver := range config.Resolvers {
			resolvers = append(resolvers, resolver.Addr)
		}
		require.Equal(t, test.domains, domains, test.content)
		require.Equal(t, test.resolvers, resolvers, test.content)
	}
}

// xdns carries a UDP flow in DNS queries to its resolvers, which the mask dials itself through
// the dialer; here the server is the resolver.
func TestH_FinalMaskXDNSRoundTrip(t *testing.T) {
	rawServer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer rawServer.Close()
	serverMasks, err := Build(parseOptions(t, `{"udp":[{"type":"xdns","settings":{"domains":[{"names":["t.example.com"]}]}}]}`))
	require.NoError(t, err)
	server, err := serverMasks.WrapPacketConnServer(rawServer)
	require.NoError(t, err)
	defer server.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			server.WriteTo(buf[:n], addr)
		}
	}()

	port := M.SocksaddrFromNet(rawServer.LocalAddr()).Port
	clientMasks, err := Build(parseOptions(t, `{"udp":[{"type":"xdns","settings":{"domains":[{"names":["t.example.com"]}],"resolvers":[{"addrs":["udp://127.0.0.1:`+strconv.Itoa(int(port))+`"],"worker":2}]}}]}`))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var resolverDials, otherDials atomic.Int32
	count := func(destination M.Socksaddr) {
		if destination.Port == port {
			resolverDials.Add(1)
		} else {
			otherDials.Add(1)
		}
	}
	conn, err := clientMasks.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr("192.0.2.1:443"), func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		count(destination)
		return N.SystemDialer.DialContext(ctx, network, destination)
	}, func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
		count(destination)
		return N.SystemDialer.ListenPacket(ctx, destination)
	})
	require.NoError(t, err)
	defer conn.Close()

	payload := []byte("hello over xdns")
	got := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, err = conn.Write(payload)
		require.NoError(t, err)
		n, err := conn.Read(got)
		require.NoError(t, err)
		if n == len(payload) {
			require.Equal(t, payload, got[:n])
			break
		}
	}
	require.Positive(t, resolverDials.Load(), "the resolvers are dialed through the dialer")
	require.Zero(t, otherDials.Load(), "nothing is dialed to the destination itself")
}

// udphop sends to the server ports it picks: one per connection with perConnRemote, and a new one
// on every hop with intervalRemote, on the same unconnected socket.
func TestH_FinalMaskUDPHop(t *testing.T) {
	var ports []string
	received := make(chan uint16, 64)
	for range 3 {
		server, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer server.Close()
		port := M.SocksaddrFromNet(server.LocalAddr()).Port
		ports = append(ports, strconv.Itoa(int(port)))
		go func() {
			buf := make([]byte, 2048)
			for {
				n, addr, err := server.ReadFrom(buf)
				if err != nil {
					return
				}
				received <- port
				server.WriteTo(buf[:n], addr)
			}
		}()
	}
	exchange := func(conn net.Conn) uint16 {
		t.Helper()
		_, err := conn.Write([]byte("hop"))
		require.NoError(t, err)
		got := make([]byte, 16)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(got)
		require.NoError(t, err)
		require.Equal(t, "hop", string(got[:n]))
		return <-received
	}
	ctx := context.Background()
	destination := M.ParseSocksaddr("127.0.0.1:9")

	masks, err := Build(parseOptions(t, `{"udp":[{"type":"udphop","settings":{"mode":"perConnRemote","remotePorts":"`+strings.Join(ports, ",")+`"}}]}`))
	require.NoError(t, err)
	seen := map[uint16]bool{}
	for range 20 {
		conn, err := dial(ctx, masks, N.NetworkUDP, destination)
		require.NoError(t, err)
		seen[exchange(conn)] = true
		conn.Close()
	}
	require.Greater(t, len(seen), 1, "connections go to different server ports")

	masks, err = Build(parseOptions(t, `{"udp":[{"type":"udphop","settings":{"mode":"intervalRemote","interval":"5","remotePorts":"`+strings.Join(ports, ",")+`"}}]}`))
	require.NoError(t, err)
	conn, err := dial(ctx, masks, N.NetworkUDP, destination)
	require.NoError(t, err)
	defer conn.Close()
	first := exchange(conn)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		if exchange(conn) != first {
			return
		}
	}
	t.Fatal("the connection never hopped to another server port")
}
