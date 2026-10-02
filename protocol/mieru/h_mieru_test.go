package mieru

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestH_MieruEnumHelpers(t *testing.T) {
	t.Parallel()
	require.Equal(t, mierupb.TransportProtocol_TCP, *getTransportProtocol("tcp"))
	require.Equal(t, mierupb.TransportProtocol_UDP, *getTransportProtocol("Udp"))
	require.Nil(t, getTransportProtocol("quic"))
	require.Nil(t, getTransportProtocol(""))

	for in, want := range map[string]mierupb.HandshakeMode{
		"":                  mierupb.HandshakeMode_HANDSHAKE_DEFAULT,
		"default":           mierupb.HandshakeMode_HANDSHAKE_DEFAULT,
		"no_wait":           mierupb.HandshakeMode_HANDSHAKE_NO_WAIT,
		"NOWAIT":            mierupb.HandshakeMode_HANDSHAKE_NO_WAIT,
		"standard":          mierupb.HandshakeMode_HANDSHAKE_STANDARD,
		"HANDSHAKE_NO_WAIT": mierupb.HandshakeMode_HANDSHAKE_NO_WAIT,
	} {
		got := getHandshakeMode(in)
		require.NotNil(t, got, in)
		require.Equal(t, want, *got, in)
	}
	require.Nil(t, getHandshakeMode("fast"))

	for in, want := range map[string]mierupb.MultiplexingLevel{
		"":                    mierupb.MultiplexingLevel_MULTIPLEXING_DEFAULT,
		"low":                 mierupb.MultiplexingLevel_MULTIPLEXING_LOW,
		"medium":              mierupb.MultiplexingLevel_MULTIPLEXING_MIDDLE,
		"MIDDLE":              mierupb.MultiplexingLevel_MULTIPLEXING_MIDDLE,
		"high":                mierupb.MultiplexingLevel_MULTIPLEXING_HIGH,
		"MULTIPLEXING_HIGH":   mierupb.MultiplexingLevel_MULTIPLEXING_HIGH,
		"multiplexing_middle": mierupb.MultiplexingLevel_MULTIPLEXING_MIDDLE,
	} {
		got := getMultiplexingLevel(in)
		require.NotNil(t, got, in)
		require.Equal(t, want, *got, in)
	}
	require.Nil(t, getMultiplexingLevel("extreme"))
}

func TestH_MieruValidateTransport(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      []option.MieruPortBinding
		wantErr string
	}{
		{"empty", nil, ""},
		{"tcp port", []option.MieruPortBinding{{Protocol: "TCP", Port: 8080}}, ""},
		{"udp range", []option.MieruPortBinding{{Protocol: "udp", PortRange: "1000-2000"}}, ""},
		{"single-port range", []option.MieruPortBinding{{Protocol: "tcp", PortRange: "443-443"}}, ""},
		{"bad protocol", []option.MieruPortBinding{{Protocol: "sctp", Port: 1}}, "TCP or UDP"},
		{"both set", []option.MieruPortBinding{{Protocol: "tcp", Port: 1, PortRange: "1-2"}}, "should not be set"},
		{"none set", []option.MieruPortBinding{{Protocol: "tcp"}}, "must be set"},
		{"garbage range", []option.MieruPortBinding{{Protocol: "tcp", PortRange: "abc"}}, "invalid server_ports"},
		{"begin zero", []option.MieruPortBinding{{Protocol: "tcp", PortRange: "0-10"}}, "begin port"},
		{"end too big", []option.MieruPortBinding{{Protocol: "tcp", PortRange: "10-70000"}}, "end port"},
		{"reversed", []option.MieruPortBinding{{Protocol: "tcp", PortRange: "200-100"}}, "less than or equal"},
		{"second entry invalid", []option.MieruPortBinding{{Protocol: "tcp", Port: 1}, {Protocol: "x", Port: 2}}, "TCP or UDP"},
	}
	for _, tc := range cases {
		err := validateMieruTransport(tc.in)
		if tc.wantErr == "" {
			require.NoError(t, err, tc.name)
		} else {
			require.ErrorContains(t, err, tc.wantErr, tc.name)
		}
	}
}

func validMieruOutboundOptions() option.MieruOutboundOptions {
	return option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1"},
		PortBindings:  []option.MieruPortBinding{{Protocol: "TCP", Port: 8964}},
		UserName:      "user",
		Password:      "pass",
	}
}

func TestH_MieruOutboundOptionsValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(o *option.MieruOutboundOptions)
		wantErr string
	}{
		{"valid", func(o *option.MieruOutboundOptions) {}, ""},
		{"empty server", func(o *option.MieruOutboundOptions) { o.Server = "" }, "server is empty"},
		{"no port", func(o *option.MieruOutboundOptions) { o.PortBindings = nil }, "either server_port or transport"},
		{"server_port matches binding", func(o *option.MieruOutboundOptions) { o.ServerPort = 8964 }, ""},
		{"server_port mismatch", func(o *option.MieruOutboundOptions) { o.ServerPort = 1 }, "Transport of Server Port"},
		{"server_port with two bindings", func(o *option.MieruOutboundOptions) {
			o.ServerPort = 8964
			o.PortBindings = append(o.PortBindings, option.MieruPortBinding{Protocol: "UDP", Port: 8964})
		}, "Transport of Server Port"},
		{"empty username", func(o *option.MieruOutboundOptions) { o.UserName = "" }, "username is empty"},
		{"empty password", func(o *option.MieruOutboundOptions) { o.Password = "" }, "password is empty"},
		{"bad multiplexing", func(o *option.MieruOutboundOptions) { o.Multiplexing = "huge" }, "invalid multiplexing level"},
		{"bad handshake", func(o *option.MieruOutboundOptions) { o.HandshakeMode = "slow" }, "invalid handshake mode"},
		{"bad transport", func(o *option.MieruOutboundOptions) { o.PortBindings[0].Protocol = "icmp" }, "TCP or UDP"},
	}
	for _, tc := range cases {
		opts := validMieruOutboundOptions()
		tc.mutate(&opts)
		err := validateMieruOptions(opts)
		if tc.wantErr == "" {
			require.NoError(t, err, tc.name)
		} else {
			require.ErrorContains(t, err, tc.wantErr, tc.name)
		}
	}
}

func TestH_MieruBuildClientConfig(t *testing.T) {
	t.Parallel()
	opts := validMieruOutboundOptions()
	opts.PortBindings = []option.MieruPortBinding{
		{Protocol: "tcp", Port: 8964},
		{Protocol: "udp", PortRange: "9000-9010"},
	}
	opts.Multiplexing = "MULTIPLEXING_HIGH"
	opts.HandshakeMode = "no_wait"
	config, err := buildMieruClientConfig(opts, mieruDialer{})
	require.NoError(t, err)
	profile := config.Profile
	require.Equal(t, "user", profile.GetUser().GetName())
	require.Equal(t, "pass", profile.GetUser().GetPassword())
	require.Len(t, profile.GetServers(), 1)
	server := profile.GetServers()[0]
	require.Equal(t, "127.0.0.1", server.GetIpAddress())
	require.Empty(t, server.GetDomainName())
	require.Len(t, server.GetPortBindings(), 2)
	require.Equal(t, int32(8964), server.GetPortBindings()[0].GetPort())
	require.Equal(t, mierupb.TransportProtocol_TCP, server.GetPortBindings()[0].GetProtocol())
	require.Equal(t, "9000-9010", server.GetPortBindings()[1].GetPortRange())
	require.Equal(t, mierupb.TransportProtocol_UDP, server.GetPortBindings()[1].GetProtocol())
	require.Equal(t, mierupb.MultiplexingLevel_MULTIPLEXING_HIGH, profile.GetMultiplexing().GetLevel())
	require.Equal(t, mierupb.HandshakeMode_HANDSHAKE_NO_WAIT, profile.GetHandshakeMode())
	require.True(t, config.DNSConfig.BypassDialerDNS)
	require.NoError(t, mieruclient.NewClient().Store(config))

	opts.Server = "example.com"
	opts.Multiplexing = "low"
	config, err = buildMieruClientConfig(opts, mieruDialer{})
	require.NoError(t, err)
	require.Equal(t, "example.com", config.Profile.GetServers()[0].GetDomainName())
	require.Empty(t, config.Profile.GetServers()[0].GetIpAddress())
	require.Equal(t, mierupb.MultiplexingLevel_MULTIPLEXING_LOW, config.Profile.GetMultiplexing().GetLevel())

	opts.UserName = ""
	_, err = buildMieruClientConfig(opts, mieruDialer{})
	require.ErrorContains(t, err, "username is empty")
}

func TestH_MieruInboundOptionsValidation(t *testing.T) {
	t.Parallel()
	valid := func() option.MieruInboundOptions {
		return option.MieruInboundOptions{
			Users:        []option.MieruUser{{Name: "u", Password: "p"}},
			PortBindings: []option.MieruPortBinding{{Protocol: "TCP", Port: 8964}},
		}
	}
	cases := []struct {
		name    string
		mutate  func(o *option.MieruInboundOptions)
		wantErr string
	}{
		{"valid", func(o *option.MieruInboundOptions) {}, ""},
		{"no ports", func(o *option.MieruInboundOptions) { o.PortBindings = nil }, "either server_port or transport"},
		{"listen_port matches", func(o *option.MieruInboundOptions) { o.ListenPort = 8964 }, ""},
		{"listen_port mismatch", func(o *option.MieruInboundOptions) { o.ListenPort = 1 }, "Transport of Server Port"},
		{"no users", func(o *option.MieruInboundOptions) { o.Users = nil }, "users is empty"},
		{"empty username", func(o *option.MieruInboundOptions) { o.Users[0].Name = "" }, "username is empty"},
		{"empty password", func(o *option.MieruInboundOptions) { o.Users[0].Password = "" }, "password is empty"},
		{"bad range", func(o *option.MieruInboundOptions) {
			o.PortBindings = []option.MieruPortBinding{{Protocol: "TCP", PortRange: "5-1"}}
		}, "less than or equal"},
	}
	for _, tc := range cases {
		opts := valid()
		tc.mutate(&opts)
		_, _, err := buildMieruServerConfig(context.Background(), opts)
		if tc.wantErr == "" {
			require.NoError(t, err, tc.name)
		} else {
			require.ErrorContains(t, err, tc.wantErr, tc.name)
		}
	}
}

func TestH_MieruBuildServerConfig(t *testing.T) {
	t.Parallel()
	config, names, err := buildMieruServerConfig(context.Background(), option.MieruInboundOptions{
		Users: []option.MieruUser{{Name: "alice", Password: "a"}, {Name: "bob", Password: "b"}},
		PortBindings: []option.MieruPortBinding{
			{Protocol: "TCP", Port: 8964},
			{Protocol: "UDP", PortRange: "9000-9001"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"alice", "bob"}, names)
	bindings := config.Config.GetPortBindings()
	require.Len(t, bindings, 2)
	require.Equal(t, int32(8964), bindings[0].GetPort())
	require.Equal(t, mierupb.TransportProtocol_TCP, bindings[0].GetProtocol())
	require.Equal(t, "9000-9001", bindings[1].GetPortRange())
	require.Equal(t, mierupb.TransportProtocol_UDP, bindings[1].GetProtocol())
	require.Len(t, config.Config.GetUsers(), 2)
	require.Equal(t, "bob", config.Config.GetUsers()[1].GetName())
	require.NoError(t, mieruserver.NewServer().Store(config))
}

func TestH_MieruSocksAddrToNetAddrSpec(t *testing.T) {
	t.Parallel()
	nas, err := socksAddrToNetAddrSpec(M.ParseSocksaddr("1.2.3.4:80"), "udp")
	require.NoError(t, err)
	require.Equal(t, "udp", nas.Net)
	require.Equal(t, 80, nas.Port)
	require.True(t, nas.IP.Equal(net.IPv4(1, 2, 3, 4)))

	nas, err = socksAddrToNetAddrSpec(M.ParseSocksaddr("example.com:443"), "tcp")
	require.NoError(t, err)
	require.Equal(t, "tcp", nas.Net)
	require.Equal(t, "example.com", nas.FQDN)
	require.Equal(t, 443, nas.Port)
}

type chanPacketConn struct {
	net.PacketConn
	ch chan []byte
}

func (c *chanPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.ch <- append([]byte(nil), p...)
	return len(p), nil
}

func (c *chanPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	data, ok := <-c.ch
	if !ok {
		return 0, nil, io.EOF
	}
	return copy(p, data), nil, nil
}

func TestH_MieruPacketConnRoundTrip(t *testing.T) {
	t.Parallel()
	pc := &mieruPacketConn{PacketConn: &chanPacketConn{ch: make(chan []byte, 4)}}
	for _, dest := range []M.Socksaddr{
		M.ParseSocksaddr("8.8.8.8:53"),
		M.ParseSocksaddr("[2001:db8::1]:443"),
		M.ParseSocksaddr("example.org:1234"),
	} {
		payload := buf.As([]byte("hello mieru"))
		require.NoError(t, pc.WritePacket(payload, dest))
		out := buf.NewPacket()
		got, err := pc.ReadPacket(out)
		require.NoError(t, err)
		require.Equal(t, dest, got)
		require.Equal(t, "hello mieru", string(out.Bytes()))
		out.Release()
	}

	short := &mieruPacketConn{PacketConn: &chanPacketConn{ch: make(chan []byte, 1)}}
	short.PacketConn.(*chanPacketConn).ch <- []byte{0, 0}
	out := buf.NewPacket()
	defer out.Release()
	_, err := short.ReadPacket(out)
	require.ErrorIs(t, err, io.ErrShortBuffer)
}

func TestH_MieruStreamer(t *testing.T) {
	t.Parallel()
	remote := M.ParseSocksaddr("1.1.1.1:53")
	s := &streamer{PacketConn: &chanPacketConn{ch: make(chan []byte, 1)}, Remote: remote}
	n, err := s.Write([]byte("ping"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	b := make([]byte, 16)
	n, err = s.Read(b)
	require.NoError(t, err)
	require.Equal(t, "ping", string(b[:n]))
	require.Equal(t, remote, s.RemoteAddr())
}

type echoRouter struct {
	adapter.Router
	mu       sync.Mutex
	metadata []adapter.InboundContext
}

func (r *echoRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.RouteConnectionEx(ctx, conn, metadata, nil)
	return nil
}

func (r *echoRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return conn.Close()
}

func (r *echoRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.mu.Lock()
	r.metadata = append(r.metadata, metadata)
	r.mu.Unlock()
	go func() {
		_, _ = io.Copy(conn, conn)
		conn.Close()
	}()
}

func (r *echoRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	conn.Close()
}

func freeTCPPort(t *testing.T) uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return uint16(port)
}

func TestH_MieruLoopbackRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	logger := log.NewNOPFactory().Logger()
	port := freeTCPPort(t)
	router := &echoRouter{}

	in, err := NewInbound(ctx, router, logger, "mieru-in", option.MieruInboundOptions{
		Users:        []option.MieruUser{{Name: "alice", Password: "secret"}},
		PortBindings: []option.MieruPortBinding{{Protocol: "TCP", Port: port}},
	})
	require.NoError(t, err)
	require.NoError(t, in.Start(adapter.StartStateStart))
	defer in.Close()

	out, err := NewOutbound(ctx, router, logger, "mieru-out", option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1"},
		PortBindings:  []option.MieruPortBinding{{Protocol: "TCP", Port: port}},
		UserName:      "alice",
		Password:      "secret",
	})
	require.NoError(t, err)
	defer out.(*Outbound).Close()

	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("10.0.0.1:4242"))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("round trip"))
	require.NoError(t, err)
	reply := make([]byte, len("round trip"))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "round trip", string(reply))

	router.mu.Lock()
	defer router.mu.Unlock()
	require.Len(t, router.metadata, 1)
	md := router.metadata[0]
	require.Equal(t, "mieru-in", md.Inbound)
	require.Equal(t, "alice", md.User)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), md.Destination.Addr)
	require.Equal(t, uint16(4242), md.Destination.Port)

	_, err = out.DialContext(ctx, "icmp", M.ParseSocksaddr("10.0.0.1:1"))
	require.Error(t, err)
}
