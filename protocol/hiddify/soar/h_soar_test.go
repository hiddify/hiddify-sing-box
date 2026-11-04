package soar

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/getlantern/soar"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

const testZone = "t.example.com"

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return pub, priv
}

func newTestOutbound(t *testing.T, options option.SoarOptions) *Outbound {
	t.Helper()
	out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "soar-out", options)
	require.NoError(t, err)
	t.Cleanup(func() { out.(*Outbound).Close() })
	return out.(*Outbound)
}

func TestH_SoarParsePublicKey(t *testing.T) {
	t.Parallel()
	pub, _ := testKey(t)
	for _, form := range []string{
		base64.StdEncoding.EncodeToString(pub),
		base64.RawStdEncoding.EncodeToString(pub),
		base64.URLEncoding.EncodeToString(pub),
		base64.RawURLEncoding.EncodeToString(pub),
		hex.EncodeToString(pub),
		" " + base64.StdEncoding.EncodeToString(pub) + "\n",
	} {
		key, err := ParsePublicKey(form)
		require.NoError(t, err, form)
		require.Equal(t, pub, key)
	}
	for _, bad := range []string{"", "not a key", base64.StdEncoding.EncodeToString(pub[:16])} {
		_, err := ParsePublicKey(bad)
		require.Error(t, err, bad)
	}
}

func TestH_SoarNewOutbound(t *testing.T) {
	t.Parallel()
	pub, _ := testKey(t)
	key := base64.StdEncoding.EncodeToString(pub)

	// resolvers written: the smart pool (on by default) carries them, no discovery
	out := newTestOutbound(t, option.SoarOptions{Domain: testZone + ".", PublicKey: key, Resolvers: []string{"8.8.8.8", "dot://1.1.1.1:853"}})
	require.Equal(t, C.TypeSoar, out.Type())
	require.Equal(t, []string{N.NetworkTCP}, out.Network())
	require.Equal(t, "Soar", out.DisplayType())
	require.NotNil(t, out.pool)
	require.False(t, out.discover)
	cfg := out.Config()
	require.Equal(t, testZone, cfg.Zone)
	require.Equal(t, []string{out.pool.Addr()}, cfg.Resolvers)
	require.False(t, cfg.Discovery.Enabled)
	require.Equal(t, "off", cfg.TCP)
	require.Equal(t, 128, cfg.MaxPathWindow)
	require.Len(t, out.candidates, 2)
	require.Equal(t, defaultConnectTimeout, out.connectTimeout)
	require.Equal(t, "www.google.com", out.options.PreTestDomain)

	// no resolvers, or "auto" alone: Soar's own discovery, no pool
	for _, resolvers := range [][]string{nil, {"auto"}} {
		out = newTestOutbound(t, option.SoarOptions{Domain: testZone, PublicKey: key, Resolvers: resolvers, SmartPool: &option.SmartPoolOptions{Enabled: true, Discovery: &option.ResolverDiscoveryOptions{Country: "ir", SampleRanges: 8, Want: 4}}})
		require.Nil(t, out.pool)
		cfg = out.Config()
		require.Empty(t, cfg.Resolvers)
		require.True(t, cfg.Discovery.Enabled)
		require.Equal(t, "ir", cfg.Discovery.Country)
		require.Equal(t, 8, cfg.Discovery.SampleRanges)
		require.Equal(t, 4, cfg.Discovery.Want)
	}

	// resolvers and "auto": the pool for the written ones, discovery besides
	out = newTestOutbound(t, option.SoarOptions{Domain: testZone, PublicKey: key, Resolvers: []string{"8.8.8.8", "auto"}})
	require.NotNil(t, out.pool)
	require.True(t, out.discover)
	cfg = out.Config()
	require.Equal(t, []string{out.pool.Addr()}, cfg.Resolvers)
	require.True(t, cfg.Discovery.Enabled)
	require.Equal(t, "", cfg.TCP)
	require.Equal(t, 0, cfg.MaxPathWindow)

	// smart_pool off: every resolver is a path of the client's own
	out = newTestOutbound(t, option.SoarOptions{Domain: testZone, PublicKey: key, Resolvers: []string{"8.8.8.8", "1.1.1.1:5353", "[2001:db8::1]"}, SmartPool: &option.SmartPoolOptions{}, TCP: "ON", MaxPathWindow: 16})
	require.Nil(t, out.pool)
	cfg = out.Config()
	require.Equal(t, []string{"8.8.8.8:53", "1.1.1.1:5353", "[2001:db8::1]:53"}, cfg.Resolvers)
	require.False(t, cfg.Discovery.Enabled)
	require.Equal(t, "on", cfg.TCP)
	require.Equal(t, 16, cfg.MaxPathWindow)
}

func TestH_SoarNewOutboundValidation(t *testing.T) {
	t.Parallel()
	pub, _ := testKey(t)
	key := base64.StdEncoding.EncodeToString(pub)
	off := &option.SmartPoolOptions{}
	cases := map[string]option.SoarOptions{
		"domain":       {PublicKey: key},
		"domain label": {Domain: "t..example.com", PublicKey: key},
		"key":          {Domain: testZone},
		"short key":    {Domain: testZone, PublicKey: "AAAA"},
		"tcp":          {Domain: testZone, PublicKey: key, TCP: "maybe"},
		"pool quic":    {Domain: testZone, PublicKey: key, Resolvers: []string{"quic://1.1.1.1"}},
		"no pool doh":  {Domain: testZone, PublicKey: key, Resolvers: []string{"https://dns.google/dns-query"}, SmartPool: off},
		"no pool bad":  {Domain: testZone, PublicKey: key, Resolvers: []string{"not an ip"}, SmartPool: off},
	}
	for name, options := range cases {
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "soar-out", options)
		require.Error(t, err, name)
	}
}

// startSoarServer runs a Soar server on the loopback whose streams all reach target.
func startSoarServer(t *testing.T, priv ed25519.PrivateKey, target string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = soar.Serve(ctx, pc, soar.ServerConfig{
			Zone:       testZone,
			PrivateKey: priv,
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", target)
			},
		})
	}()
	t.Cleanup(func() {
		cancel()
		pc.Close()
		<-done
	})
	return pc.LocalAddr().String()
}

// startEcho runs a TCP echo server.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// startRelay runs a recursive resolver stand-in: it answers found.test, and forwards every
// other query to the Soar server, the authority for the tunnel zone.
func startRelay(t *testing.T, authority string) string {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == "found.test." {
			m := new(dns.Msg)
			m.SetReply(r)
			rr, _ := dns.NewRR("found.test. 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
			_ = w.WriteMsg(m)
			return
		}
		client := &dns.Client{Net: "udp", UDPSize: 4096, Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(r, authority)
		if err != nil {
			return
		}
		_ = w.WriteMsg(resp)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: pc, Handler: handler, UDPSize: 4096}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return pc.LocalAddr().String()
}

func echoThrough(t *testing.T, out *Outbound) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	defer conn.Close()
	message := []byte("hello through soar")
	_, err = conn.Write(message)
	require.NoError(t, err)
	reply := make([]byte, len(message))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(20*time.Second)))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, message, reply)
	require.Equal(t, adapter.StatusReady, out.Status())
}

// The outbound carries a connection through a Soar server, the server as the client's resolver.
func TestH_SoarEndToEnd(t *testing.T) {
	t.Parallel()
	pub, priv := testKey(t)
	server := startSoarServer(t, priv, startEcho(t))
	out := newTestOutbound(t, option.SoarOptions{
		Domain:    testZone,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Resolvers: []string{server},
		SmartPool: &option.SmartPoolOptions{},
	})
	require.NoError(t, out.PreStart())
	require.NoError(t, out.PostStart())
	echoThrough(t, out)
	require.Contains(t, out.DisplayType(), "1 resolvers")
}

// The same through the smart pool: the resolver passes the probe and joins the pool, and the
// client's queries go through it.
func TestH_SoarEndToEndSmartPool(t *testing.T) {
	t.Parallel()
	pub, priv := testKey(t)
	relay := startRelay(t, startSoarServer(t, priv, startEcho(t)))
	out := newTestOutbound(t, option.SoarOptions{
		Domain:        testZone,
		PublicKey:     base64.StdEncoding.EncodeToString(pub),
		Resolvers:     []string{"127.0.0.1:1", relay},
		PreTestDomain: "found.test",
	})
	require.NoError(t, out.PreStart())
	require.NoError(t, out.PostStart())
	echoThrough(t, out)
	require.Equal(t, 1, out.PoolResolvers())
}

// Datagrams to the pool go through the loopback socket, the rest through the outside one, and
// replies from both are read.
func TestH_SoarSplitPacketConn(t *testing.T) {
	t.Parallel()
	echoUDP := func() *net.UDPConn {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		go func() {
			buffer := make([]byte, 1500)
			for {
				n, addr, err := conn.ReadFrom(buffer)
				if err != nil {
					return
				}
				_ = n
				_, _ = conn.WriteTo([]byte(addr.String()), addr) // who sent it
			}
		}()
		return conn
	}
	pool, other := echoUDP(), echoUDP()
	var outside net.PacketConn
	conn, err := newSplitPacketConn(context.Background(), pool.LocalAddr().(*net.UDPAddr), func(ctx context.Context) (net.PacketConn, error) {
		var err error
		outside, err = net.ListenPacket("udp", "127.0.0.1:0")
		return outside, err
	})
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, outside.LocalAddr(), conn.LocalAddr())

	seen := map[string]string{}
	for _, target := range []*net.UDPConn{pool, other} {
		_, err := conn.WriteTo([]byte(target.LocalAddr().String()), target.LocalAddr())
		require.NoError(t, err)
	}
	buffer := make([]byte, 1500)
	for range 2 {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, addr, err := conn.ReadFrom(buffer)
		require.NoError(t, err)
		seen[addr.String()] = string(buffer[:n])
	}
	// the pool saw the loopback socket, the other resolver the outside one
	require.NotEmpty(t, seen[pool.LocalAddr().String()])
	require.NotEqual(t, outside.LocalAddr().String(), seen[pool.LocalAddr().String()])
	require.Equal(t, outside.LocalAddr().String(), seen[other.LocalAddr().String()])

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err = conn.ReadFrom(buffer)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, conn.Close())
	_, _, err = conn.ReadFrom(buffer)
	require.ErrorIs(t, err, net.ErrClosed)
}
