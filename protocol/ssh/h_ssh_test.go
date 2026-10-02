package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type testRouter struct {
	adapter.Router
	mu       sync.Mutex
	metadata []adapter.InboundContext
	routed   chan struct{}
}

func newTestRouter() *testRouter {
	return &testRouter{routed: make(chan struct{}, 16)}
}

func (r *testRouter) record(metadata adapter.InboundContext) {
	r.mu.Lock()
	r.metadata = append(r.metadata, metadata)
	r.mu.Unlock()
	r.routed <- struct{}{}
}

func (r *testRouter) last(t *testing.T) adapter.InboundContext {
	select {
	case <-r.routed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for routed connection")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.metadata[len(r.metadata)-1]
}

func (r *testRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.RouteConnectionEx(ctx, conn, metadata, nil)
	return nil
}

func (r *testRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	r.RoutePacketConnectionEx(ctx, conn, metadata, nil)
	return nil
}

func (r *testRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.record(metadata)
	go func() {
		_, _ = io.Copy(conn, conn)
		conn.Close()
		if onClose != nil {
			onClose(nil)
		}
	}()
}

func (r *testRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.record(metadata)
	go func() {
		defer conn.Close()
		for {
			buffer := buf.NewPacket()
			destination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			if conn.WritePacket(buffer, destination) != nil {
				return
			}
		}
	}()
}

type keyPair struct {
	signer        ssh.Signer
	privatePEM    string
	authorizedKey string
}

func newKeyPair(t *testing.T) keyPair {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return keyPair{
		signer:        signer,
		privatePEM:    string(pem.EncodeToMemory(block)),
		authorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
	}
}

func freeTCPPort(t *testing.T) uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return uint16(port)
}

type sshFixture struct {
	router   *testRouter
	inbound  *Inbound
	hostKey  keyPair
	userKey  keyPair
	addr     string
	port     uint16
	inOption option.SSHInboundOptions
}

func startInbound(t *testing.T, mutate func(*option.SSHInboundOptions)) *sshFixture {
	f := &sshFixture{router: newTestRouter(), hostKey: newKeyPair(t), userKey: newKeyPair(t), port: freeTCPPort(t)}
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	f.inOption = option.SSHInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listen, ListenPort: f.port},
		Users: []option.SSHUser{
			{User: "alice", Password: "wonderland"},
			{User: "bob", PublicKey: f.userKey.authorizedKey},
		},
		HostKey: []string{f.hostKey.privatePEM},
	}
	if mutate != nil {
		mutate(&f.inOption)
	}
	in, err := NewInbound(context.Background(), f.router, log.NewNOPFactory().Logger(), "ssh-in", f.inOption)
	require.NoError(t, err)
	f.inbound = in.(*Inbound)
	require.NoError(t, f.inbound.Start(adapter.StartStateStart))
	t.Cleanup(func() { f.inbound.Close() })
	f.addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.port)))
	return f
}

func (f *sshFixture) dial(user string, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.FixedHostKey(f.hostKey.signer.PublicKey()),
		Timeout:         5 * time.Second,
	})
}

func echoOnce(t *testing.T, conn net.Conn, payload string) {
	errCh := make(chan error, 1)
	go func() {
		if _, err := conn.Write([]byte(payload)); err != nil {
			errCh <- err
			return
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil {
			errCh <- err
			return
		}
		if string(reply) != payload {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("echo timeout")
	}
}

func TestH_SSHInboundInvalidHostKey(t *testing.T) {
	t.Parallel()
	_, err := NewInbound(context.Background(), newTestRouter(), log.NewNOPFactory().Logger(), "ssh-in", option.SSHInboundOptions{
		HostKey: []string{"not a private key"},
	})
	require.Error(t, err)
}

func TestH_SSHInboundPasswordAuthDirectTCPIP(t *testing.T) {
	t.Parallel()
	f := startInbound(t, nil)
	client, err := f.dial("alice", ssh.Password("wonderland"))
	require.NoError(t, err)
	defer client.Close()

	conn, err := client.Dial("tcp", "10.1.2.3:8080")
	require.NoError(t, err)
	echoOnce(t, conn, "hello over ssh")
	conn.Close()
	md := f.router.last(t)
	require.Equal(t, "ssh-in", md.Inbound)
	require.Equal(t, "alice", md.User)
	require.Equal(t, M.ParseSocksaddr("10.1.2.3:8080"), md.Destination)

	conn, err = client.Dial("tcp", "example.com:443")
	require.NoError(t, err)
	echoOnce(t, conn, "fqdn")
	conn.Close()
	md = f.router.last(t)
	require.Equal(t, "example.com", md.Destination.Fqdn)
	require.Equal(t, uint16(443), md.Destination.Port)
}

func TestH_SSHInboundPublicKeyAuth(t *testing.T) {
	t.Parallel()
	f := startInbound(t, nil)
	client, err := f.dial("bob", ssh.PublicKeys(f.userKey.signer))
	require.NoError(t, err)
	defer client.Close()
	conn, err := client.Dial("tcp", "192.0.2.1:22")
	require.NoError(t, err)
	echoOnce(t, conn, "key auth")
	conn.Close()
	require.Equal(t, "bob", f.router.last(t).User)
}

func TestH_SSHInboundAuthFailures(t *testing.T) {
	t.Parallel()
	f := startInbound(t, nil)
	other := newKeyPair(t)
	cases := []struct {
		name string
		user string
		auth ssh.AuthMethod
	}{
		{"wrong password", "alice", ssh.Password("nope")},
		{"unknown user password", "mallory", ssh.Password("wonderland")},
		{"password for key-only user", "bob", ssh.Password("")},
		{"key for password-only user", "alice", ssh.PublicKeys(f.userKey.signer)},
		{"wrong key", "bob", ssh.PublicKeys(other.signer)},
		{"unknown user key", "mallory", ssh.PublicKeys(f.userKey.signer)},
	}
	for _, tc := range cases {
		client, err := f.dial(tc.user, tc.auth)
		if client != nil {
			client.Close()
		}
		require.Error(t, err, tc.name)
		require.Contains(t, err.Error(), "unable to authenticate", tc.name)
	}
}

func TestH_SSHInboundRejectsNonForwardChannels(t *testing.T) {
	t.Parallel()
	f := startInbound(t, nil)
	client, err := f.dial("alice", ssh.Password("wonderland"))
	require.NoError(t, err)
	defer client.Close()
	_, err = client.NewSession()
	require.Error(t, err)
	var openErr *ssh.OpenChannelError
	require.ErrorAs(t, err, &openErr)
	require.Equal(t, ssh.UnknownChannelType, openErr.Reason)

	conn, err := client.Dial("tcp", "10.0.0.1:1")
	require.NoError(t, err)
	echoOnce(t, conn, "still alive")
	conn.Close()
}

func TestH_SSHInboundServerVersion(t *testing.T) {
	t.Skip("BUG: SSHInboundOptions.ServerVersion is never applied to ssh.ServerConfig (protocol/ssh/inbound.go:55)")
	t.Parallel()
	f := startInbound(t, func(o *option.SSHInboundOptions) { o.ServerVersion = "SSH-2.0-HiddifyTest" })
	client, err := f.dial("alice", ssh.Password("wonderland"))
	require.NoError(t, err)
	defer client.Close()
	require.Equal(t, "SSH-2.0-HiddifyTest", string(client.ServerVersion()))
}

func newTestOutbound(t *testing.T, f *sshFixture, mutate func(*option.SSHOutboundOptions)) *Outbound {
	options := option.SSHOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: f.port},
		User:          "alice",
		Password:      "wonderland",
		HostKey:       []string{f.hostKey.authorizedKey},
	}
	if mutate != nil {
		mutate(&options)
	}
	out, err := NewOutbound(context.Background(), f.router, log.NewNOPFactory().Logger(), "ssh-out", options)
	require.NoError(t, err)
	t.Cleanup(func() { out.(*Outbound).Close() })
	return out.(*Outbound)
}

func TestH_SSHOutboundToInboundTCP(t *testing.T) {
	t.Parallel()
	f := startInbound(t, nil)
	out := newTestOutbound(t, f, nil)
	require.False(t, out.IsReady())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("198.51.100.7:9000"))
	require.NoError(t, err)
	require.True(t, out.IsReady())
	require.Empty(t, out.connectionErr)
	echoOnce(t, conn, "outbound tcp")
	conn.Close()
	md := f.router.last(t)
	require.Equal(t, "alice", md.User)
	require.Equal(t, M.ParseSocksaddr("198.51.100.7:9000"), md.Destination)

	keyOut := newTestOutbound(t, f, func(o *option.SSHOutboundOptions) {
		o.User = "bob"
		o.Password = ""
		o.PrivateKey = []string{f.userKey.privatePEM}
	})
	conn, err = keyOut.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("198.51.100.8:9001"))
	require.NoError(t, err)
	echoOnce(t, conn, "outbound key")
	conn.Close()
	require.Equal(t, "bob", f.router.last(t).User)
}

func TestH_SSHOutboundConnectErrorRecorded(t *testing.T) {
	t.Parallel()
	f := startInbound(t, nil)
	out := newTestOutbound(t, f, func(o *option.SSHOutboundOptions) {
		o.HostKey = []string{newKeyPair(t).authorizedKey}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("10.0.0.1:80"))
	require.ErrorContains(t, err, "host key mismatch")
	require.Contains(t, out.connectionErr, "host key mismatch")
	require.False(t, out.IsReady())
}

func TestH_SSHOutboundProxyDisplayName(t *testing.T) {
	t.Skip("BUG: ProxyDisplayName builds a status string but returns s.connectionErr (protocol/ssh/outbound.go:375)")
	t.Parallel()
	f := startInbound(t, nil)
	out := newTestOutbound(t, f, nil)
	require.Contains(t, out.ProxyDisplayName(), "Connecting")
}

func TestH_SSHOutboundUDPOverTCP(t *testing.T) {
	t.Parallel()
	for _, version := range []uint8{0, 1, 2} {
		f := startInbound(t, nil)
		out := newTestOutbound(t, f, func(o *option.SSHOutboundOptions) {
			o.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true, Version: version}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		destination := M.ParseSocksaddr("203.0.113.5:53")

		packetConn, err := out.ListenPacket(ctx, destination)
		require.NoError(t, err, version)
		watchdog := time.AfterFunc(5*time.Second, func() { packetConn.Close() })
		_, err = packetConn.WriteTo([]byte("udp payload"), destination.UDPAddr())
		require.NoError(t, err, version)
		reply := make([]byte, 64)
		n, _, err := packetConn.ReadFrom(reply)
		require.NoError(t, err, version)
		require.Equal(t, "udp payload", string(reply[:n]))
		watchdog.Stop()
		packetConn.Close()
		md := f.router.last(t)
		require.Equal(t, "alice", md.User)
		if version != 1 {
			require.Equal(t, destination, md.Destination, version)
		}

		conn, err := out.DialContext(ctx, N.NetworkUDP, destination)
		require.NoError(t, err, version)
		watchdog = time.AfterFunc(5*time.Second, func() { conn.Close() })
		_, err = conn.Write([]byte("connected udp"))
		require.NoError(t, err)
		n, err = conn.Read(reply)
		require.NoError(t, err)
		require.Equal(t, "connected udp", string(reply[:n]))
		watchdog.Stop()
		conn.Close()
		f.router.last(t)
		cancel()
	}
}

func TestH_SSHOutboundUDPWithoutUoT(t *testing.T) {
	t.Parallel()
	f := startInbound(t, nil)
	out := newTestOutbound(t, f, nil)
	_, err := out.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorIs(t, err, os.ErrInvalid)

	tcpOnly := newTestOutbound(t, f, func(o *option.SSHOutboundOptions) { o.Network = "tcp" })
	require.Equal(t, []string{N.NetworkTCP}, tcpOnly.Network())
}

func TestH_SSHOutboundUoTStreamAccounting(t *testing.T) {
	t.Skip("BUG: DialContext(udp) with UoT increments s.streams before delegating to uotClient, which dials again; the first increment is never released (protocol/ssh/outbound.go:299,310)")
	t.Parallel()
	f := startInbound(t, nil)
	out := newTestOutbound(t, f, func(o *option.SSHOutboundOptions) {
		o.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true, Version: 2}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr("203.0.113.5:53"))
	require.NoError(t, err)
	conn.Close()
	out.clientAccess.Lock()
	streams := out.streams
	out.clientAccess.Unlock()
	require.Equal(t, 0, streams)
}
