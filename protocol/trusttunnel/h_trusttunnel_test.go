package trusttunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

const testServerName = "trusttunnel.test"

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

func generateCertificate(t *testing.T) (certPEM, keyPEM string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testServerName},
		DNSNames:              []string{testServerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func freeTCPPort(t *testing.T) uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return uint16(port)
}

func TestH_TrustTunnelInboundValidation(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	users := []auth.User{{Username: "u", Password: "p"}}
	cases := []struct {
		name    string
		options option.TrustTunnelInboundOptions
		wantErr string
	}{
		{"udp without tls", option.TrustTunnelInboundOptions{Users: users}, C.ErrTLSRequired.Error()},
		{"udp with disabled tls", option.TrustTunnelInboundOptions{
			Users:                      users,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{}},
		}, C.ErrTLSRequired.Error()},
		{"no users", option.TrustTunnelInboundOptions{Network: "tcp"}, "missing users"},
		{"empty username", option.TrustTunnelInboundOptions{Network: "tcp", Users: []auth.User{users[0], {Password: "p"}}}, "missing username or password of user 1"},
		{"empty password", option.TrustTunnelInboundOptions{Network: "tcp", Users: []auth.User{{Username: "u"}}}, "missing username or password of user 0"},
	}
	for _, tc := range cases {
		_, err := NewInbound(context.Background(), newTestRouter(), logger, "tt-in", tc.options)
		require.ErrorContains(t, err, tc.wantErr, tc.name)
	}
	in, err := NewInbound(context.Background(), newTestRouter(), logger, "tt-in", option.TrustTunnelInboundOptions{Network: "tcp", Users: users})
	require.NoError(t, err)
	require.Equal(t, C.TypeTrustTunnel, in.Type())
	require.NoError(t, in.Close())
}

func TestH_TrustTunnelOutboundValidation(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	server := option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}
	tlsOn := option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true}}
	cases := []struct {
		name    string
		options option.TrustTunnelOutboundOptions
		wantErr string
	}{
		{"no tls", option.TrustTunnelOutboundOptions{ServerOptions: server, Username: "u", Password: "p"}, C.ErrTLSRequired.Error()},
		{"tls disabled", option.TrustTunnelOutboundOptions{
			ServerOptions: server, Username: "u", Password: "p",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{}},
		}, C.ErrTLSRequired.Error()},
		{"no username", option.TrustTunnelOutboundOptions{ServerOptions: server, Password: "p", OutboundTLSOptionsContainer: tlsOn}, "require auth"},
		{"no password", option.TrustTunnelOutboundOptions{ServerOptions: server, Username: "u", OutboundTLSOptionsContainer: tlsOn}, "require auth"},
	}
	for _, tc := range cases {
		_, err := NewOutbound(context.Background(), newTestRouter(), logger, "tt-out", tc.options)
		require.ErrorContains(t, err, tc.wantErr, tc.name)
	}
	out, err := NewOutbound(context.Background(), newTestRouter(), logger, "tt-out", option.TrustTunnelOutboundOptions{
		ServerOptions: server, Username: "u", Password: "p", OutboundTLSOptionsContainer: tlsOn,
	})
	require.NoError(t, err)
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, out.Network())
	_, err = out.DialContext(context.Background(), "icmp", M.ParseSocksaddr("1.1.1.1:0"))
	require.ErrorIs(t, err, N.ErrUnknownNetwork)
	require.NoError(t, out.(*Outbound).Close())
}

type tunnelFixture struct {
	router *testRouter
	port   uint16
	cert   string
}

func startTrustTunnelInbound(t *testing.T) *tunnelFixture {
	certPEM, keyPEM := generateCertificate(t)
	f := &tunnelFixture{router: newTestRouter(), port: freeTCPPort(t), cert: certPEM}
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	in, err := NewInbound(context.Background(), f.router, log.NewNOPFactory().Logger(), "tt-in", option.TrustTunnelInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listen, ListenPort: f.port},
		Network:       "tcp",
		Users:         []auth.User{{Username: "alice", Password: "secret"}, {Username: "bob", Password: "hunter2"}},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled:     true,
			ServerName:  testServerName,
			ALPN:        []string{"h2"},
			Certificate: []string{certPEM},
			Key:         []string{keyPEM},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, in.Start(adapter.StartStateStart))
	t.Cleanup(func() { in.Close() })
	return f
}

func (f *tunnelFixture) outbound(t *testing.T, user, password string) adapter.Outbound {
	out, err := NewOutbound(context.Background(), f.router, log.NewNOPFactory().Logger(), "tt-out", option.TrustTunnelOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: f.port},
		Username:      user,
		Password:      password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  testServerName,
			Certificate: []string{f.cert},
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { out.(*Outbound).Close() })
	return out
}

func runWithTimeout(t *testing.T, fn func() error) {
	errCh := make(chan error, 1)
	go func() { errCh <- fn() }()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestH_TrustTunnelLoopbackTCP(t *testing.T) {
	t.Parallel()
	f := startTrustTunnelInbound(t)
	out := f.outbound(t, "alice", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("10.9.8.7:8080"))
	require.NoError(t, err)
	defer conn.Close()
	runWithTimeout(t, func() error {
		if _, err := conn.Write([]byte("trusttunnel tcp")); err != nil {
			return err
		}
		reply := make([]byte, len("trusttunnel tcp"))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return err
		}
		require.Equal(t, "trusttunnel tcp", string(reply))
		return nil
	})
	md := f.router.last(t)
	require.Equal(t, "tt-in", md.Inbound)
	require.Equal(t, C.TypeTrustTunnel, md.InboundType)
	require.Equal(t, "alice", md.User)
	require.Equal(t, M.ParseSocksaddr("10.9.8.7:8080"), md.Destination)
}

func TestH_TrustTunnelLoopbackUDPOverH2(t *testing.T) {
	t.Parallel()
	f := startTrustTunnelInbound(t)
	out := f.outbound(t, "bob", "hunter2")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	destination := M.ParseSocksaddr("192.0.2.53:53")
	conn, err := out.DialContext(ctx, N.NetworkUDP, destination)
	require.NoError(t, err)
	defer conn.Close()
	runWithTimeout(t, func() error {
		if _, err := conn.Write([]byte("datagram")); err != nil {
			return err
		}
		reply := make([]byte, 64)
		n, err := conn.Read(reply)
		if err != nil {
			return err
		}
		require.Equal(t, "datagram", string(reply[:n]))
		return nil
	})
	md := f.router.last(t)
	require.Equal(t, "bob", md.User)
}

func TestH_TrustTunnelAuthFailure(t *testing.T) {
	t.Parallel()
	f := startTrustTunnelInbound(t)
	for _, creds := range [][2]string{{"alice", "wrong"}, {"mallory", "secret"}} {
		out := f.outbound(t, creds[0], creds[1])
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("10.0.0.1:80"))
		require.NoError(t, err)
		errCh := make(chan error, 1)
		go func() {
			_, err := conn.Write([]byte("x"))
			if err == nil {
				_, err = conn.Read(make([]byte, 1))
			}
			errCh <- err
		}()
		select {
		case err = <-errCh:
			require.Error(t, err, creds[0])
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for auth failure")
		}
		conn.Close()
		cancel()
	}
	select {
	case <-f.router.routed:
		t.Fatal("unauthenticated connection was routed")
	default:
	}
}
