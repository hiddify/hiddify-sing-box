//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// hRecordingConn keeps what the client writes, to inspect the ClientHello.
type hRecordingConn struct {
	net.Conn
	access  sync.Mutex
	written bytes.Buffer
}

func (c *hRecordingConn) Write(b []byte) (int, error) {
	c.access.Lock()
	c.written.Write(b)
	c.access.Unlock()
	return c.Conn.Write(b)
}

// hStartTLSDest serves TLS 1.3 with a self-signed certificate, as the REALITY handshake target.
func hStartTLSDest(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		DNSNames:     []string{"www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.(*tls.Conn).Handshake()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// Xray servers from v26.10 reject a REALITY ClientHello without an X25519MLKEM768 key share before
// the X25519 one; every fingerprint must send it in that order and still authenticate (with the
// X25519 share).
func TestH_RealityClientSendsMLKEMKeyShare(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "firefox", "edge", "safari", "ios", "android", "360", "qq", "random", "randomized"} {
		t.Run(fingerprint, func(t *testing.T) {
			hTestRealityFingerprint(t, fingerprint)
		})
	}
}

func hTestRealityFingerprint(t *testing.T, fingerprint string) {
	ctx := context.Background()
	dest := hStartTLSDest(t)
	destHost, destPort, err := net.SplitHostPort(dest)
	require.NoError(t, err)
	port, err := net.LookupPort("tcp", destPort)
	require.NoError(t, err)

	serverConfig, err := NewRealityServer(ctx, log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		Enabled:    true,
		ServerName: "www.example.com",
		Reality: &option.InboundRealityOptions{
			Enabled: true,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: destHost, ServerPort: uint16(port)},
			},
			ShortID:    []string{"0123456789abcdef"},
			PrivateKey: "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
		},
	})
	require.NoError(t, err)
	// Xray servers apply a minClientVer (26.3.27 when unset in v26.7)
	serverConfig.(*RealityServerConfig).config.MinClientVer = []byte{26, 3, 27}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		tlsConn, err := ServerHandshake(ctx, conn, serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = io.Copy(tlsConn, io.LimitReader(tlsConn, 4))
		serverDone <- err
	}()

	clientConfig, err := NewRealityClient(ctx, logger.NOP(), listener.Addr().String(), option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			ShortID:   "0123456789abcdef",
			PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
		},
	})
	require.NoError(t, err)
	rawConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer rawConn.Close()
	require.NoError(t, rawConn.SetDeadline(time.Now().Add(10*time.Second)))
	recording := &hRecordingConn{Conn: rawConn}
	clientConn, err := ClientHandshake(ctx, recording, clientConfig)
	require.NoError(t, err)

	recording.access.Lock()
	clientHello := bytes.Clone(recording.written.Bytes())
	recording.access.Unlock()
	// key_share entries: X25519MLKEM768 (0x11EC, 1216 bytes) before X25519 (0x001D, 32 bytes)
	mlkemShare := bytes.Index(clientHello, []byte{0x11, 0xEC, 0x04, 0xC0})
	x25519Share := bytes.Index(clientHello, []byte{0x00, 0x1D, 0x00, 0x20})
	require.NotEqual(t, -1, mlkemShare, "no X25519MLKEM768 key share in the ClientHello")
	require.NotEqual(t, -1, x25519Share, "no X25519 key share in the ClientHello")
	require.Less(t, mlkemShare, x25519Share, "X25519MLKEM768 key share is not before X25519")

	_, err = clientConn.Write([]byte("ping"))
	require.NoError(t, err)
	reply := make([]byte, 4)
	_, err = io.ReadFull(clientConn, reply)
	require.NoError(t, err)
	require.Equal(t, "ping", string(reply))
	clientConn.Close()
	require.NoError(t, <-serverDone)
}
