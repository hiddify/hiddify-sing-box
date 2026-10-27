//go:build with_utls

package tls

import (
	"context"
	stdtls "crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

type hHelloExtension struct {
	kind uint16
	data []byte
}

// hCaptureClientHello runs a client handshake against a listener that never answers and returns
// the extensions of the ClientHello it sent.
func hCaptureClientHello(t *testing.T, options option.OutboundTLSOptions) []hHelloExtension {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	hello := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		hello <- body
	}()
	config, err := NewClient(context.Background(), log.NewNOPFactory().Logger(), "127.0.0.1", options)
	require.NoError(t, err)
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	tlsConn, err := config.Client(conn)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go tlsConn.HandshakeContext(ctx)
	var body []byte
	select {
	case body = <-hello:
	case <-time.After(3 * time.Second):
		t.Fatal("no ClientHello")
	}
	// handshake type, length, version, random, session id, cipher suites, compression
	offset := 4 + 2 + 32
	offset += 1 + int(body[offset])
	offset += 2 + int(binary.BigEndian.Uint16(body[offset:]))
	offset += 1 + int(body[offset])
	end := offset + 2 + int(binary.BigEndian.Uint16(body[offset:]))
	var extensions []hHelloExtension
	for offset += 2; offset < end; {
		kind := binary.BigEndian.Uint16(body[offset:])
		length := int(binary.BigEndian.Uint16(body[offset+2:]))
		extensions = append(extensions, hHelloExtension{kind, body[offset+4 : offset+4+length]})
		offset += 4 + length
	}
	return extensions
}

func hServerName(extensions []hHelloExtension) (string, int) {
	for i, extension := range extensions {
		if extension.kind == 0 {
			return string(extension.data[5:]), i
		}
	}
	return "", -1
}

const hTricksServerName = "a-long-server-name.example.com"

func hTricksOptions(tricks *option.TLSTricksOptions) option.OutboundTLSOptions {
	return option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: hTricksServerName,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		TLSTricks:  tricks,
	}
}

// padding_mode "random" adds a padding extension of padding_size bytes before the SNI.
func TestH_TLSTricksPadding(t *testing.T) {
	extensions := hCaptureClientHello(t, hTricksOptions(&option.TLSTricksOptions{PaddingMode: "random", PaddingSize: "500-500"}))
	name, sniIndex := hServerName(extensions)
	require.Equal(t, hTricksServerName, name)
	paddings := 0
	for i, extension := range extensions {
		if extension.kind == 0x15 {
			paddings++
			require.Len(t, extension.data, 500)
			require.Less(t, i, sniIndex, "the padding comes before the SNI")
		}
	}
	require.Equal(t, 1, paddings)
}

// mixedcase_sni sends the server name with a random case, a new one on each connection.
func TestH_TLSTricksMixedCaseSNI(t *testing.T) {
	seen := map[string]bool{}
	for range 4 {
		name, _ := hServerName(hCaptureClientHello(t, hTricksOptions(&option.TLSTricksOptions{MixedCaseSNI: true})))
		require.True(t, strings.EqualFold(hTricksServerName, name))
		seen[name] = true
	}
	require.Greater(t, len(seen), 1, "the case changes between connections")
	require.False(t, seen[hTricksServerName] && len(seen) == 1)
}

// Without tricks the ClientHello is the fingerprint's own.
func TestH_TLSTricksOff(t *testing.T) {
	name, _ := hServerName(hCaptureClientHello(t, hTricksOptions(nil)))
	require.Equal(t, hTricksServerName, name)
}

// A full handshake with both tricks against a real server, with the certificate verified.
func TestH_TLSTricksHandshake(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &stdtls.Config{MinVersion: stdtls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for _, fingerprint := range []string{"chrome", "firefox", "safari"} {
		options := option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "example.com",
			Certificate: badoption.Listable[string]{string(certificate)},
			UTLS:        &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
			TLSTricks:   &option.TLSTricksOptions{MixedCaseSNI: true, PaddingMode: "random", PaddingSize: "100-1200"},
		}
		config, err := NewClient(context.Background(), log.NewNOPFactory().Logger(), "127.0.0.1", options)
		require.NoError(t, err)
		conn, err := net.Dial("tcp", server.Listener.Addr().String())
		require.NoError(t, err)
		tlsConn, err := config.Client(conn)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		require.NoError(t, tlsConn.HandshakeContext(ctx), fingerprint)
		cancel()
		tlsConn.Close()
	}
}

// The standard client (no uTLS) also sends a mixed-case SNI and still verifies the certificate.
func TestH_TLSTricksStandardClient(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	options := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "example.com",
		Certificate: badoption.Listable[string]{string(certificate)},
		TLSTricks:   &option.TLSTricksOptions{MixedCaseSNI: true, PaddingMode: "random", PaddingSize: "100"},
	}
	config, err := NewClient(context.Background(), log.NewNOPFactory().Logger(), "127.0.0.1", options)
	require.NoError(t, err)
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	require.NoError(t, err)
	tlsConn, err := config.Client(conn)
	require.NoError(t, err)
	defer tlsConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, tlsConn.HandshakeContext(ctx))
	require.True(t, strings.EqualFold("example.com", tlsConn.ConnectionState().ServerName))
}
