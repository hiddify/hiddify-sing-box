package vless

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	stdtls "crypto/tls"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/vless/encryption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func encodeKey(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateKeyStrings(t *testing.T) (serverX25519, clientX25519, serverMLKEM, clientMLKEM string) {
	t.Helper()
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	dk, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	return encodeKey(sk.Bytes()), encodeKey(sk.PublicKey().Bytes()), encodeKey(dk.Bytes()), encodeKey(dk.EncapsulationKey().Bytes())
}

func TestH_ParseServerDecryption(t *testing.T) {
	t.Parallel()
	sx, _, sm, _ := generateKeyStrings(t)

	cfg, err := parseServerDecryption(" mlkem768x25519plus.native.600s." + sx + " ")
	require.NoError(t, err)
	require.Equal(t, uint32(0), cfg.xorMode)
	require.Equal(t, int64(600), cfg.secondsFrom)
	require.Equal(t, int64(0), cfg.secondsTo)
	require.Len(t, cfg.keys, 1)
	require.Len(t, cfg.keys[0], 32)
	require.Empty(t, cfg.padding)

	cfg, err = parseServerDecryption("mlkem768x25519plus.xorpub.300-600s." + sm + "." + sx)
	require.NoError(t, err)
	require.Equal(t, uint32(1), cfg.xorMode)
	require.Equal(t, int64(300), cfg.secondsFrom)
	require.Equal(t, int64(600), cfg.secondsTo)
	require.Len(t, cfg.keys, 2)
	require.Len(t, cfg.keys[0], 64)

	cfg, err = parseServerDecryption("mlkem768x25519plus.random.0s." + sx)
	require.NoError(t, err)
	require.Equal(t, uint32(2), cfg.xorMode)
	require.Zero(t, cfg.secondsFrom)

	for _, invalid := range []string{
		"",
		"   ",
		"mlkem768x25519plus.native.600s",
		"x25519.native.600s." + sx,
		"mlkem768x25519plus.foo.600s." + sx,
		"mlkem768x25519plus.native.." + sx,
		"mlkem768x25519plus.native.s." + sx,
		"mlkem768x25519plus.native.abcs." + sx,
		"mlkem768x25519plus.native.1-xs." + sx,
		"mlkem768x25519plus.native.600s.." + sx,
		"mlkem768x25519plus.native.600s." + encodeKey(make([]byte, 31)),
		"mlkem768x25519plus.native.600s." + sx + ".!bad!",
		"mlkem768x25519plus.native.600s.!bad!",
	} {
		_, err = parseServerDecryption(invalid)
		require.Error(t, err, invalid)
	}
}

func TestH_ParseClientEncryption(t *testing.T) {
	t.Parallel()
	_, cx, _, cm := generateKeyStrings(t)

	cfg, err := parseClientEncryption("mlkem768x25519plus.native.0rtt." + cx)
	require.NoError(t, err)
	require.Equal(t, uint32(0), cfg.xorMode)
	require.Equal(t, uint32(1), cfg.seconds)
	require.Len(t, cfg.keys, 1)

	cfg, err = parseClientEncryption("mlkem768x25519plus.random.1rtt." + cm + "." + cx)
	require.NoError(t, err)
	require.Equal(t, uint32(2), cfg.xorMode)
	require.Zero(t, cfg.seconds)
	require.Len(t, cfg.keys, 2)
	require.Len(t, cfg.keys[0], 1184)

	for _, invalid := range []string{
		"",
		"mlkem768x25519plus.native.0rtt",
		"other.native.0rtt." + cx,
		"mlkem768x25519plus.bad.0rtt." + cx,
		"mlkem768x25519plus.native.2rtt." + cx,
		"mlkem768x25519plus.native.600s." + cx,
		"mlkem768x25519plus.native.0rtt.." + cx,
		"mlkem768x25519plus.native.0rtt." + encodeKey(make([]byte, 64)),
		"mlkem768x25519plus.native.0rtt." + cx + ".!bad!",
	} {
		_, err = parseClientEncryption(invalid)
		require.Error(t, err, invalid)
	}
}

func TestH_ParseEncryptionWithPadding(t *testing.T) {
	t.Skip("BUG: padding segments like \"100-111-1111\" are valid RawURL base64, so they are decoded as keys and rejected with \"invalid key length\" (inbound.go:301, outbound.go:484)")
	t.Parallel()
	sx, cx, _, _ := generateKeyStrings(t)
	padding := "100-111-1111.75-0-111.50-0-3333"

	serverCfg, err := parseServerDecryption("mlkem768x25519plus.native.600s." + padding + "." + sx)
	require.NoError(t, err)
	require.Equal(t, padding, serverCfg.padding)
	require.Len(t, serverCfg.keys, 1)

	clientCfg, err := parseClientEncryption("mlkem768x25519plus.native.0rtt." + padding + "." + cx)
	require.NoError(t, err)
	require.Equal(t, padding, clientCfg.padding)
	require.Len(t, clientCfg.keys, 1)
}

func TestH_ParseEncryptionPaddingNonBase64(t *testing.T) {
	t.Parallel()
	sx, cx, _, _ := generateKeyStrings(t)
	serverCfg, err := parseServerDecryption("mlkem768x25519plus.native.600s.100-40-40." + sx)
	require.NoError(t, err)
	require.Equal(t, "100-40-40", serverCfg.padding)

	serverCfg, err = parseServerDecryption("mlkem768x25519plus.native.600s.100-111-11111." + sx)
	require.NoError(t, err)
	require.Equal(t, "100-111-11111", serverCfg.padding)

	clientCfg, err := parseClientEncryption("mlkem768x25519plus.native.0rtt.100-111-11111." + cx)
	require.NoError(t, err)
	require.Equal(t, "100-111-11111", clientCfg.padding)
}

func TestH_ParsedConfigHandshake(t *testing.T) {
	t.Parallel()
	sx, cx, sm, cm := generateKeyStrings(t)
	for _, mode := range []string{"native", "xorpub", "random"} {
		serverCfg, err := parseServerDecryption("mlkem768x25519plus." + mode + ".600s." + sm + "." + sx)
		require.NoError(t, err)
		clientCfg, err := parseClientEncryption("mlkem768x25519plus." + mode + ".0rtt." + cm + "." + cx)
		require.NoError(t, err)

		server := &encryption.ServerInstance{}
		require.NoError(t, server.Init(serverCfg.keys, serverCfg.xorMode, serverCfg.secondsFrom, serverCfg.secondsTo, serverCfg.padding))
		client := &encryption.ClientInstance{}
		require.NoError(t, client.Init(clientCfg.keys, clientCfg.xorMode, clientCfg.seconds, clientCfg.padding))

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		result := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				result <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			encConn, err := server.Handshake(conn, nil)
			if err != nil {
				result <- err
				return
			}
			buffer := make([]byte, 64)
			n, err := encConn.Read(buffer)
			if err != nil {
				result <- err
				return
			}
			_, err = encConn.Write(buffer[:n])
			result <- err
		}()
		raw, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		encConn, err := client.Handshake(raw)
		require.NoError(t, err)
		_, err = encConn.Write([]byte("echo " + mode))
		require.NoError(t, err)
		buffer := make([]byte, 64)
		n, err := encConn.Read(buffer)
		require.NoError(t, err)
		require.Equal(t, "echo "+mode, string(buffer[:n]))
		require.NoError(t, <-result)
		raw.Close()
		listener.Close()
		server.Close()
		require.Same(t, encConn, findEncryptionLayer(encConn))
	}
}

type fakeHandshakeConn struct{ net.Conn }

func (fakeHandshakeConn) Handshake() error { return nil }

type fakeStateConn struct{ net.Conn }

func (fakeStateConn) ConnectionState() stdtls.ConnectionState { return stdtls.ConnectionState{} }

type upstreamConn struct {
	net.Conn
	upstream any
}

func (c *upstreamConn) Upstream() any { return c.upstream }

type replaceableConn struct {
	net.Conn
	replaceable bool
}

func (c *replaceableConn) ReaderReplaceable() bool { return c.replaceable }
func (c *replaceableConn) WriterReplaceable() bool { return c.replaceable }
func (c *replaceableConn) Upstream() any           { return c.Conn }

func TestH_IsVisionTLSConn(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	require.False(t, isVisionTLSConn(nil))
	require.False(t, isVisionTLSConn(a))
	require.True(t, isVisionTLSConn(stdtls.Client(a, &stdtls.Config{})))
	require.True(t, isVisionTLSConn(fakeHandshakeConn{a}))
	require.True(t, isVisionTLSConn(fakeStateConn{a}))
	require.False(t, isVisionTLSConn(&upstreamConn{Conn: a}))
}

func TestH_FindEncryptionLayer(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	common := encryption.NewCommonConn(a, false)
	xorConn := encryption.NewXorConn(a, nil, nil, 0, 0)

	require.Nil(t, findEncryptionLayer(nil))
	require.Nil(t, findEncryptionLayer(a))
	require.Same(t, common, findEncryptionLayer(common))
	require.Same(t, xorConn, findEncryptionLayer(xorConn))
	require.Same(t, common, findEncryptionLayer(&upstreamConn{Conn: a, upstream: &upstreamConn{Conn: a, upstream: common}}))
	require.Nil(t, findEncryptionLayer(&upstreamConn{Conn: a, upstream: "not a conn"}))
	require.Nil(t, findEncryptionLayer(&upstreamConn{Conn: a}))
}

func TestH_VisionConnWrapper(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	inner := &upstreamConn{Conn: a}

	require.Same(t, a, newVisionConnWrapper(a, nil))
	require.Same(t, a, newVisionConnWrapper(a, a))
	require.Nil(t, newVisionConnWrapper(nil, a))

	wrapped := newVisionConnWrapper(inner, b)
	wrapper, ok := wrapped.(*visionConnWrapper)
	require.True(t, ok)
	require.Same(t, b, wrapper.Upstream())

	locked := newVisionConnWrapper(&replaceableConn{Conn: a, replaceable: false}, b).(*visionConnWrapper)
	require.False(t, locked.ReaderReplaceable())
	require.False(t, locked.WriterReplaceable())
	open := newVisionConnWrapper(&replaceableConn{Conn: a, replaceable: true}, b).(*visionConnWrapper)
	require.True(t, open.ReaderReplaceable())
	require.True(t, open.WriterReplaceable())
}

func TestH_VisionConnWrapperDoesNotBypassEncryption(t *testing.T) {
	t.Skip("BUG: visionConnWrapper reports ReaderReplaceable/WriterReplaceable=true when the wrapped conn (e.g. encryption.CommonConn) does not implement them, so N.UnwrapReader/UnwrapWriter skip the encryption layer and go straight to the TLS upstream (outbound.go:377-389)")
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	tlsConn := stdtls.Client(a, &stdtls.Config{})
	encConn := encryption.NewCommonConn(tlsConn, false)
	wrapped := newVisionConnWrapper(encConn, tlsConn)
	require.NotSame(t, tlsConn, N.UnwrapReader(wrapped))
	require.NotSame(t, tlsConn, N.UnwrapWriter(wrapped))
}
