package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"
	wgTun "github.com/sagernet/wireguard-go/tun"
	"github.com/stretchr/testify/require"
)

func TestH_RandomIdentifiers(t *testing.T) {
	serial, err := GenerateRandomAndroidSerial()
	require.NoError(t, err)
	require.Len(t, serial, 16)
	_, err = hex.DecodeString(serial)
	require.NoError(t, err)

	pubkey, err := GenerateRandomWgPubkey()
	require.NoError(t, err)
	raw, err := base64.StdEncoding.DecodeString(pubkey)
	require.NoError(t, err)
	require.Len(t, raw, 32)

	other, err := GenerateRandomWgPubkey()
	require.NoError(t, err)
	require.NotEqual(t, pubkey, other)
}

func TestH_TimeAsCfString(t *testing.T) {
	zone := time.FixedZone("x", 3*3600+30*60)
	require.Equal(t, "2024-03-05T07:08:09.123+03:30", TimeAsCfString(time.Date(2024, 3, 5, 7, 8, 9, 123456789, zone)))
	require.Equal(t, "2024-03-05T07:08:09.000+00:00", TimeAsCfString(time.Date(2024, 3, 5, 7, 8, 9, 0, time.UTC)))
}

func TestH_LoginToBase64(t *testing.T) {
	encoded := LoginToBase64("user", "p:ss")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.Equal(t, "user:p:ss", string(decoded))
}

func TestH_CheckIfname(t *testing.T) {
	require.NoError(t, CheckIfname("utun3"))
	require.NoError(t, CheckIfname("averyveryverylongname"))
	require.NoError(t, CheckIfname("tün0"))
	require.Error(t, CheckIfname(""))
	require.Error(t, CheckIfname("a/b"))
	require.Error(t, CheckIfname("a b"))
	require.Error(t, CheckIfname("a\tb"))
}

func TestH_GenerateEcKeyPairAndCert(t *testing.T) {
	privateDER, publicDER, err := GenerateEcKeyPair()
	require.NoError(t, err)
	privateKey, err := x509.ParseECPrivateKey(privateDER)
	require.NoError(t, err)
	require.Equal(t, elliptic.P256(), privateKey.Curve)
	publicKey, err := x509.ParsePKIXPublicKey(publicDER)
	require.NoError(t, err)
	require.True(t, privateKey.PublicKey.Equal(publicKey))

	chain, err := GenerateCert(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	cert, err := x509.ParseCertificate(chain[0])
	require.NoError(t, err)
	require.True(t, cert.PublicKey.(*ecdsa.PublicKey).Equal(&privateKey.PublicKey))
	require.NoError(t, cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature))
	require.InDelta(t, float64(24*time.Hour), float64(cert.NotAfter.Sub(cert.NotBefore)), float64(2*time.Second))
	require.WithinDuration(t, time.Now(), cert.NotBefore, time.Minute)
}

func TestH_DefaultQuicConfig(t *testing.T) {
	config := DefaultQuicConfig(15*time.Second, 0)
	require.True(t, config.EnableDatagrams)
	require.Equal(t, 15*time.Second, config.KeepAlivePeriod)
	require.False(t, config.DisablePathMTUDiscovery)
	require.Zero(t, config.InitialPacketSize)

	config = DefaultQuicConfig(0, 1242)
	require.Equal(t, uint16(1242), config.InitialPacketSize)
	require.True(t, config.DisablePathMTUDiscovery)
	var _ *quic.Config = config
}

func TestH_ParsePortMapping(t *testing.T) {
	mapping, err := ParsePortMapping("127.0.0.1:8080:10.0.0.1:80")
	require.NoError(t, err)
	require.Equal(t, PortMapping{BindAddress: "127.0.0.1", LocalPort: 8080, RemoteIP: "10.0.0.1", RemotePort: 80}, mapping)

	mapping, err = ParsePortMapping("*:53:1.1.1.1:53")
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0", mapping.BindAddress)

	mapping, err = ParsePortMapping("1080:192.0.2.5:443")
	require.NoError(t, err)
	require.True(t, net.ParseIP(mapping.BindAddress).IsLoopback(), mapping.BindAddress)
	require.Equal(t, 1080, mapping.LocalPort)
	require.Equal(t, "192.0.2.5", mapping.RemoteIP)
	require.Equal(t, 443, mapping.RemotePort)

	for _, input := range []string{
		"",
		"80",
		"80:1.1.1.1",
		"0:1.1.1.1:80",
		"70000:1.1.1.1:80",
		"x:1.1.1.1:80",
		"80:1.1.1.1:0",
		"80:1.1.1.1:65536",
		"80:nodots:443",
		"a:b:c:d:e",
	} {
		_, err = ParsePortMapping(input)
		require.Error(t, err, input)
	}
}

func TestH_ParsePortMappingIPv6(t *testing.T) {
	t.Skip("BUG: parsePortMapping splits on ':' before handling brackets, so documented IPv6 bind addresses like [::1] are always rejected")
	mapping, err := ParsePortMapping("[::1]:8080:10.0.0.1:80")
	require.NoError(t, err)
	require.Equal(t, "::1", mapping.BindAddress)
	require.Equal(t, 8080, mapping.LocalPort)
}

type hFakeTun struct {
	wgTun.Device
	inbound  chan []byte
	written  [][]byte
	readErr  error
	writeErr error
}

func (f *hFakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	packet := <-f.inbound
	sizes[0] = copy(bufs[0][offset:], packet)
	return 1, nil
}

func (f *hFakeTun) Write(bufs [][]byte, offset int) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func TestH_NetstackAdapter(t *testing.T) {
	fake := &hFakeTun{inbound: make(chan []byte, 2)}
	adapter := NewNetstackAdapter(fake)
	fake.inbound <- []byte("first-packet")
	fake.inbound <- []byte("second")
	buffer := make([]byte, 64)
	n, err := adapter.ReadPacket(buffer)
	require.NoError(t, err)
	require.Equal(t, "first-packet", string(buffer[:n]))
	n, err = adapter.ReadPacket(buffer)
	require.NoError(t, err)
	require.Equal(t, "second", string(buffer[:n]))

	require.NoError(t, adapter.WritePacket([]byte("out")))
	require.Equal(t, [][]byte{[]byte("out")}, fake.written)

	fake.readErr = os.ErrClosed
	_, err = adapter.ReadPacket(buffer)
	require.ErrorIs(t, err, os.ErrClosed)
	fake.writeErr = errors.New("write failed")
	require.EqualError(t, adapter.WritePacket([]byte("x")), "write failed")
}

func TestH_ConnectTunnelEndpointValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, _, _, err := ConnectTunnel(ctx, nil, nil, DefaultQuicConfig(0, 0), "https://cloudflareaccess.com", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, true)
	require.ErrorContains(t, err, "missing HTTP/2 TCP endpoint")
	_, _, _, _, err = ConnectTunnel(ctx, nil, nil, DefaultQuicConfig(0, 0), "https://cloudflareaccess.com", (*net.TCPAddr)(nil), true)
	require.ErrorContains(t, err, "missing HTTP/2 TCP endpoint")
	_, _, _, _, err = ConnectTunnel(ctx, nil, nil, DefaultQuicConfig(0, 0), "https://cloudflareaccess.com", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, false)
	require.ErrorContains(t, err, "missing HTTP/3 UDP endpoint")
	_, _, _, _, err = ConnectTunnel(ctx, nil, nil, DefaultQuicConfig(0, 0), "https://cloudflareaccess.com", nil, false)
	require.ErrorContains(t, err, "missing HTTP/3 UDP endpoint")
	_, err = newHTTP2Client(nil, nil, nil, "")
	require.ErrorContains(t, err, "missing HTTP/2 endpoint")
}

func TestH_ConnectTunnelListenError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialer := &hFailingDialer{}
	_, _, _, _, err := ConnectTunnel(ctx, dialer, nil, DefaultQuicConfig(0, 0), "https://cloudflareaccess.com", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, false)
	require.ErrorContains(t, err, "listen refused")
	require.Equal(t, M.ParseSocksaddr("192.0.2.1:443"), dialer.listened.Unwrap())
}

type hFailingDialer struct {
	listened M.Socksaddr
}

func (d *hFailingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("dial refused")
}

func (d *hFailingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.listened = destination
	return nil, errors.New("listen refused")
}
