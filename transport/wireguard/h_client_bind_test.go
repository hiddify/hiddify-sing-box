package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/hiddify"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type hLoopbackDialer struct {
	access sync.Mutex
	listen int
}

func (d *hLoopbackDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("dial not supported")
}

func (d *hLoopbackDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.access.Lock()
	d.listen++
	d.access.Unlock()
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

var _ N.Dialer = (*hLoopbackDialer)(nil)

type hCapture struct {
	conn net.PacketConn
}

func hNewCapture(t *testing.T) *hCapture {
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { packetConn.Close() })
	return &hCapture{conn: packetConn}
}

func (c *hCapture) addrPort() netip.AddrPort {
	return c.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (c *hCapture) read(t *testing.T) []byte {
	buffer := make([]byte, 65535)
	require.NoError(t, c.conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, _, err := c.conn.ReadFrom(buffer)
	require.NoError(t, err)
	return buffer[:n]
}

func hOpenBind(t *testing.T, reserved [3]uint8) *ClientBind {
	bind := NewClientBind(context.Background(), logger.NOP(), &hLoopbackDialer{}, false, netip.AddrPort{}, reserved)
	_, _, err := bind.Open(0)
	require.NoError(t, err)
	t.Cleanup(func() { bind.Close() })
	return bind
}

func TestH_ClientBindOpenAfterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	bind := NewClientBind(ctx, logger.NOP(), &hLoopbackDialer{}, false, netip.AddrPort{}, [3]uint8{})
	cancel()
	fns, port, err := bind.Open(0)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, fns)
	require.Zero(t, port)
}

func TestH_ClientBindSendWithoutModifyKeepsReservedBytes(t *testing.T) {
	capture := hNewCapture(t)
	reserved := [3]uint8{0xAA, 0xBB, 0xCC}
	bind := hOpenBind(t, reserved)
	ep, err := bind.ParseEndpoint(capture.addrPort().String())
	require.NoError(t, err)

	const offset = 4
	packet := func() []byte {
		return append(make([]byte, offset), 0x01, 0x00, 0x00, 0x00, 0x11, 0x22)
	}

	require.NoError(t, bind.Send([][]byte{packet()}, ep, offset))
	require.Equal(t, []byte{0x01, 0xAA, 0xBB, 0xCC, 0x11, 0x22}, capture.read(t))

	require.NoError(t, bind.SendWithoutModify([][]byte{packet(), packet()}, ep, offset))
	require.Equal(t, []byte{0x01, 0x00, 0x00, 0x00, 0x11, 0x22}, capture.read(t))
	require.Equal(t, []byte{0x01, 0x00, 0x00, 0x00, 0x11, 0x22}, capture.read(t))

	bind.SetReservedForEndpoint(capture.addrPort(), [3]uint8{1, 2, 3})
	require.NoError(t, bind.Send([][]byte{packet()}, ep, offset))
	require.Equal(t, []byte{0x01, 1, 2, 3, 0x11, 0x22}, capture.read(t))
	require.NoError(t, bind.SendWithoutModify([][]byte{packet()}, ep, offset))
	require.Equal(t, []byte{0x01, 0x00, 0x00, 0x00, 0x11, 0x22}, capture.read(t))

	require.NoError(t, bind.SendWithoutModify([][]byte{{0x09, 0x08}}, ep, 0))
	require.Equal(t, []byte{0x09, 0x08}, capture.read(t))
}

func TestH_ClientBindReceiveClearsReserved(t *testing.T) {
	bind := NewClientBind(context.Background(), logger.NOP(), &hLoopbackDialer{}, false, netip.AddrPort{}, [3]uint8{})
	fns, _, err := bind.Open(0)
	require.NoError(t, err)
	defer bind.Close()
	capture := hNewCapture(t)
	ep, err := bind.ParseEndpoint(capture.addrPort().String())
	require.NoError(t, err)
	require.NoError(t, bind.SendWithoutModify([][]byte{{0x00}}, ep, 0))
	require.NoError(t, capture.conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	buffer := make([]byte, 16)
	_, bindAddr, err := capture.conn.ReadFrom(buffer)
	require.NoError(t, err)
	_, err = capture.conn.WriteTo([]byte{0x02, 0x07, 0x07, 0x07, 0x05}, bindAddr)
	require.NoError(t, err)

	packets := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	count, err := fns[0](packets, sizes, eps)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, []byte{0x02, 0, 0, 0, 0x05}, packets[0][:sizes[0]])
	require.Equal(t, capture.addrPort().String(), eps[0].DstToString())
}

func hKey(t *testing.T) wgtypes.Key {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}

func hNoiseEndpoint(t *testing.T, ctx context.Context, peerPort uint16, noise hiddify.NoiseOptions, resolve func(domain string) ([]netip.Addr, error)) *Endpoint {
	ep, err := NewEndpoint(EndpointOptions{
		Context:     ctx,
		Logger:      logger.NOP(),
		Dialer:      &hLoopbackDialer{},
		MTU:         1280,
		Address:     []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")},
		PrivateKey:  hKey(t).String(),
		ResolvePeer: resolve,
		Peers: []PeerOptions{{
			Endpoint:   M.ParseSocksaddrHostPort("peer.h.test", peerPort),
			PublicKey:  hKey(t).PublicKey().String(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.66.0.0/24")},
			Reserved:   []uint8{7, 8, 9},
		}},
		Noise: noise,
	})
	require.NoError(t, err)
	require.NoError(t, ep.Initialize(nil))
	require.NoError(t, ep.Start(false), "domain peers start in post-start")
	require.Nil(t, ep.device.Load())
	require.NoError(t, ep.Start(true))
	require.NotNil(t, ep.device.Load())
	t.Cleanup(func() { ep.Close() })
	return ep
}

// hTriggerHandshake sends traffic until ctx ends: a single packet can be lost while the device
// comes up on a loaded machine, and initiations are rate-limited, so retries add none.
func hTriggerHandshake(ctx context.Context, ep *Endpoint) {
	for ctx.Err() == nil {
		dialCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		tcpConn, err := ep.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("10.66.0.1:80"))
		cancel()
		if err == nil {
			tcpConn.Close()
		}
	}
}

func TestH_EndpointDomainPeerResolverAndReserved(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	capture := hNewCapture(t)
	var access sync.Mutex
	var resolved []string
	ep := hNoiseEndpoint(t, ctx, capture.addrPort().Port(), hiddify.NoiseOptions{}, func(domain string) ([]netip.Addr, error) {
		access.Lock()
		resolved = append(resolved, domain)
		access.Unlock()
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	go hTriggerHandshake(ctx, ep)
	initiation := capture.read(t)
	require.Len(t, initiation, 148)
	require.Equal(t, byte(1), initiation[0])
	require.Equal(t, []byte{7, 8, 9}, initiation[1:4], "reserved bytes for resolved domain endpoint")
	access.Lock()
	require.Contains(t, resolved, "peer.h.test")
	access.Unlock()
	require.NotNil(t, ep.Lookup(netip.MustParseAddr("10.66.0.5")))
	require.Nil(t, ep.Lookup(netip.MustParseAddr("192.0.2.1")))
}

func TestH_EndpointResolverErrorSendsNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	capture := hNewCapture(t)
	ep := hNoiseEndpoint(t, ctx, capture.addrPort().Port(), hiddify.NoiseOptions{}, func(domain string) ([]netip.Addr, error) {
		return nil, errors.New("nxdomain")
	})
	triggerCtx, stopTrigger := context.WithTimeout(ctx, time.Second)
	defer stopTrigger()
	go hTriggerHandshake(triggerCtx, ep)
	require.NoError(t, capture.conn.SetReadDeadline(time.Now().Add(time.Second)))
	_, _, err := capture.conn.ReadFrom(make([]byte, 2048))
	require.Error(t, err)
}

func hNoiseOptions(noModify bool) hiddify.NoiseOptions {
	return hiddify.NoiseOptions{FakePacket: hiddify.FakePacketOptions{
		Enabled:  true,
		Count:    hiddify.Range{From: 2, To: 2},
		Size:     hiddify.Range{From: 20, To: 20},
		Delay:    hiddify.Range{From: 1, To: 1},
		Header:   []byte{0xC3},
		NoModify: noModify,
	}}
}

func hCaptureHandshakeWithNoise(t *testing.T, noise hiddify.NoiseOptions) ([][]byte, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	capture := hNewCapture(t)
	ep := hNoiseEndpoint(t, ctx, capture.addrPort().Port(), noise, func(domain string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	go hTriggerHandshake(ctx, ep)
	var fakes [][]byte
	for i := 0; i < 8; i++ {
		packet := capture.read(t)
		if len(packet) == 148 && packet[0] == 1 {
			return fakes, packet
		}
		fakes = append(fakes, packet)
	}
	t.Fatal("no handshake initiation captured")
	return nil, nil
}

func TestH_EndpointNoiseFakePacketsPrecedeHandshake(t *testing.T) {
	for _, noModify := range []bool{true, false} {
		fakes, initiation := hCaptureHandshakeWithNoise(t, hNoiseOptions(noModify))
		require.NotEmpty(t, fakes, "noise must be sent before the handshake initiation")
		for _, fake := range fakes {
			require.Equal(t, []byte{0x00, 0x00, 0x44, 0xD0}, fake[14:18], "fake packet trailer before random payload")
		}
		require.Equal(t, []byte{7, 8, 9}, initiation[1:4])
	}
}

func TestH_EndpointNoiseDisabledSendsOnlyHandshake(t *testing.T) {
	fakes, _ := hCaptureHandshakeWithNoise(t, hiddify.NoiseOptions{FakePacket: hiddify.FakePacketOptions{Count: hiddify.Range{From: 3, To: 3}, Size: hiddify.Range{From: 10, To: 10}}})
	require.Empty(t, fakes)
}

func TestH_EndpointNoiseFakePacketCount(t *testing.T) {
	fakes, _ := hCaptureHandshakeWithNoise(t, hNoiseOptions(true))
	require.Len(t, fakes, 2)
}

func TestH_EndpointNoiseFakePacketLayout(t *testing.T) {
	fakes, _ := hCaptureHandshakeWithNoise(t, hNoiseOptions(true))
	require.NotEmpty(t, fakes)
	for _, fake := range fakes {
		require.Len(t, fake, 6+8+4+20)
		require.Equal(t, []byte{0xC3, 0x00, 0x00, 0x00, 0x01, 0x08}, fake[:6])
		require.Equal(t, []byte{0x00, 0x00, 0x44, 0xD0}, fake[14:18])
	}
}

// QUIC noise: the fake packets are QUIC v1 Initials of at least 1200 bytes, sent unchanged (no
// reserved bytes in the version), before the handshake.
func TestH_EndpointNoiseQUIC(t *testing.T) {
	fakes, initiation := hCaptureHandshakeWithNoise(t, hiddify.NoiseOptions{FakePacket: hiddify.FakePacketOptions{
		Enabled: true,
		Count:   hiddify.Range{From: 2, To: 2},
		Delay:   hiddify.Range{From: 1, To: 1},
		Mode:    hiddify.NoiseModeQUIC,
		SNI:     "www.example.com",
	}})
	require.Len(t, fakes, 2)
	for _, fake := range fakes {
		require.GreaterOrEqual(t, len(fake), 1200)
		require.Equal(t, byte(0xc0), fake[0]&0xf0, "long header, Initial")
		require.Equal(t, []byte{0, 0, 0, 1}, fake[1:5], "QUIC version 1")
	}
	require.Equal(t, fakes[0][5:14], fakes[1][5:14], "one connection")
	require.Equal(t, []byte{7, 8, 9}, initiation[1:4])
}
