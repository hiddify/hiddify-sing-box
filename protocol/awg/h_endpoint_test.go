package awg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/sagernet/sing-box/adapter/htest"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/peeruser"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	transportAwg "github.com/sagernet/sing-box/transport/awg"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func hKey(t *testing.T) wgtypes.Key {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}

func hHex(key wgtypes.Key) string {
	return hex.EncodeToString(key[:])
}

func TestH_GenIpcConfigFullTranslation(t *testing.T) {
	privateKey := hKey(t)
	peerKey := hKey(t).PublicKey()
	presharedKey := hKey(t)
	options := option.AwgEndpointOptions{
		PrivateKey: privateKey.String(),
		ListenPort: 51820,
		Awg: option.AwgOptions{
			Jc: 4, Jmin: 40, Jmax: 70,
			S1: 15, S2: 18, S3: 20, S4: 25,
			H1: "1111", H2: "2222", H3: "3333", H4: "4444",
			I1: "<b 0x01>", I2: "<b 0x02>", I3: "<b 0x03>", I4: "<b 0x04>", I5: "<b 0x05>",
		},
		Peers: []option.AwgPeerOptions{{
			Address:                     "192.0.2.10",
			Port:                        2408,
			PublicKey:                   peerKey.String(),
			PresharedKey:                presharedKey.String(),
			AllowedIPs:                  badoption.Listable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			PersistentKeepaliveInterval: 25,
		}},
	}
	ipc, err := genIpcConfig(options, nil)
	require.NoError(t, err)
	require.Equal(t, strings.Join([]string{
		"private_key=" + hHex(privateKey),
		"listen_port=51820",
		"jc=4", "jmin=40", "jmax=70",
		"s1=15", "s2=18", "s3=20", "s4=25",
		"h1=1111", "h2=2222", "h3=3333", "h4=4444",
		"i1=<b 0x01>", "i2=<b 0x02>", "i3=<b 0x03>", "i4=<b 0x04>", "i5=<b 0x05>",
		"public_key=" + hHex(peerKey),
		"preshared_key=" + hHex(presharedKey),
		"endpoint=192.0.2.10:2408",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
	}, "\n"), ipc)
}

func TestH_GenIpcConfigOmitsZeroValues(t *testing.T) {
	privateKey := hKey(t)
	peerKey := hKey(t).PublicKey()
	ipc, err := genIpcConfig(option.AwgEndpointOptions{
		PrivateKey: privateKey.String(),
		Peers: []option.AwgPeerOptions{
			{PublicKey: peerKey.String()},
			{PublicKey: peerKey.String(), Address: "192.0.2.1"},
			{PublicKey: peerKey.String(), Port: 1},
		},
	}, nil)
	require.NoError(t, err)
	peerLine := "public_key=" + hHex(peerKey)
	require.Equal(t, "private_key="+hHex(privateKey)+"\n"+peerLine+"\n"+peerLine+"\n"+peerLine, ipc)
}

func TestH_GenIpcConfigIPv6PeerEndpoint(t *testing.T) {
	ipc, err := genIpcConfig(option.AwgEndpointOptions{
		PrivateKey: hKey(t).String(),
		Peers:      []option.AwgPeerOptions{{PublicKey: hKey(t).PublicKey().String(), Address: "2001:db8::1", Port: 51820}},
	}, nil)
	require.NoError(t, err)
	require.Contains(t, ipc, "\nendpoint=[2001:db8::1]:51820")
	require.NoError(t, hApplyIpc(t, ipc))
}

func TestH_GenIpcConfigDomainPeer(t *testing.T) {
	peerKey := hKey(t).PublicKey().String()
	options := option.AwgEndpointOptions{
		PrivateKey: hKey(t).String(),
		Peers:      []option.AwgPeerOptions{{PublicKey: peerKey, Address: "vpn.example.test", Port: 443}},
	}

	_, err := genIpcConfig(options, nil)
	require.ErrorContains(t, err, "no resolver provided")

	var resolved []string
	ipc, err := genIpcConfig(options, func(domain string) (netip.Addr, error) {
		resolved = append(resolved, domain)
		return netip.MustParseAddr("198.51.100.7"), nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"vpn.example.test"}, resolved)
	require.Contains(t, ipc, "\nendpoint=198.51.100.7:443")

	_, err = genIpcConfig(options, func(domain string) (netip.Addr, error) {
		return netip.Addr{}, errors.New("nxdomain")
	})
	require.ErrorContains(t, err, "resolve peer endpoint vpn.example.test")
	require.ErrorContains(t, err, "nxdomain")
}

func TestH_GenIpcConfigInvalidKeys(t *testing.T) {
	validKey := hKey(t).String()
	_, err := genIpcConfig(option.AwgEndpointOptions{PrivateKey: "!!notbase64"}, nil)
	require.Error(t, err)
	_, err = genIpcConfig(option.AwgEndpointOptions{PrivateKey: validKey, Peers: []option.AwgPeerOptions{{PublicKey: "!!"}}}, nil)
	require.Error(t, err)
	_, err = genIpcConfig(option.AwgEndpointOptions{PrivateKey: validKey, Peers: []option.AwgPeerOptions{{PublicKey: validKey, PresharedKey: "!!"}}}, nil)
	require.Error(t, err)
}

type hNopDialer struct{}

func (hNopDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (hNopDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

func hApplyIpc(t *testing.T, ipc string) error {
	device, err := transportAwg.NewDevice(context.Background(), logger.NOP(), hNopDialer{}, ipc, transportAwg.DeviceOpts{
		Address: []netip.Prefix{netip.MustParsePrefix("10.79.0.1/32")},
		MTU:     1280,
	})
	require.NoError(t, err)
	defer device.Close()
	return device.Start(adapter.StartStateStart)
}

func TestH_GenIpcConfigAcceptedByDevice(t *testing.T) {
	ipc, err := genIpcConfig(option.AwgEndpointOptions{
		PrivateKey: hKey(t).String(),
		Awg: option.AwgOptions{
			Jc: 4, Jmin: 40, Jmax: 70, S1: 15, S2: 18,
			H1: "1111", H2: "2222", H3: "3333", H4: "4444",
			I1: "<b 0xc0ffee>",
		},
		Peers: []option.AwgPeerOptions{{
			PublicKey:  hKey(t).PublicKey().String(),
			Address:    "127.0.0.1",
			Port:       9,
			AllowedIPs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.79.0.0/24")},
		}},
	}, nil)
	require.NoError(t, err)
	require.NoError(t, hApplyIpc(t, ipc))
}

func TestH_GenIpcConfigS3S4AcceptedByDevice(t *testing.T) {
	ipc, err := genIpcConfig(option.AwgEndpointOptions{
		PrivateKey: hKey(t).String(),
		Awg:        option.AwgOptions{S3: 20, S4: 25},
	}, nil)
	require.NoError(t, err)
	require.NoError(t, hApplyIpc(t, ipc))
}

type hRecordingRouter struct {
	adapter.Router
	metadata   adapter.InboundContext
	packetConn N.PacketConn
}

func (r *hRecordingRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.metadata = metadata
}

func (r *hRecordingRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.metadata = metadata
	r.packetConn = conn
}

func hTestEndpoint(router adapter.Router) *Endpoint {
	return &Endpoint{
		Adapter: endpoint.NewAdapter(C.TypeAwg, "awg-test", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		address: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32"), netip.MustParsePrefix("fd00::2/128")},
		router:  router,
		logger:  log.NewNOPFactory().NewLogger("test"),
		ctx:     context.Background(),
	}
}

func TestH_EndpointNewConnectionRewritesLocalAddress(t *testing.T) {
	router := &hRecordingRouter{}
	ep := hTestEndpoint(router)
	source := M.ParseSocksaddr("10.8.0.1:40000")

	ep.NewConnectionEx(context.Background(), nil, source, M.ParseSocksaddr("10.8.0.2:80"), nil)
	require.Equal(t, "awg-test", router.metadata.Inbound)
	require.Equal(t, C.TypeAwg, router.metadata.InboundType)
	require.Equal(t, source, router.metadata.Source)
	require.Equal(t, M.ParseSocksaddr("127.0.0.1:80"), router.metadata.Destination)
	require.Equal(t, M.ParseSocksaddr("10.8.0.2:80"), router.metadata.OriginDestination)

	ep.NewConnectionEx(context.Background(), nil, source, M.ParseSocksaddr("[fd00::2]:443"), nil)
	require.Equal(t, M.ParseSocksaddr("[::1]:443"), router.metadata.Destination)

	ep.NewConnectionEx(context.Background(), nil, source, M.ParseSocksaddr("1.1.1.1:53"), nil)
	require.Equal(t, M.ParseSocksaddr("1.1.1.1:53"), router.metadata.Destination)
	require.False(t, router.metadata.OriginDestination.IsValid())
}

func TestH_EndpointNewPacketConnectionRewritesLocalAddress(t *testing.T) {
	router := &hRecordingRouter{}
	ep := hTestEndpoint(router)
	source := M.ParseSocksaddr("10.8.0.1:40000")

	ep.NewPacketConnectionEx(context.Background(), nil, source, M.ParseSocksaddr("10.8.0.2:53"), nil)
	require.Equal(t, M.ParseSocksaddr("127.0.0.1:53"), router.metadata.Destination)
	require.Equal(t, M.ParseSocksaddr("10.8.0.2:53"), router.metadata.OriginDestination)
	require.NotNil(t, router.packetConn)

	ep.NewPacketConnectionEx(context.Background(), nil, source, M.ParseSocksaddr("8.8.8.8:53"), nil)
	require.Equal(t, M.ParseSocksaddr("8.8.8.8:53"), router.metadata.Destination)
	require.False(t, router.metadata.OriginDestination.IsValid())
	require.Nil(t, router.packetConn)
}

func TestH_EndpointReadinessAndDialValidation(t *testing.T) {
	ep := hTestEndpoint(&hRecordingRouter{})
	require.False(t, adapter.IsReady(ep))
	hRequireConnecting(t, "Awg", adapter.DisplayType(ep))
	ep.started = true
	require.True(t, adapter.IsReady(ep))
	require.Equal(t, "Awg", ep.DisplayType())

	_, err := ep.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{Port: 80})
	require.ErrorContains(t, err, "invalid destination")
	require.NoError(t, htest.Start(ep, adapter.StartStateInitialize))
}

func TestH_RegisterEndpoint(t *testing.T) {
	registry := endpoint.NewRegistry()
	RegisterEndpoint(registry)
	options, loaded := registry.CreateOptions(C.TypeAwg)
	require.True(t, loaded)
	require.IsType(t, &option.AwgEndpointOptions{}, options)
}

func TestH_EndpointSetsPeerUser(t *testing.T) {
	router := &hRecordingRouter{}
	ep := hTestEndpoint(router)
	ep.peerUsers = peeruser.New([]peeruser.Peer{
		{User: "alice", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.10/32")}},
	})

	ep.NewConnectionEx(context.Background(), nil, M.ParseSocksaddr("10.8.0.10:40000"), M.ParseSocksaddr("1.1.1.1:443"), nil)
	require.Equal(t, "alice", router.metadata.User)

	ep.NewPacketConnectionEx(context.Background(), nil, M.ParseSocksaddr("10.8.0.10:40000"), M.ParseSocksaddr("1.1.1.1:53"), nil)
	require.Equal(t, "alice", router.metadata.User)

	ep.NewConnectionEx(context.Background(), nil, M.ParseSocksaddr("10.8.0.11:40000"), M.ParseSocksaddr("1.1.1.1:443"), nil)
	require.Empty(t, router.metadata.User, "a peer without user")
}

// the AmneziaWG 3.x settings and header ranges reach the device and it accepts them
func TestH_GenIpcConfigAWG3(t *testing.T) {
	var awg option.AwgOptions
	require.NoError(t, json.Unmarshal([]byte(`{
		"s1": 20, "s2": 20, "s3": 20, "s4": 20, "h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800",
		"header_protection_key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"content_padding_addition": "0-32", "rekey_after_time": 120, "rekey_timeout": "5-7",
		"reject_after_time": 180, "keepalive_timeout": 10, "max_handshake_attempts": "18-20",
		"random_trailers": true, "disable_cookies": true
	}`), &awg))
	require.True(t, awg.IsAvailble())
	ipc, err := genIpcConfig(option.AwgEndpointOptions{PrivateKey: hKey(t).String(), Awg: awg}, nil)
	require.NoError(t, err)
	for _, line := range []string{"h1=100-200", "rekey_after_time=120", "rekey_timeout=5-7", "max_handshake_attempts=18-20", "random_trailers=true", "disable_cookies=true"} {
		require.Contains(t, ipc, "\n"+line)
	}
	require.NoError(t, hApplyIpc(t, ipc))

	require.Error(t, json.Unmarshal([]byte(`{"rekey_timeout": true}`), &awg))
}

// ip=quic turns i1 into a fresh QUIC Initial for the domain, and the device accepts it
func TestH_GenIpcConfigMasquerade(t *testing.T) {
	options := option.AwgEndpointOptions{PrivateKey: hKey(t).String(), Awg: option.AwgOptions{IP: "quic", ID: "www.Google.com", IB: "chrome"}}
	ipc, err := genIpcConfig(options, nil)
	require.NoError(t, err)
	require.Contains(t, ipc, "\ni1=<qi www.google.com>")
	require.NoError(t, hApplyIpc(t, ipc))

	for _, invalid := range []option.AwgOptions{
		{ID: "example.com"},                             // id without ip
		{IP: "quic"},                                    // no domain
		{IP: "quic", ID: "a.com> <b 0x00"},              // a domain that would end the tag
		{IP: "quic", ID: "example.com", I1: "<r 10>"},   // with i1
		{IP: "dns", ID: "example.com"},                  // not implemented
		{IP: "quic", ID: "example.com", IB: "netscape"}, // unknown profile
	} {
		_, err := genIpcConfig(option.AwgEndpointOptions{PrivateKey: hKey(t).String(), Awg: invalid}, nil)
		require.Error(t, err, "%+v", invalid)
	}
}

func hRequireConnecting(t *testing.T, base string, display string, message ...any) {
	t.Helper()
	gotBase, mark := adapter.SplitStatus(display)
	require.Equal(t, base, gotBase, message...)
	require.NotEmpty(t, mark, message...)
}
