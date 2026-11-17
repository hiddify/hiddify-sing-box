package awg

import (
	"context"
	"net/netip"
	"os"
	"testing"

	awgTun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A device that is created and never started holds nothing to close: its tunnel, a network
// stack, is made when it starts. It was made with the device, and a device that never starts is
// never closed: each check of a config (the app checks one at every start and reload) left a
// stack behind for every AmneziaWG or WARP endpoint in it.
func TestH_DeviceMakesItsTunnelAtStart(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	ipc := "private_key=" + hKeyHex(key) + "\npublic_key=" + hKeyHex(peerKey.PublicKey()) + "\nendpoint=127.0.0.1:9\nallowed_ip=0.0.0.0/0"
	device, err := NewDevice(context.Background(), logger.NOP(), &hLoopbackDialer{}, ipc, DeviceOpts{
		Address: []netip.Prefix{netip.MustParsePrefix("10.79.0.2/32")}, MTU: 1408, MTUDiscovery: true,
	})
	require.NoError(t, err)
	require.Nil(t, device.tun, "a tunnel was made for a device that has not started")
	_, err = device.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("10.79.0.1:80"))
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = device.ListenPacket(context.Background(), M.ParseSocksaddr("10.79.0.1:53"))
	require.ErrorIs(t, err, os.ErrInvalid)
	require.NoError(t, device.Close(), "nothing to close")

	started, err := NewDevice(context.Background(), logger.NOP(), &hLoopbackDialer{}, ipc, DeviceOpts{
		Address: []netip.Prefix{netip.MustParsePrefix("10.79.0.2/32")}, MTU: 1408, MTUDiscovery: true,
	})
	require.NoError(t, err)
	require.NoError(t, started.Start(adapter.StartStateStart))
	require.NotNil(t, started.tun)
	require.NotNil(t, started.path.stack, "MTU discovery has the stack of the tunnel")
	require.NoError(t, started.Close())
	require.NoError(t, started.Close())
}

type hFakeSystemTun struct {
	tun.Tun
	closes int
}

func (f *hFakeSystemTun) Close() error {
	f.closes++
	return nil
}

// Closing the system tunnel twice is not a panic, and closes its interface, once.
func TestH_SystemTunClosesOnce(t *testing.T) {
	fake := &hFakeSystemTun{}
	system := &systemTun{singtun: fake, events: make(chan awgTun.Event)}
	require.NoError(t, system.Close())
	require.NotPanics(t, func() { require.NoError(t, system.Close()) })
	require.Equal(t, 1, fake.closes)
}
