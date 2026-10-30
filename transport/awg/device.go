package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/exceptions"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

type DeviceOpts struct {
	UseIntegratedTun bool
	Address          []netip.Prefix
	AllowedIps       []netip.Prefix
	ExcludedIps      []netip.Prefix
	MTU              uint32
	// Peer is the address of the only peer, when it has one: the bind then connects to it.
	Peer netip.AddrPort
	// Reserved, when set, are the peer's reserved bytes (WARP).
	Reserved *Reserved
	// MTUDiscovery and Fallback, the peer's other addresses: see h_path.go. //H
	MTUDiscovery bool             //H
	Fallback     []netip.AddrPort //H
}

type Device struct {
	awgDevice *device.Device
	tun       tunAdapter
	bind      conn.Bind
	logger    *device.Logger
	ipcConfig string
	path      *devicePath //H: MTU discovery and fallback addresses
}

func NewDevice(ctx context.Context, logger logger.ContextLogger, dial network.Dialer, ipcConfig string, opts DeviceOpts) (*Device, error) {
	var (
		tun tunAdapter
		err error
	)

	if opts.UseIntegratedTun {
		tun, err = newSystemTun(ctx, opts.Address, opts.AllowedIps, opts.ExcludedIps, opts.MTU, logger)
		if err != nil {
			return nil, exceptions.Cause(err, "create tunnel")
		}
	} else {
		tun, err = newNetworkTun(opts.Address, opts.MTU)
		if err != nil {
			return nil, err
		}
	}

	awgLogger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}

	return &Device{
		tun:       tun,
		bind:      newBind(ctx, dial, opts.Peer, opts.Reserved),
		logger:    awgLogger,
		ipcConfig: ipcConfig,
		path:      newDevicePath(ctx, logger, tun, opts), //H
	}, nil
}

func (d *Device) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	d.awgDevice = device.NewDevice(d.tun, d.bind, d.logger)
	if err := d.awgDevice.IpcSet(d.ipcConfig); err != nil {
		return E.Cause(err, "set ipc config")
	}

	if err := d.tun.Start(); err != nil {
		return E.Cause(err, "tun start")
	}

	if err := d.awgDevice.Up(); err != nil { //H
		return err //H
	} //H
	d.path.start(d) //H
	return nil      //H
}

func (d *Device) IsUnderLoad() bool {
	if d.awgDevice == nil {
		return false
	}
	return d.awgDevice.IsUnderLoad()
}

func (d *Device) Close() error {
	d.path.close() //H
	if d.awgDevice != nil {
		// H: close the detour's connections first: a send stuck on a stalled detour holds the
		// device's network lock, which device.Close needs to close the bind //H
		if bind, isBind := d.bind.(*bind_adapter); isBind { //H
			bind.abort() //H
		} //H
		d.awgDevice.Close()
	}
	return nil
}

func (d *Device) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	conn, err := d.tun.DialContext(ctx, network, destination) //H
	return d.path.track(network, conn, err)                   //H: closed when discovery lowers the MTU
}

func (d *Device) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	return d.tun.ListenPacket(ctx, destination)
}

// IpcGet returns the device's state in the UAPI format; WARP reads handshakes and traffic from it.
func (d *Device) IpcGet() (string, error) {
	if d.awgDevice == nil {
		return "", os.ErrInvalid
	}
	return d.awgDevice.IpcGet()
}
