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
	// ListenPort, set on a server, is the port its peers send to: see h_listen.go. //H
	ListenPort uint16 //H
	// PeerPending: the only peer is given by a domain, resolved after the start (SetPeerEndpoint). //H
	PeerPending bool //H
}

type Device struct {
	awgDevice *device.Device
	tun       tunAdapter                 //H: made by Start, nil before
	newTun    func() (tunAdapter, error) //H
	bind      conn.Bind
	logger    *device.Logger
	ipcConfig string
	path      *devicePath //H: MTU discovery and fallback addresses
}

func NewDevice(ctx context.Context, logger logger.ContextLogger, dial network.Dialer, ipcConfig string, opts DeviceOpts) (*Device, error) {
	// H: the tunnel is made when the device starts. It holds a network stack, or a system
	// interface, and it was made here: a device that is created and never started is never
	// closed (only what started is, and a config check builds a whole box to drop it), so each
	// check of a config with an AmneziaWG or WARP endpoint left a network stack behind.
	newTun := func() (tunAdapter, error) { //H
		if opts.UseIntegratedTun {
			tun, err := newSystemTun(ctx, opts.Address, opts.AllowedIps, opts.ExcludedIps, opts.MTU, logger) //H
			if err != nil {
				return nil, exceptions.Cause(err, "create tunnel")
			}
			return tun, nil //H
		}
		return newNetworkTun(opts.Address, opts.MTU) //H
	} //H

	awgLogger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}

	return &Device{
		newTun:    newTun,                                 //H
		bind:      newDeviceBind(ctx, logger, dial, opts), //H: a server listens on its port
		logger:    awgLogger,
		ipcConfig: ipcConfig,
		path:      newDevicePath(ctx, logger, opts), //H
	}, nil
}

func (d *Device) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	tun, err := d.newTun() //H
	if err != nil {        //H
		return err //H
	} //H
	d.tun = tun        //H
	d.path.useTun(tun) //H
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
	// H: the bind first, and for good: nothing of the device waits on the detour while it
	// closes, and no reconnect on its way opens the bind again //H
	if bind, isBind := d.bind.(*bind_adapter); isBind { //H
		bind.abort() //H
	} //H
	d.path.close() //H
	if d.awgDevice != nil {
		d.awgDevice.Close()
	}
	return nil
}

func (d *Device) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	if d.tun == nil { //H: not started, as IpcGet answers
		return nil, os.ErrInvalid //H
	} //H
	conn, err := d.tun.DialContext(ctx, network, destination) //H
	return d.path.track(network, conn, err)                   //H: closed when discovery lowers the MTU
}

func (d *Device) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	if d.tun == nil { //H
		return nil, os.ErrInvalid //H
	} //H
	return d.tun.ListenPacket(ctx, destination)
}

// IpcGet returns the device's state in the UAPI format; WARP reads handshakes and traffic from it.
func (d *Device) IpcGet() (string, error) {
	if d.awgDevice == nil {
		return "", os.ErrInvalid
	}
	return d.awgDevice.IpcGet()
}
