package wireguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

var _ Device = (*stackDevice)(nil)

type stackDevice struct {
	stack        *tun.Go
	memoryTun    *tun.MemoryTun
	mtu          uint32
	events       chan wgTun.Event
	outbound     chan *buf.Buffer // H: packets from the stack, read by wireguard-go
	closed       chan struct{}
	closeOnce    sync.Once
	inet4Address netip.Addr
	inet6Address netip.Addr
}

func newStackDevice(options DeviceOptions) (*stackDevice, error) {
	inet4Address, inet6Address := deviceAddresses(options.Address)
	device := &stackDevice{
		mtu:          options.MTU,
		events:       make(chan wgTun.Event, 1),
		outbound:     make(chan *buf.Buffer, conn.IdealBatchSize*4),
		closed:       make(chan struct{}),
		inet4Address: inet4Address,
		inet6Address: inet6Address,
	}
	// H: sing-tun's memory TUN pushes the stack's packets; Read hands them to wireguard-go
	device.memoryTun = tun.NewMemoryTun(tun.MemoryTunOptions{MTU: int(options.MTU), Outbound: device.queueOutbound})
	stack, err := newStack(options, device.memoryTun)
	if err != nil {
		return nil, err
	}
	device.stack = stack
	return device, nil
}

func (w *stackDevice) queueOutbound(packets []*buf.Buffer) {
	for i, packet := range packets {
		select {
		case w.outbound <- packet:
		case <-w.closed:
			buf.ReleaseMulti(packets[i:])
			return
		}
	}
}

func (w *stackDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	bind, err := w.bindAddress(destination)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		var tcpConn *tun.GoConn
		tcpConn, err = w.stack.DialTCP(ctx, bind, destination.AddrPort())
		if err != nil {
			return nil, err
		}
		tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 15 * time.Second})
		return tcpConn, nil
	case N.NetworkUDP:
		var udpConn *tun.GoUDPConn
		udpConn, err = w.stack.DialUDP(netip.AddrPortFrom(bind, 0), destination.AddrPort())
		if err != nil {
			return nil, err
		}
		return udpConn, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (w *stackDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind, err := w.bindAddress(destination)
	if err != nil {
		return nil, err
	}
	udpConn, err := w.stack.ListenUDP(netip.AddrPortFrom(bind, 0))
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}

func (w *stackDevice) bindAddress(destination M.Socksaddr) (netip.Addr, error) {
	if destination.IsIPv4() {
		if !w.inet4Address.IsValid() {
			return netip.Addr{}, E.New("missing IPv4 local address")
		}
		return w.inet4Address, nil
	}
	if !w.inet6Address.IsValid() {
		return netip.Addr{}, E.New("missing IPv6 local address")
	}
	return w.inet6Address, nil
}

func (w *stackDevice) Inet4Address() netip.Addr {
	return w.inet4Address
}

func (w *stackDevice) Inet6Address() netip.Addr {
	return w.inet6Address
}

func (w *stackDevice) SetDevice(device *device.Device) {
}

func (w *stackDevice) Start() error {
	err := w.stack.Start()
	if err != nil {
		return err
	}
	w.events <- wgTun.EventUp
	return nil
}

func (w *stackDevice) File() *os.File {
	return nil
}

func (w *stackDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var packet *buf.Buffer
	select {
	case packet = <-w.outbound:
	case <-w.closed:
		return 0, os.ErrClosed
	}
	count := 0
	for {
		sizes[count] = copy(bufs[count][offset:], packet.Bytes())
		packet.Release()
		count++
		if count == len(bufs) {
			return count, nil
		}
		select {
		case packet = <-w.outbound:
		default:
			return count, nil
		}
	}
}

func (w *stackDevice) Write(bufs [][]byte, offset int) (int, error) {
	packets := make([][]byte, 0, len(bufs))
	for _, packet := range bufs {
		packets = append(packets, packet[offset:])
	}
	return w.memoryTun.WritePackets(packets)
}

func (w *stackDevice) Flush() error {
	return nil
}

func (w *stackDevice) MTU() (int, error) {
	return int(w.mtu), nil
}

func (w *stackDevice) Name() (string, error) {
	return "sing-box", nil
}

func (w *stackDevice) Events() <-chan wgTun.Event {
	return w.events
}

func (w *stackDevice) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.events)
		close(w.closed)
		err = E.Errors(w.stack.Close(), w.memoryTun.Close())
		for {
			select {
			case packet := <-w.outbound:
				packet.Release()
			default:
				return
			}
		}
	})
	return err
}

func (w *stackDevice) BatchSize() int {
	return conn.IdealBatchSize
}
