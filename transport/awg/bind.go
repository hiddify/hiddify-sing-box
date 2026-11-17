package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

var _ conn.Bind = (*bind_adapter)(nil)

type bind_adapter struct {
	conn4  net.PacketConn
	conn6  net.PacketConn
	dialer N.Dialer
	ctx    context.Context
	mutex  sync.Mutex
	// peer, when valid, is the only peer: the bind opens one packet connection to it instead of
	// two to any address. A proxy whose UDP needs a destination (an HTTP proxy's UDP, for one)
	// refused the connections to 0.0.0.0, and the endpoint never started.
	peer     netip.AddrPort
	reserved *Reserved
	opens    int                  //H: see h_path.go
	onReopen func()               //H
	open     *hBindOpen           //H: the current opening, see h_bind_later.go
	aborted  bool                 //H: closed for good, see abort
	held     [2][]hHeldPacket     //H: sent while a connection was being made, see h_bind_later.go
	logger   logger.ContextLogger //H
	pending  bool                 //H: the only peer, given by a domain, is not resolved yet
	failedTx atomic.Uint64        //H: bytes of the sends that failed, see h_path.go
}

func newBind(ctx context.Context, dial N.Dialer, peer netip.AddrPort, reserved *Reserved) conn.Bind {
	return &bind_adapter{
		ctx:      ctx,
		dialer:   dial,
		peer:     peer,
		reserved: reserved,
		logger:   logger.NOP(), //H
	}
}

func (b *bind_adapter) receive(c net.PacketConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		n, addr, err := c.ReadFrom(packets[0])
		if err != nil {
			return 0, E.Cause(err, "read data")
		}

		bindEp, err := b.ParseEndpoint(addr.String())
		if err != nil {
			return 0, E.Cause(err, "parse endpoint")
		}

		b.reserved.clear(packets[0][:n])
		sizes[0] = n
		eps[0] = bindEp
		return 1, nil
	}
}

func (b *bind_adapter) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.aborted { //H
		return nil, 0, net.ErrClosed //H
	} //H
	if b.open != nil { //H
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.noteOpen() //H: a path change, after the first

	// H: the connections are dialed by the receive loops, see h_bind_later.go: the device calls
	// Open under its locks, and a dial through a detour may take as long as the detour likes
	return b.openLater(port) //H
}

func (b *bind_adapter) Close() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.closeLocked() //H
}

func (b *bind_adapter) closeLocked() error { //H
	var err4, err6 error
	b.closeLater() //H

	if b.conn4 != nil {
		err4 = closeConn(b.conn4) //H: closed already by a network change
		b.conn4 = nil
	}

	if b.conn6 != nil {
		err6 = closeConn(b.conn6) //H
		b.conn6 = nil
	}

	return errors.Join(err4, err6)
}

// abort closes the bind for good: its connections and the dials on their way end, and it does
// not open again. The device closes with it first, so that nothing of the device waits on the
// detour while it closes, and a reconnect that was on its way (a fallback move, a network
// change) cannot open the bind again behind the close. //H
func (b *bind_adapter) abort() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.aborted = true
	b.closeLocked()
	b.dropHeld()
}

func (b *bind_adapter) SetMark(mark uint32) error {
	return nil
}

func (b *bind_adapter) Send(bufs [][]byte, ep conn.Endpoint) error {
	conn := b.sendConn(bufs, ep) //H: set by the receive loop, once it has dialed

	if conn == nil {
		return errors.ErrUnsupported
	}

	bindEp, ok := ep.(*bind_endpoint)
	if !ok {
		return errors.ErrUnsupported
	}

	udpAddr := &net.UDPAddr{
		IP:   bindEp.AddrPort.Addr().AsSlice(),
		Port: int(bindEp.AddrPort.Port()),
	}

	for _, buf := range bufs {
		b.reserved.write(buf)
		if _, err := conn.WriteTo(buf, udpAddr); err != nil {
			b.noteFailedSend(bufs) //H
			return err
		}
	}

	return nil
}

func (b *bind_adapter) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, E.Cause(err, "parse addrport")
	}

	return &bind_endpoint{AddrPort: ap}, nil
}

func (b *bind_adapter) BatchSize() int {
	return 1
}

var _ conn.Endpoint = (*bind_endpoint)(nil)

type bind_endpoint struct {
	AddrPort netip.AddrPort
}

func (e bind_endpoint) ClearSrc() {
}

func (e bind_endpoint) SrcToString() string {
	return ""
}

func (e bind_endpoint) DstToString() string {
	return e.AddrPort.String()
}

func (e bind_endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e bind_endpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

func (e bind_endpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
