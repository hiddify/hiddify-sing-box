package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/sagernet/sing-box/hiddify/sendqueue"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// The bind's connections are dialed by its receive loops, not by Open.
//
// The device calls Open with its network lock held (and, at Up, its state lock), and every send,
// every status read and the close wait for that lock. A dial through a detour takes as long as
// the detour likes: one that is not ready fails, and one whose stream stalled does not answer at
// all. Dialed in Open, a detour that was not ready failed the device's start for good, and one
// that did not answer held the device, which then could not even close.
//
// So Open returns at once, and each receive loop dials its connection, again each second while
// the detour refuses, with no lock held. A send that finds no connection yet is reported as
// failed, as nothing went out, but its packets are kept for a moment and go out when the
// connection is there: the first handshake of a start, or of a reconnect, is not lost to wait
// for the device's retry 5 seconds later. A dial that ends after the bind was closed, or opened
// again, is thrown away.

const laterInterval = time.Second

// hHeldPackets is how many packets wait for a connection being made, per address family, and
// hHeldFor how long: a handshake older than that has been sent again by the device.
const (
	hHeldPackets = 16
	hHeldFor     = 5 * time.Second
)

type hHeldPacket struct {
	buffer *buf.Buffer
	addr   *net.UDPAddr
	at     time.Time
}

// hBindOpen is one opening of the bind: Close, or abort, ends it and its dials.
type hBindOpen struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// openLater opens the bind without its connections; b.mutex is held.
func (b *bind_adapter) openLater(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	ctx, cancel := context.WithCancel(b.ctx)
	open := &hBindOpen{ctx: ctx, cancel: cancel}
	b.open = open
	switch {
	case b.peer.IsValid():
		// the only peer: one connection to it, instead of two to any address. A proxy whose UDP
		// needs a destination (an HTTP proxy's UDP, for one) refuses the connections to 0.0.0.0
		return []conn.ReceiveFunc{b.receiveLater(open, b.peer.Addr(), b.peer.Port(), false)}, port, nil
	case b.pending:
		// a peer given by a domain, before it is resolved: no connection, as the any-address ones
		// may be refused. Resolving the peer sets its address and opens the bind again
		return []conn.ReceiveFunc{func([][]byte, []int, []conn.Endpoint) (int, error) {
			<-ctx.Done()
			return 0, net.ErrClosed
		}}, port, nil
	default:
		return []conn.ReceiveFunc{
			b.receiveLater(open, netip.IPv4Unspecified(), port, true),
			b.receiveLater(open, netip.IPv6Unspecified(), port, true),
		}, port, nil
	}
}

// receiveLater is the receive loop of one connection of open, to address: it dials the
// connection, then reads from it.
func (b *bind_adapter) receiveLater(open *hBindOpen, address netip.Addr, port uint16, anyAddress bool) conn.ReceiveFunc {
	var (
		receive conn.ReceiveFunc // of the connection, once dialed; only the receive loop uses these
		failed  bool
	)
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if receive == nil {
			if failed {
				select {
				case <-open.ctx.Done():
					return 0, net.ErrClosed
				case <-time.After(laterInterval):
				}
			}
			dialed, err := b.dial(open, address, port)
			if err != nil {
				if open.ctx.Err() != nil {
					return 0, net.ErrClosed
				}
				if anyAddress && errors.Is(err, syscall.EAFNOSUPPORT) {
					return 0, net.ErrClosed // the system has no such addresses: the other loop serves
				}
				if !failed {
					b.logger.Debug("connect to ", netip.AddrPortFrom(address, port), ": ", err, "; trying again each second")
				}
				failed = true
				return 0, nil // the device's receive loop calls again
			}
			if !b.adopt(open, address, dialed) {
				dialed.Close()
				return 0, net.ErrClosed
			}
			receive, failed = b.receive(dialed), false
		}
		n, err := receive(packets, sizes, eps)
		if err != nil && open.ctx.Err() != nil {
			return 0, net.ErrClosed // whatever a closed connection of the detour answers
		}
		return n, err
	}
}

// dial makes a connection of open through the dialer, with no lock held. When open ends first
// the dial is left to end by itself, as a detour may not answer the cancel, and its connection
// is closed when it comes.
func (b *bind_adapter) dial(open *hBindOpen, address netip.Addr, port uint16) (net.PacketConn, error) {
	type result struct {
		conn net.PacketConn
		err  error
	}
	results := make(chan result, 1)
	go func() {
		dialed, err := b.dialer.ListenPacket(open.ctx, M.Socksaddr{Addr: address, Port: port})
		results <- result{dialed, err}
	}()
	select {
	case dialed := <-results:
		if dialed.err != nil {
			return nil, dialed.err
		}
		return sendqueue.Wrap(dialed.conn), nil // a send does not wait for the detour
	case <-open.ctx.Done():
		go func() {
			if dialed := <-results; dialed.conn != nil {
				dialed.conn.Close()
			}
		}()
		return nil, net.ErrClosed
	}
}

// adopt makes dialed the bind's connection for address's family, and sends what was kept for it;
// false when open is over: the bind was closed, or opened again, while it dialed.
func (b *bind_adapter) adopt(open *hBindOpen, address netip.Addr, dialed net.PacketConn) bool {
	family := 0
	if !address.Is4() && !address.Is4In6() {
		family = 1
	}
	b.mutex.Lock()
	if b.open != open {
		b.mutex.Unlock()
		return false
	}
	if family == 0 {
		b.conn4 = dialed
	} else {
		b.conn6 = dialed
	}
	held := b.held[family]
	b.held[family] = nil
	b.mutex.Unlock()
	for _, packet := range held {
		if time.Since(packet.at) < hHeldFor {
			dialed.WriteTo(packet.buffer.Bytes(), packet.addr)
		}
		packet.buffer.Release()
	}
	return true
}

// closeLater ends the current opening and its dials; b.mutex is held.
func (b *bind_adapter) closeLater() {
	if b.open != nil {
		b.open.cancel()
		b.open = nil
	}
}

// sendConn is the connection for packets to ep: read under the lock, as the receive loop sets
// it. While there is none, it is nil and the packets are kept for the one being made.
func (b *bind_adapter) sendConn(bufs [][]byte, ep conn.Endpoint) net.PacketConn {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	family, sendConn := 0, b.conn4
	if ep.DstIP().Is6() {
		family, sendConn = 1, b.conn6
	}
	if sendConn != nil || b.open == nil {
		return sendConn
	}
	bindEp, isBind := ep.(*bind_endpoint)
	if !isBind {
		return nil
	}
	addr := &net.UDPAddr{IP: bindEp.AddrPort.Addr().AsSlice(), Port: int(bindEp.AddrPort.Port())}
	for _, packet := range bufs {
		if len(b.held[family]) == hHeldPackets {
			b.held[family][0].buffer.Release()
			b.held[family] = b.held[family][1:]
		}
		b.reserved.write(packet)
		buffer := buf.NewSize(len(packet))
		common.Must1(buffer.Write(packet))
		b.held[family] = append(b.held[family], hHeldPacket{buffer: buffer, addr: addr, at: time.Now()})
	}
	return nil
}

// dropHeld forgets the packets kept for a connection; b.mutex is held.
func (b *bind_adapter) dropHeld() {
	for family := range b.held {
		for _, packet := range b.held[family] {
			packet.buffer.Release()
		}
		b.held[family] = nil
	}
}
