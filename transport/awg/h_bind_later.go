package awg

import (
	"net"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// A bind whose connection to the peer cannot be made when it opens: a detour that is not ready
// yet (another WireGuard endpoint still starting, a selector with no working outbound) fails the
// dial. The device's start used to fail with it, for good. Instead the bind opens without the
// connection and dials it again each second, in its receive loop, until the detour lets it.

const laterInterval = time.Second

// openLater opens the bind without its connection to the peer; b.mutex is held.
func (b *bind_adapter) openLater(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	done := make(chan struct{})
	b.later = done
	peer := b.peer
	var peerConn net.PacketConn // only the receive loop uses it
	return []conn.ReceiveFunc{func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if peerConn == nil {
			select {
			case <-done:
				return 0, net.ErrClosed
			case <-time.After(laterInterval):
			}
			dialed, err := b.connect(peer.Addr(), peer.Port())
			if err != nil {
				return 0, nil // the receive loop calls again
			}
			b.mutex.Lock()
			select {
			case <-done:
				b.mutex.Unlock()
				dialed.Close()
				return 0, net.ErrClosed
			default:
			}
			if peer.Addr().Is4() || peer.Addr().Is4In6() {
				b.conn4 = dialed
			} else {
				b.conn6 = dialed
			}
			b.mutex.Unlock()
			peerConn = dialed
		}
		return b.receive(peerConn)(packets, sizes, eps)
	}}, port, nil
}

// closeLater stops a receive loop still dialing; b.mutex is held.
func (b *bind_adapter) closeLater() {
	if b.later != nil {
		close(b.later)
		b.later = nil
	}
}

// sendConn is the connection for a packet to ep: read under the lock, as openLater sets it late.
func (b *bind_adapter) sendConn(ep conn.Endpoint) net.PacketConn {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if ep.DstIP().Is6() {
		return b.conn6
	}
	return b.conn4
}
