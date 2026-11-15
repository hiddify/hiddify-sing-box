package route

import (
	"net"
	"sync/atomic"
	"time"
)

// A paced socket may be late by a small part of its path's round trip, and no more.
//
// A wait of a millisecond is nothing on a path that takes 50 ms there and back. On a path that
// takes a fifth of a millisecond (this machine, the local network, a server in the same rack) it
// is five round trips: the peer's congestion control sees every acknowledgement late and slows
// down, and an exchange of questions and answers takes six times as long. Measured over loopback,
// with waits of 0.2 to 1 ms: a Hysteria2 download at a third of its speed, uploads through QUIC
// and OpenVPN 20 to 30% slower, and a round trip of 0.3 ms where it had been 0.18.
//
// So the round trip is measured, at the socket, from what every protocol begins with: it writes,
// and the peer answers (a QUIC or OpenVPN handshake, a DNS query). The time from the first
// datagram written to the first one that arrives is the round trip plus the time the peer took
// to answer, so it is never too short. A socket whose round trip is not known, or whose peer is
// this machine, is not paced.
const (
	pathShare = 32                    // a wait is at most this part of the round trip
	pathLate  = 20 * time.Millisecond // a reader that began to wait this long after the first write did not see the first answer
)

// pathRTT measures the round trip of one socket's path.
type pathRTT struct {
	created   int64        // when the socket was made, unix nanoseconds
	written   atomic.Int64 // when the first datagram was written; 0 until then
	local     atomic.Bool  // the peer is this machine
	answered  atomic.Bool  // something has arrived
	roundTrip atomic.Int64 // nanoseconds; 0 while it is not known
}

func (p *pathRTT) init(conn any) {
	p.created = time.Now().UnixNano()
	if remote, hasRemote := conn.(interface{ RemoteAddr() net.Addr }); hasRemote {
		p.peer(remote.RemoteAddr())
	}
}

// peer notes a peer on this machine.
func (p *pathRTT) peer(addr net.Addr) {
	switch address := addr.(type) {
	case *net.UDPAddr:
		if address != nil && address.IP.IsLoopback() {
			p.local.Store(true)
		}
	case *net.TCPAddr:
		if address != nil && address.IP.IsLoopback() {
			p.local.Store(true)
		}
	}
}

// wrote is called for every datagram written; it reads the clock for the first one only.
func (p *pathRTT) wrote() {
	if p.written.Load() == 0 {
		p.written.CompareAndSwap(0, time.Now().UnixNano())
	}
}

// wroteTo is wrote for a datagram written to addr.
func (p *pathRTT) wroteTo(addr net.Addr) {
	if p.written.Load() == 0 {
		p.peer(addr)
		p.written.CompareAndSwap(0, time.Now().UnixNano())
	}
}

// read is called when a read brought something without waiting for it: nothing tells when it
// arrived, so the first answer was not timed.
func (p *pathRTT) read() {
	if !p.answered.Load() {
		p.answered.Store(true)
	}
}

// arrived is called when a reader that waited since since is woken, at now.
func (p *pathRTT) arrived(since time.Time, now time.Time) {
	if p.answered.Load() {
		return
	}
	p.answered.Store(true)
	written := p.written.Load()
	if written == 0 {
		// written before this socket was tracked, or by a way that is not seen here: not before
		// the socket was made
		written = p.created
	}
	if time.Duration(since.UnixNano()-written) > pathLate {
		return
	}
	p.roundTrip.Store(max(now.UnixNano()-written, 0))
}

// longestWait is how long a read of this socket may be held back: nothing while the round trip
// is not known or the peer is this machine.
func (p *pathRTT) longestWait() time.Duration {
	if p.local.Load() {
		return 0
	}
	return time.Duration(p.roundTrip.Load()) / pathShare
}
