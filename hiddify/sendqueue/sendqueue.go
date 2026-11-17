// Package sendqueue keeps a send through a detour from holding the WireGuard or AmneziaWG device.
//
// The device sends with its network lock held, and a handshake also with the peer's lock and, at
// Up, the device's state lock: a status read, a reconnect of the bind and the close all wait for
// them. A UDP socket takes a packet or refuses it at once. A detour that carries UDP in a stream
// (VMess, VLESS, Trojan, anything over a multiplexed or TCP connection) blocks the write while
// its stream is stalled, for as long as that lasts: the device was then stuck behind one packet,
// and neither a move to a fallback address nor the close could get through.
//
// So a connection that is not a UDP socket is written by a goroutine of its own, from a queue:
// the bind's send only puts the packet there. When the queue is full the packet is dropped, as a
// socket drops what its buffer cannot take. A UDP socket is written directly, as before.
package sendqueue

import (
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

// Size is how many packets may wait for a detour; about 350 KB of full-size packets.
const Size = 256

// Wrap is conn with sends that return at once: conn itself when it is a UDP socket, a queue in
// front of it otherwise. Closing the result closes conn.
func Wrap(conn net.PacketConn) net.PacketConn {
	if _, isSocket := common.Cast[*net.UDPConn](conn); isSocket {
		return conn
	}
	queued := &queuedConn{
		PacketConn: conn,
		queue:      make(chan packet, Size),
		done:       make(chan struct{}),
	}
	go queued.loop()
	return queued
}

type packet struct {
	buffer *buf.Buffer
	addr   net.Addr
}

type queuedConn struct {
	net.PacketConn
	queue     chan packet
	done      chan struct{}
	closeOnce sync.Once
}

func (c *queuedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	buffer := buf.NewSize(len(p))
	common.Must1(buffer.Write(p))
	select {
	case c.queue <- packet{buffer: buffer, addr: addr}:
	default:
		buffer.Release() // the detour does not take them this fast, or not at all
	}
	return len(p), nil
}

func (c *queuedConn) loop() {
	for {
		select {
		case <-c.done:
			return
		case next := <-c.queue:
			_, err := c.PacketConn.WriteTo(next.buffer.Bytes(), next.addr)
			next.buffer.Release()
			if errors.Is(err, net.ErrClosed) {
				return
			}
		}
	}
}

func (c *queuedConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return c.PacketConn.Close()
}

func (c *queuedConn) Upstream() any {
	return c.PacketConn
}
