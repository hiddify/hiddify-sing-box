package soar

import (
	"context"
	"net"
	"os"
	"sync"
	"time"
)

// splitPacketConn is the Soar client's one UDP socket when it has the smart pool and discovered
// resolvers at once: datagrams to the pool go through a plain loopback socket, the rest through
// the outbound's protected socket, which may be bound to the outside interface and so unable to
// reach the loopback. Reads come from both.
type splitPacketConn struct {
	pool    *net.UDPAddr
	local   net.PacketConn // to the pool
	outside net.PacketConn // to the resolvers

	packets   chan packet
	done      chan struct{}
	closeOnce sync.Once

	deadlineMu sync.Mutex
	deadlineCh chan struct{} // replaced on every SetReadDeadline, closed when it passes
}

type packet struct {
	data []byte
	addr net.Addr
	err  error
}

func newSplitPacketConn(ctx context.Context, pool *net.UDPAddr, listenOutside func(context.Context) (net.PacketConn, error)) (net.PacketConn, error) {
	var lc net.ListenConfig
	local, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort(pool.IP.String(), "0"))
	if err != nil {
		return nil, err
	}
	outside, err := listenOutside(ctx)
	if err != nil {
		local.Close()
		return nil, err
	}
	c := &splitPacketConn{
		pool:       pool,
		local:      local,
		outside:    outside,
		packets:    make(chan packet, 64),
		done:       make(chan struct{}),
		deadlineCh: make(chan struct{}),
	}
	go c.readLoop(local)
	go c.readLoop(outside)
	return c, nil
}

func (c *splitPacketConn) readLoop(conn net.PacketConn) {
	for {
		buffer := make([]byte, 65535)
		n, addr, err := conn.ReadFrom(buffer)
		select {
		case c.packets <- packet{data: buffer[:n], addr: addr, err: err}:
		case <-c.done:
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *splitPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select { // closed is closed, even with a deadline that passed too
	case <-c.done:
		return 0, nil, net.ErrClosed
	default:
	}
	c.deadlineMu.Lock()
	deadlineCh := c.deadlineCh
	c.deadlineMu.Unlock()
	select {
	case pk := <-c.packets:
		if pk.err != nil {
			return 0, nil, pk.err
		}
		return copy(p, pk.data), pk.addr, nil
	case <-deadlineCh:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *splitPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr.IP.Equal(c.pool.IP) && udpAddr.Port == c.pool.Port {
		return c.local.WriteTo(p, addr)
	}
	return c.outside.WriteTo(p, addr)
}

func (c *splitPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.local.Close()
		c.outside.Close()
	})
	return nil
}

func (c *splitPacketConn) LocalAddr() net.Addr {
	return c.outside.LocalAddr()
}

func (c *splitPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *splitPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	ch := make(chan struct{})
	c.deadlineCh = ch
	if !t.IsZero() {
		if wait := time.Until(t); wait <= 0 {
			close(ch)
		} else {
			time.AfterFunc(wait, func() {
				c.deadlineMu.Lock()
				defer c.deadlineMu.Unlock()
				if c.deadlineCh == ch {
					close(ch)
				}
			})
		}
	}
	return nil
}

func (c *splitPacketConn) SetWriteDeadline(t time.Time) error {
	_ = c.local.SetWriteDeadline(t)
	return c.outside.SetWriteDeadline(t)
}
