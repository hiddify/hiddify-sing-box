package wireguard

import (
	"context"
	"net"
	"net/netip"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/sendqueue"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The bind's connection through the dialer is made with no lock held, and written without
// waiting for a detour.
//
// The device sends with its locks held, and the first send dials the connection. The dial ran
// under connAccess, which Close takes: a detour that did not answer the dial, or its cancel, held
// the bind and with it the device, which could not close. And a detour that carries UDP in a
// stream blocks a write while its stream is stalled, with the device's locks held just the same.
//
//   - One dial runs at a time, on a goroutine of its own; those who need the connection wait for
//     it or for the bind to close, whichever comes first. A dial that ends after the bind was
//     closed, or opened again, is thrown away. It still gives up after the TCP timeout, so that
//     the senders waiting for it with the device's locks held go on.
//   - A connection that is not a UDP socket is written through a queue (package sendqueue).
//   - hAbort closes the bind for good: the endpoint closes with it first, so no reconnect on its
//     way (a network change, a fallback move) opens the bind again behind the close.

// hDial is a dial on its way: done is closed when it has ended, with conn or err set.
type hDial struct {
	done chan struct{}
	conn *wireConn
	err  error
}

// hConnect returns the bind's connection, dialing it when there is none.
func (c *ClientBind) hConnect() (*wireConn, error) {
	c.connAccess.Lock()
	opened := c.done
	select {
	case <-opened:
		c.connAccess.Unlock()
		return nil, net.ErrClosed
	default:
	}
	if serverConn := c.hLiveConn(); serverConn != nil {
		c.connAccess.Unlock()
		return serverConn, nil
	}
	dial := c.dialing
	if dial == nil {
		dial = &hDial{done: make(chan struct{})}
		c.dialing = dial
		go c.hDial(dial, opened, c.bindCtx, c.connectAddr)
	}
	c.connAccess.Unlock()
	select {
	case <-dial.done:
		return dial.conn, dial.err
	case <-opened:
		return nil, net.ErrClosed // the dial is left to end by itself
	}
}

// hLiveConn is the bind's connection, nil when there is none or it is closed.
func (c *ClientBind) hLiveConn() *wireConn {
	serverConn := c.conn.Load()
	if serverConn == nil {
		return nil
	}
	select {
	case <-serverConn.done:
		return nil
	default:
		return serverConn
	}
}

// hDial dials for the opening of the bind whose done channel is opened.
func (c *ClientBind) hDial(dial *hDial, opened chan struct{}, bindCtx context.Context, address netip.AddrPort) {
	// only the dial is bounded; the connection may live on its context, which ends when the
	// connection closes
	dialCtx, cancelDial := context.WithCancel(bindCtx)
	dialTimer := time.AfterFunc(C.TCPTimeout, cancelDial)
	var packetConn net.PacketConn
	if c.isConnect {
		udpConn, err := c.dialer.DialContext(dialCtx, N.NetworkUDP, M.SocksaddrFromNetIP(address))
		if err == nil {
			packetConn = bufio.NewUnbindPacketConn(udpConn)
		}
		dial.err = err
	} else {
		udpConn, err := c.dialer.ListenPacket(dialCtx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
		if err == nil {
			packetConn = bufio.NewPacketConn(udpConn)
		}
		dial.err = err
	}
	dialTimer.Stop()
	c.connAccess.Lock()
	c.dialing = nil
	if dial.err == nil {
		select {
		case <-opened: // closed while it dialed; opened again, it has another done
			dial.err = net.ErrClosed
		default:
		}
	}
	if dial.err != nil {
		c.connAccess.Unlock()
		cancelDial()
		common.Close(packetConn)
		close(dial.done)
		return
	}
	dial.conn = &wireConn{
		PacketConn: sendqueue.Wrap(packetConn), // a send does not wait for the detour
		done:       make(chan struct{}),
		cancel:     cancelDial,
	}
	c.conn.Store(dial.conn)
	reconnected := c.connected && c.onReconnect != nil
	c.connected = true
	c.connAccess.Unlock()
	if reconnected {
		go c.onReconnect()
	}
	close(dial.done)
}

// hAbort closes the bind for good: its connection and the dial on its way end, those waiting
// for them go on, and it does not open again.
func (c *ClientBind) hAbort() {
	c.connAccess.Lock()
	c.aborted = true
	c.connAccess.Unlock()
	c.Close()
}

// hWaitAfterFailure waits a second before the next try to connect, or until the bind closes.
func (c *ClientBind) hWaitAfterFailure() {
	c.connAccess.Lock()
	opened := c.done
	c.connAccess.Unlock()
	select {
	case <-opened:
	case <-time.After(time.Second):
	}
}
