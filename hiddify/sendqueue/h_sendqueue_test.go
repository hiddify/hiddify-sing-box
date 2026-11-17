package sendqueue

import (
	"net"
	"sync"
	"testing"
	"time"
)

// stalledConn is a detour whose stream stalled: a write blocks until the connection closes.
type stalledConn struct {
	net.PacketConn
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *stalledConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stalledConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// A connection that is not a UDP socket takes sends through its queue and drops what the queue
// cannot take; a UDP socket is written directly.
func TestH_WrapQueuesForADetour(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if Wrap(socket) != socket {
		t.Fatal("a UDP socket is queued")
	}

	stalled := &stalledConn{closed: make(chan struct{})}
	queued := Wrap(stalled)
	sent := make(chan error, 1)
	go func() {
		for range Size * 4 {
			if n, sendErr := queued.WriteTo([]byte("packet"), socket.LocalAddr()); sendErr != nil || n != 6 {
				sent <- sendErr
				return
			}
		}
		sent <- nil
	}()
	select {
	case err = <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a send waits for the detour")
	}
	if err = queued.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = queued.WriteTo([]byte("packet"), socket.LocalAddr()); err != net.ErrClosed {
		t.Fatal("a send after Close: ", err)
	}
	select {
	case <-stalled.closed:
	default:
		t.Fatal("closing the queue did not close the connection")
	}
}

// What is queued arrives, in order.
func TestH_WrapDelivers(t *testing.T) {
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	queued := Wrap(notASocket{sender}) // as a detour's connection: not a *net.UDPConn
	defer queued.Close()
	for _, payload := range []string{"one", "two", "three"} {
		if _, err = queued.WriteTo([]byte(payload), receiver.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	buffer := make([]byte, 16)
	receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	for _, payload := range []string{"one", "two", "three"} {
		n, _, readErr := receiver.ReadFrom(buffer)
		if readErr != nil || string(buffer[:n]) != payload {
			t.Fatalf("got %q, %v; want %q", buffer[:n], readErr, payload)
		}
	}
}

type notASocket struct{ conn net.PacketConn }

func (c notASocket) ReadFrom(p []byte) (int, net.Addr, error) { return c.conn.ReadFrom(p) }
func (c notASocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.conn.WriteTo(p, addr)
}
func (c notASocket) Close() error                       { return c.conn.Close() }
func (c notASocket) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c notASocket) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c notASocket) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c notASocket) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
