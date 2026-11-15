// Package readahead reads a connection in large pieces for a protocol that reads it in small ones.
//
// A VMess or Shadowsocks client reads each chunk of the stream it receives in two reads: the
// encrypted length, 18 bytes, and then the chunk, up to 16 KB. Straight from a socket each of
// them is a system call, two for every 16 KB downloaded. Xray reads the socket 64 KB at a time
// and takes the lengths and chunks out of memory, and downloaded through VMess or Shadowsocks
// over plain TCP at twice the speed. Under such a protocol, a Conn reads the socket up to Size
// at once and serves the small reads from what it read.
//
// What was read ahead is kept in a pooled buffer only until it is taken, so a connection that
// waits holds no buffer: a phone with hundreds of idle connections spends nothing on it.
package readahead

import (
	"net"

	"github.com/sagernet/sing/common/buf"
)

// Size is the most one read of the connection takes.
const Size = 64 << 10

// Conn is a connection whose reads are served from a read of up to Size bytes.
type Conn struct {
	net.Conn
	ahead   *buf.Buffer // read and not taken yet; nil when there is nothing
	pending error       // the error that came with the last read, after its data is taken
}

// New returns conn with its reads taken from reads of up to Size bytes.
func New(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	if _, isAhead := conn.(*Conn); isAhead {
		return conn
	}
	return &Conn{Conn: conn}
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.ahead != nil {
		return c.take(p), nil
	}
	if c.pending != nil {
		err := c.pending
		c.pending = nil
		return 0, err
	}
	if len(p) >= Size {
		return c.Conn.Read(p)
	}
	ahead := buf.NewSize(Size)
	n, err := ahead.ReadOnceFrom(c.Conn)
	if n == 0 {
		ahead.Release()
		return 0, err
	}
	c.ahead, c.pending = ahead, err
	return c.take(p), nil
}

// take copies what was read ahead into p, and gives the buffer back once it is all taken.
func (c *Conn) take(p []byte) int {
	n := copy(p, c.ahead.Bytes())
	c.ahead.Advance(n)
	if c.ahead.IsEmpty() {
		c.ahead.Release()
		c.ahead = nil
	}
	return n
}

// Buffered is how much was read and not taken yet.
func (c *Conn) Buffered() int {
	if c.ahead == nil {
		return 0
	}
	return c.ahead.Len()
}

func (c *Conn) Upstream() any {
	return c.Conn
}

// ReaderReplaceable is false: a read of the connection below would skip what was read ahead.
func (c *Conn) ReaderReplaceable() bool {
	return false
}

func (c *Conn) WriterReplaceable() bool {
	return true
}
