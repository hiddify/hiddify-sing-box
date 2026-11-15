package readahead

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// A protocol connection over a Conn hands the copy loop several chunks at a time.
//
// Read ahead, a VMess or Shadowsocks client still gives the copy loop one decrypted chunk of up
// to 16 KB at a time, and the copy loop writes each to the application in a system call of its
// own. Xray writes what it decrypted from one read of the socket in one call. So the reader of a
// Batch takes, after the chunk it waited for, the chunks that are already read ahead in full
// into the same buffer, up to batchSize: one write for four chunks instead of four. It never
// waits for a chunk that has not arrived, so what came is handed on at once.

const batchSize = 64 << 10

// Batch returns conn, a protocol's connection that reads its chunks from ahead, with a reader that
// gathers chunks: further chunks are taken while one of wire bytes on the wire, the largest the
// protocol may send, is read ahead in full and plain bytes of it fit in the buffer. The protocol's
// reader must keep what does not fit in a read for the next one, as Shadowsocks's does; VMess's
// fails on a read shorter than its chunk, whose length it does not bound below 64 KB. With ahead
// not a Conn, conn is returned as it is.
func Batch(conn net.Conn, ahead net.Conn, wire int, plain int) net.Conn {
	aheadConn, isAhead := ahead.(*Conn)
	if conn == nil || !isAhead || wire <= 0 || plain <= 0 || plain > batchSize/2 {
		return conn
	}
	return &batchConn{Conn: conn, ahead: aheadConn, wire: wire, plain: plain}
}

type batchConn struct {
	net.Conn
	ahead   *Conn
	wire    int
	plain   int
	options N.ReadWaitOptions
	pending error // an error that came after data, returned by the next read
}

var _ N.ReadWaiter = (*batchConn)(nil)

func (c *batchConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.options = options
	return false
}

func (c *batchConn) WaitReadBuffer() (*buf.Buffer, error) {
	if c.pending != nil {
		err := c.pending
		c.pending = nil
		return nil, err
	}
	buffer := c.options.NewBufferSize(batchSize)
	var (
		n   int
		err error
	)
	for tries := 0; n == 0 && err == nil; tries++ {
		if tries == 100 {
			err = errNoProgress // as io.ReadAtLeast: a reader that keeps bringing nothing
			break
		}
		n, err = c.Conn.Read(buffer.FreeBytes())
	}
	if n == 0 {
		buffer.Release()
		return nil, err
	}
	buffer.Extend(n)
	for err == nil && buffer.FreeLen() >= c.plain && c.ahead.Buffered() >= c.wire {
		n, err = c.Conn.Read(buffer.FreeBytes())
		if n == 0 {
			break
		}
		buffer.Extend(n)
	}
	if err != nil {
		c.pending = err
	}
	c.options.PostReturn(buffer)
	return buffer, nil
}

func (c *batchConn) Upstream() any {
	return c.Conn
}

// ReaderReplaceable is false: the copy loop reads through the batch.
func (c *batchConn) ReaderReplaceable() bool {
	return false
}

func (c *batchConn) WriterReplaceable() bool {
	return true
}
