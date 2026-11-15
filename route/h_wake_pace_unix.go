//go:build unix

package route

import (
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"
)

// datagramRead is one plain read of a busy datagram socket, done through the paced raw
// connection: the read is tried, and when the socket is empty the reader waits for it there, where
// its wake-up is paced.
type datagramRead struct {
	buffer []byte
	n      int
	err    error
	eof    bool
	step   func(fd uintptr) bool // try, bound once
}

func (r *datagramRead) try(fd uintptr) bool {
	for {
		r.n, r.err = syscall.Read(int(fd), r.buffer)
		if r.err != syscall.EINTR {
			break
		}
	}
	if r.err == syscall.EAGAIN {
		return false
	}
	if r.err == nil && r.n == 0 {
		r.eof = control.IsUDPEOF(fd) // as the dialer's connection does, for a connected socket on BSD
	}
	return true
}

// readDatagram reads one datagram of a connected socket. While the socket is not busy this is the
// connection's own read; a busy socket's goes through the paced raw connection.
func (c *trackedConn) readDatagram(b []byte) (int, error) {
	if !c.rate.busy || c.raw == nil {
		if c.raw != nil && !c.wake.path.answered.Load() {
			return c.readFirstDatagram(b)
		}
		n, err := c.Conn.Read(b)
		if n > 0 && c.raw != nil {
			c.rate.count()
		}
		return n, err
	}
	c.reading.Lock()
	defer c.reading.Unlock()
	read := &c.read
	if read.step == nil {
		read.step = read.try
	}
	read.buffer, read.n, read.err, read.eof = b, 0, nil, false
	err := c.raw.Read(read.step)
	read.buffer = nil
	if err != nil {
		return 0, err
	}
	if read.err != nil {
		return 0, &net.OpError{Op: "read", Net: c.LocalAddr().Network(), Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: os.NewSyscallError("read", read.err)}
	}
	if read.eof {
		return 0, io.EOF
	}
	if read.n > 0 {
		c.rate.count()
	}
	return read.n, nil
}

// datagramWaited is how long a plain read takes at least when it had to wait for its datagram.
const datagramWaited = 50 * time.Microsecond

// readFirstDatagram reads the first datagram of a socket, the answer to the first one written,
// and times it for the round trip of the socket's path.
func (c *trackedConn) readFirstDatagram(b []byte) (int, error) {
	since := time.Now()
	n, err := c.Conn.Read(b)
	if n > 0 {
		if now := time.Now(); now.Sub(since) >= datagramWaited {
			c.wake.path.arrived(since, now)
		} else {
			c.wake.path.read() // it was there already: nothing tells when it arrived
		}
		c.rate.count()
	}
	return n, err
}
