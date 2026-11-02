// The oob mask is ported from patterniha/Xray-core's "oob." dialMode
// (https://github.com/patterniha/xray-core, transport/internet/dialmode_oob*.go, Mozilla Public
// License 2.0). Changes: it is a tcp mask with a bytes setting instead of a dialMode string.

package finalmask

import (
	"errors"
	"net"
	"syscall"

	xnet "github.com/xtls/xray-core/common/net"
	xfinalmask "github.com/xtls/xray-core/transport/internet/finalmask"
)

// OOBMask sends each of the first len(bytes) writes of a TCP connection with one more byte,
// bytes[i] for write i, as TCP urgent (out-of-band) data; later writes pass through. The server's
// TCP stack takes the urgent byte out of the stream, while a filter that mishandles the urgent
// pointer reads those segments (a TLS ClientHello) wrong. It is Xray's dialMode "oob.<b>,<b>,...".
// It must be the last tcp mask, the one next to the socket; a connection that is not a socket is
// left as it is.
type OOBMask struct {
	Bytes []int `json:"bytes"`
}

func (c *OOBMask) BuildTcpmask() (xfinalmask.TCPMask, error) {
	if len(c.Bytes) == 0 {
		return nil, errors.New("bytes is empty")
	}
	for _, b := range c.Bytes {
		if b < 0 || b > 255 {
			return nil, errors.New("bytes must be from 0 to 255")
		}
	}
	return &oobTcpmask{bytes: append([]int(nil), c.Bytes...)}, nil
}

type oobTcpmask struct {
	bytes []int
}

func (m *oobTcpmask) WrapConnClient(conn net.Conn, _ *xnet.Destination, _ *xfinalmask.Dialer) (net.Conn, error) {
	oobBytes := make([]byte, len(m.bytes))
	for i, b := range m.bytes {
		oobBytes[i] = byte(b)
	}
	return &oobConn{Conn: conn, oobBytes: oobBytes}, nil
}

func (m *oobTcpmask) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

type oobConn struct {
	net.Conn
	oobBytes []byte
	index    int
}

func (c *oobConn) Write(p []byte) (int, error) {
	if c.index >= len(c.oobBytes) {
		return c.Conn.Write(p)
	}
	oobByte := c.oobBytes[c.index]
	c.index++
	sc, ok := c.Conn.(syscall.Conn)
	if !ok || !oobSupported {
		return c.Conn.Write(p)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return c.Conn.Write(p)
	}
	data := make([]byte, len(p)+1)
	copy(data, p)
	data[len(p)] = oobByte
	var (
		sent    int
		sendErr error
	)
	controlErr := raw.Write(func(fd uintptr) bool {
		n, err := sendOOB(fd, data)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return false // not writable yet: wait and send again
		}
		sent, sendErr = n, err
		return true
	})
	if controlErr != nil {
		return 0, controlErr
	}
	if sendErr != nil {
		return 0, sendErr
	}
	if sent > len(p) {
		sent = len(p) // the urgent byte is not the caller's
	}
	if sent < len(p) {
		n, err := c.Conn.Write(p[sent:])
		return sent + n, err
	}
	return len(p), nil
}

// SyscallConn keeps the read side's fast path.
func (c *oobConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("oob: the connection is not a syscall.Conn")
}
