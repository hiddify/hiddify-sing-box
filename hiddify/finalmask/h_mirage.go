// The mirage mask wraps PoriyaVali/mirage (https://github.com/PoriyaVali/mirage, MIT License,
// branch mirage-reliability-20261024), which does the splitting.

package finalmask

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/PoriyaVali/mirage"
	xnet "github.com/xtls/xray-core/common/net"
	xfinalmask "github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	mirageLayoutSeparate = "separate"
	mirageLayoutSingle   = "single"
)

// MirageMask splits the TLS ClientHello that opens a connection into two TLS records, the first
// offset bytes of the handshake long. A filter that matches the server name in one record misses
// it; the real server reassembles the handshake. layout "separate" (the default) writes each
// record on its own, layout "single" writes both in one write; which one a filter lets through
// changes by network and over time. Anything that is not a complete ClientHello with a server
// name is sent unchanged. Replies are not changed. Put it last in tcp, or after the masks that
// must see the plain ClientHello.
type MirageMask struct {
	Offset int    `json:"offset"`
	Layout string `json:"layout"`
}

func (c *MirageMask) BuildTcpmask() (xfinalmask.TCPMask, error) {
	if c.Offset < 0 || c.Offset >= 1<<14 {
		return nil, errors.New("offset must be from 0 to 16383")
	}
	switch c.Layout {
	case "", mirageLayoutSeparate:
		return &mirageTcpmask{offset: c.Offset}, nil
	case mirageLayoutSingle:
		return &mirageTcpmask{offset: c.Offset, single: true}, nil
	}
	return nil, errors.New(`layout must be "separate" or "single"`)
}

type mirageTcpmask struct {
	offset int // 0 is mirage's default
	single bool
}

func (m *mirageTcpmask) WrapConnClient(conn net.Conn, _ *xnet.Destination, _ *xfinalmask.Dialer) (net.Conn, error) {
	if m.single {
		return &mirageSingleConn{Conn: conn, offset: m.offset}, nil
	}
	return mirage.NewConn(conn, m.offset), nil
}

// WrapConnServer leaves the connection as it is: mirage only shapes what a client sends.
func (m *mirageTcpmask) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

// mirageSingleConn sends the split ClientHello, and any bytes after it in the same write, in one
// write (mirage.Split). Only the first non-empty write is looked at.
type mirageSingleConn struct {
	net.Conn
	offset int

	mu      sync.Mutex
	started bool
}

func (c *mirageSingleConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return c.Conn.Write(b)
	}
	defer c.mu.Unlock()
	c.started = true
	if len(b) < 5 {
		return c.Conn.Write(b)
	}
	end := 5 + int(binary.BigEndian.Uint16(b[3:5]))
	if end > len(b) {
		return c.Conn.Write(b)
	}
	split, err := mirage.Split(b[:end], c.offset)
	if err != nil {
		return c.Conn.Write(b)
	}
	split = append(split, b[end:]...)
	n, err := c.Conn.Write(split)
	if err != nil {
		// The second record's header is framing the caller did not write.
		if n -= 5; n < 0 {
			n = 0
		}
		if n > len(b) {
			n = len(b)
		}
		return n, err
	}
	return len(b), nil
}
