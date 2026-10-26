package dialer

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// H: dialer-level TLS ClientHello fragmentation with size/sleep ranges.
// Distinct from route-action / tls.fragment (SNI-split via common/tlsfragment).

type tlsFragment struct {
	Enabled bool
	Sleep   option.IntRange
	Size    option.IntRange
}

func buildTLSFragment(options option.TLSFragmentOptions, tcpFastOpen bool) (*tlsFragment, error) {
	if !options.Enabled {
		return nil, nil
	}
	if tcpFastOpen {
		return nil, E.New("TLS Fragmentation is not compatible with TCP Fast Open, set `tcp_fast_open` to `false` in your outbound if you intend to enable TLS fragmentation.")
	}
	sizeStr := options.Size
	if sizeStr == "" {
		sizeStr = "1-10"
	}
	sleepStr := options.Sleep
	if sleepStr == "" {
		sleepStr = "0"
	}
	sleep, err := option.Parse2IntRange(sleepStr)
	if err != nil {
		return nil, E.Cause(err, "missing or invalid value supplied as TLS fragment `sleep` option")
	}
	if sleep.Max > 1000 {
		return nil, E.New("invalid range supplied as TLS fragment `sleep` option! set to '0' to disable sleeps or set to range [0,1000]")
	}
	size, err := option.Parse2IntRange(sizeStr)
	if err != nil {
		return nil, E.Cause(err, "missing or invalid value supplied as TLS fragment `size` option")
	}
	if size.Min <= 0 || size.Max > 256 {
		return nil, E.New("invalid range supplied as TLS fragment `size` option! valid range: [1,256]")
	}
	return &tlsFragment{Enabled: true, Sleep: sleep, Size: size}, nil
}

func newTLSFragmentDialer(dialer N.Dialer, fragment *tlsFragment) N.Dialer {
	if fragment == nil || !fragment.Enabled {
		return dialer
	}
	fragDialer := tlsFragmentDialer{dialer: dialer, fragment: *fragment}
	if parallelDialer, isParallel := dialer.(ParallelInterfaceDialer); isParallel {
		return &tlsFragmentParallelDialer{tlsFragmentDialer: fragDialer, parallel: parallelDialer}
	}
	return &fragDialer
}

type tlsFragmentDialer struct {
	dialer   N.Dialer
	fragment tlsFragment
}

func (d *tlsFragmentDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	if N.NetworkName(network) != N.NetworkTCP {
		return conn, nil
	}
	return &fragmentConn{conn: conn, fragment: d.fragment}, nil
}

func (d *tlsFragmentDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.dialer.ListenPacket(ctx, destination)
}

type tlsFragmentParallelDialer struct {
	tlsFragmentDialer
	parallel ParallelInterfaceDialer
}

func (d *tlsFragmentParallelDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	conn, err := d.parallel.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	if N.NetworkName(network) != N.NetworkTCP {
		return conn, nil
	}
	return &fragmentConn{conn: conn, fragment: d.fragment}, nil
}

func (d *tlsFragmentParallelDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error) {
	return d.parallel.ListenSerialInterfacePacket(ctx, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
}

type fragmentConn struct {
	conn     net.Conn
	err      error
	fragment tlsFragment
}

func isClientHelloPacket(b []byte) bool {
	if len(b) < 6 || b[0] != 22 {
		return false
	}
	version := uint16(b[1])<<8 | uint16(b[2])
	if version < 0x0301 {
		return false
	}
	return b[5] == 1
}

func (c *fragmentConn) writeFragments(b []byte) (n int, err error) {
	recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
	if len(b) < recordLen {
		return c.conn.Write(b)
	}

	var bytesWritten int
	data := b[5:recordLen]
	buf := make([]byte, 1024)
	queue := make([]byte, 2048)
	nQueue := int(option.GetRandomIntFromRange(1, 4))
	lQueue := 0
	cQueue := 0
	for from := 0; ; {
		to := from + int(option.GetRandomIntFromRange(c.fragment.Size.Min, c.fragment.Size.Max))
		if to > len(data) {
			to = len(data)
		}
		copy(buf[:3], b)
		copy(buf[5:], data[from:to])
		l := to - from
		from = to
		buf[3] = byte(l >> 8)
		buf[4] = byte(l)

		if cQueue < nQueue {
			if l > 0 {
				copy(queue[lQueue:], buf[:5+l])
				lQueue = lQueue + 5 + l
			}
			cQueue = cQueue + 1
		} else {
			if l > 0 {
				copy(queue[lQueue:], buf[:5+l])
				lQueue = lQueue + 5 + l
			}

			if lQueue > 0 {
				n, err := c.conn.Write(queue[:lQueue])
				if err != nil {
					return 0, err
				}
				bytesWritten += n
				if c.fragment.Sleep.Max != 0 {
					time.Sleep(time.Duration(option.GetRandomIntFromRange(c.fragment.Sleep.Min, c.fragment.Sleep.Max)) * time.Millisecond)
				}
			}

			lQueue = 0
			cQueue = 0
		}

		if from == len(data) {
			if lQueue > 0 {
				n, err := c.conn.Write(queue[:lQueue])
				if err != nil {
					return 0, err
				}
				bytesWritten += n
				if c.fragment.Sleep.Max != 0 {
					time.Sleep(time.Duration(option.GetRandomIntFromRange(c.fragment.Sleep.Min, c.fragment.Sleep.Max)) * time.Millisecond)
				}
			}
			if len(b) > recordLen {
				n, err := c.conn.Write(b[recordLen:])
				if err != nil {
					return recordLen + n, err
				}
				bytesWritten += n
			}
			return bytesWritten, nil
		}
	}
}

func (c *fragmentConn) Write(b []byte) (n int, err error) {
	if c.conn == nil {
		return 0, c.err
	}
	if isClientHelloPacket(b) {
		return c.writeFragments(b)
	}
	return c.conn.Write(b)
}

func (c *fragmentConn) Read(b []byte) (n int, err error) {
	if c.conn == nil {
		return 0, c.err
	}
	return c.conn.Read(b)
}

func (c *fragmentConn) Close() error {
	return common.Close(c.conn)
}

func (c *fragmentConn) LocalAddr() net.Addr {
	if c.conn == nil {
		return M.Socksaddr{}
	}
	return c.conn.LocalAddr()
}

func (c *fragmentConn) RemoteAddr() net.Addr {
	if c.conn == nil {
		return M.Socksaddr{}
	}
	return c.conn.RemoteAddr()
}

func (c *fragmentConn) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	return c.conn.SetDeadline(t)
}

func (c *fragmentConn) SetReadDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	return c.conn.SetReadDeadline(t)
}

func (c *fragmentConn) SetWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *fragmentConn) Upstream() any {
	return c.conn
}

func (c *fragmentConn) ReaderReplaceable() bool {
	return c.conn != nil
}

func (c *fragmentConn) WriterReplaceable() bool {
	return c.conn != nil
}

func (c *fragmentConn) LazyHeadroom() bool {
	return c.conn == nil
}

func (c *fragmentConn) NeedHandshake() bool {
	return c.conn == nil
}

func (c *fragmentConn) WriteTo(w io.Writer) (n int64, err error) {
	if c.conn == nil {
		return 0, c.err
	}
	return bufio.Copy(w, c.conn)
}
