//go:build with_bond

package bond

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// maxFrame is the largest payload of one frame: its length travels as a uint16.
const maxFrame = 65535

// bondedConn spreads each frame over all legs by ratio. The frame length goes first on leg 0,
// then each leg carries its share of the payload in order.
type bondedConn struct {
	conns          []net.Conn
	downloadRatios []uint8
	uploadRatios   []uint8
	readBuffer     *bytes.Buffer
	readAccess     sync.Mutex
	writeAccess    sync.Mutex
	closeOnce      sync.Once
	onClose        func()
}

func newBondedConn(conns []net.Conn, downloadRatios, uploadRatios []uint8, onClose func()) *bondedConn {
	return &bondedConn{
		conns:          conns,
		downloadRatios: downloadRatios,
		uploadRatios:   uploadRatios,
		readBuffer:     bytes.NewBuffer(make([]byte, 0, 4096)),
		onClose:        onClose,
	}
}

func (c *bondedConn) Read(b []byte) (int, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	for c.readBuffer.Len() == 0 { // a frame of length 0 carries nothing; read the next
		c.readBuffer.Reset()
		var header [2]byte
		if _, err := io.ReadFull(c.conns[0], header[:]); err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint16(header[:]))
		for i, chunkLen := range splitByRatios(size, c.downloadRatios) {
			if chunkLen == 0 {
				continue
			}
			if _, err := io.CopyN(c.readBuffer, c.conns[i], int64(chunkLen)); err != nil {
				return 0, err
			}
		}
	}
	return c.readBuffer.Read(b)
}

func (c *bondedConn) Write(b []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	total := 0
	for len(b) > 0 { // a frame holds at most maxFrame bytes: its length is a uint16
		frame := b[:min(len(b), maxFrame)]
		if err := c.writeFrame(frame); err != nil {
			return total, err
		}
		total += len(frame)
		b = b[len(frame):]
	}
	return total, nil
}

func (c *bondedConn) writeFrame(frame []byte) error {
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(frame)))
	if _, err := c.conns[0].Write(header[:]); err != nil {
		return err
	}
	offset := 0
	for i, chunkLen := range splitByRatios(len(frame), c.uploadRatios) {
		if chunkLen == 0 {
			continue
		}
		if _, err := c.conns[i].Write(frame[offset : offset+chunkLen]); err != nil {
			return err
		}
		offset += chunkLen
	}
	return nil
}

func (c *bondedConn) Close() error {
	var errs []error
	for _, conn := range c.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return errors.Join(errs...)
}

func (c *bondedConn) LocalAddr() net.Addr  { return c.conns[0].LocalAddr() }
func (c *bondedConn) RemoteAddr() net.Addr { return c.conns[0].RemoteAddr() }

func (c *bondedConn) SetDeadline(t time.Time) error {
	return c.each(func(conn net.Conn) error { return conn.SetDeadline(t) })
}

func (c *bondedConn) SetReadDeadline(t time.Time) error {
	return c.each(func(conn net.Conn) error { return conn.SetReadDeadline(t) })
}

func (c *bondedConn) SetWriteDeadline(t time.Time) error {
	return c.each(func(conn net.Conn) error { return conn.SetWriteDeadline(t) })
}

func (c *bondedConn) each(do func(net.Conn) error) error {
	var errs []error
	for _, conn := range c.conns {
		if err := do(conn); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// splitByRatios splits number by percentages; the last part takes the rounding.
func splitByRatios(number int, ratios []uint8) []int {
	result := make([]int, len(ratios))
	remaining := number
	for i := 0; i < len(ratios)-1; i++ {
		part := number * int(ratios[i]) / 100
		result[i] = part
		remaining -= part
	}
	result[len(ratios)-1] = remaining
	return result
}

// checkRatios requires the ratios of all legs to add up to 100, counted without overflow.
func checkRatios(name string, ratios []uint8) error {
	total := 0
	for _, ratio := range ratios {
		total += int(ratio)
	}
	if total != 100 {
		return E.New("bond: ", name, " ratios add up to ", total, ", not 100")
	}
	return nil
}
