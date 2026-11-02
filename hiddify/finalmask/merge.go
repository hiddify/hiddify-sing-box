// The merge mask is ported from patterniha/Xray-core transport/internet/finalmask/merge
// (https://github.com/patterniha/xray-core, Mozilla Public License 2.0). Changes: it is built from
// its JSON settings here instead of a protobuf message, and implements the TCPMask interface of
// the Xray-core version this package uses.

package finalmask

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	xfinalmask "github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	defaultMergeDelayMs  = 30
	defaultMergeMaxBytes = 16384
)

// MergeMask coalesces the first writes of a TCP connection: each write is held until no new one
// comes for delayMs, or the held bytes reach maxBytes, and then goes out as one write. After times
// such writes the connection passes writes straight through; times 0 or less means for its whole
// life. Replies are not changed.
type MergeMask struct {
	Times    int32 `json:"times"`
	DelayMs  int32 `json:"delayMs"`
	MaxBytes int32 `json:"maxBytes"`
}

func (c *MergeMask) BuildTcpmask() (xfinalmask.TCPMask, error) {
	if c.DelayMs < 0 || c.MaxBytes < 0 {
		return nil, errors.New("delayMs and maxBytes can't be negative")
	}
	mask := *c
	if mask.DelayMs == 0 {
		mask.DelayMs = defaultMergeDelayMs
	}
	if mask.MaxBytes == 0 {
		mask.MaxBytes = defaultMergeMaxBytes
	}
	return &mask, nil
}

func (c *MergeMask) WrapConnClient(conn net.Conn, _ *xnet.Destination, _ *xfinalmask.Dialer) (net.Conn, error) {
	return newMergeConn(conn, int(c.Times), int(c.MaxBytes), time.Duration(c.DelayMs)*time.Millisecond), nil
}

// WrapConnServer leaves the connection as it is: merge only shapes what a client sends.
func (c *MergeMask) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

type mergeConn struct {
	net.Conn

	delay     time.Duration
	maxBytes  int
	unlimited bool

	mu        sync.Mutex
	buf       []byte
	remaining int
	epoch     uint64
	timer     *time.Timer
	closed    bool
	err       error
}

func newMergeConn(conn net.Conn, times, maxBytes int, delay time.Duration) net.Conn {
	c := &mergeConn{Conn: conn, delay: delay, maxBytes: maxBytes}
	if times <= 0 {
		c.unlimited = true
	} else {
		c.remaining = times
	}
	return c
}

func (c *mergeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	if !c.unlimited && c.remaining == 0 {
		n, err := c.Conn.Write(p)
		if err != nil {
			c.err = err
		}
		return n, err
	}
	c.buf = append(c.buf, p...) // a copy: the caller may reuse p once Write returns
	if len(c.buf) >= c.maxBytes {
		if err := c.flushLocked(); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	c.armTimerLocked()
	return len(p), nil
}

// armTimerLocked restarts the idle timer. A new epoch turns a timer that already fired but still
// waits for the lock into a no-op.
func (c *mergeConn) armTimerLocked() {
	c.epoch++
	epoch := c.epoch
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(c.delay, func() { c.onTimer(epoch) })
}

func (c *mergeConn) onTimer(epoch uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.err != nil || epoch != c.epoch {
		return
	}
	_ = c.flushLocked()
}

// flushLocked sends the held bytes as one write and counts it; c.mu is held.
func (c *mergeConn) flushLocked() error {
	if len(c.buf) == 0 {
		return nil
	}
	c.epoch++
	if c.timer != nil {
		c.timer.Stop()
	}
	data := c.buf
	c.buf = nil
	if _, err := c.Conn.Write(data); err != nil {
		c.err = err
		return err
	}
	if !c.unlimited {
		c.remaining--
	}
	return nil
}

func (c *mergeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.epoch++
	if c.timer != nil {
		c.timer.Stop()
	}
	if len(c.buf) > 0 && c.err == nil {
		data := c.buf
		c.buf = nil
		if _, err := c.Conn.Write(data); err != nil {
			c.err = err
		}
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// SyscallConn keeps the read side's fast path; writes always go through Write.
func (c *mergeConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("merge: the connection is not a syscall.Conn")
}
