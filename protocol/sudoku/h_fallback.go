package sudoku

import (
	"bytes"
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// maxFallbackRecord bounds what a connection may send before its handshake fails and it is
// passed to the fallback; past it, the connection is closed instead.
const maxFallbackRecord = 64 << 10

// recordingConn keeps what the handshake reads, so a connection that is not Sudoku can be
// replayed to the fallback.
type recordingConn struct {
	net.Conn
	access    sync.Mutex
	recorded  bytes.Buffer
	overflow  bool
	recording bool
}

func newRecordingConn(conn net.Conn) *recordingConn {
	return &recordingConn{Conn: conn, recording: true}
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.access.Lock()
	if c.recording && n > 0 {
		if c.recorded.Len()+n > maxFallbackRecord {
			c.overflow = true
			c.recording = false
			c.recorded = bytes.Buffer{}
		} else {
			c.recorded.Write(p[:n])
		}
	}
	c.access.Unlock()
	return n, err
}

// stop ends the recording once the handshake worked.
func (c *recordingConn) stop() {
	c.access.Lock()
	c.recording = false
	c.recorded = bytes.Buffer{}
	c.access.Unlock()
}

// serveFallback sends what was read to the fallback address and relays the rest both ways.
func (h *Inbound) serveFallback(ctx context.Context, conn *recordingConn) {
	conn.access.Lock()
	recorded, overflow := bytes.Clone(conn.recorded.Bytes()), conn.overflow
	conn.recording = false
	conn.access.Unlock()
	if overflow {
		conn.Close()
		return
	}
	upstream, err := h.fallbackDialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(h.fallback))
	if err != nil {
		h.logger.DebugContext(ctx, "sudoku fallback: ", err)
		conn.Close()
		return
	}
	if len(recorded) > 0 {
		if _, err = upstream.Write(recorded); err != nil {
			upstream.Close()
			conn.Close()
			return
		}
	}
	_ = bufio.CopyConn(ctx, conn.Conn, upstream)
}
