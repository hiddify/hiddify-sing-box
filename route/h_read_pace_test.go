package route

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// segmentConn is a socket that data arrives on in TCP segments: a Read returns what has arrived,
// and waits for the next segment when nothing has.
type segmentConn struct {
	net.Conn
	mu      sync.Mutex
	ready   *sync.Cond
	waiting int
	closed  bool
	reads   int
}

func newSegmentConn() *segmentConn {
	c := &segmentConn{}
	c.ready = sync.NewCond(&c.mu)
	return c
}

func (c *segmentConn) arrive(n int) {
	c.mu.Lock()
	c.waiting += n
	c.mu.Unlock()
	c.ready.Signal()
}

func (c *segmentConn) end() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.ready.Signal()
}

func (c *segmentConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.waiting == 0 {
		if c.closed {
			return 0, io.EOF
		}
		c.ready.Wait()
	}
	c.reads++
	n := min(len(b), c.waiting)
	c.waiting -= n
	return n, nil
}

// feed lets segment-sized pieces arrive at bytesPerSecond for d, as evenly as the clock allows.
func feed(c *segmentConn, bytesPerSecond int, d time.Duration) (sent int) {
	const segment = 1400
	start := time.Now()
	for {
		elapsed := time.Since(start)
		if elapsed >= d {
			return
		}
		due := int(float64(bytesPerSecond)*elapsed.Seconds()) - sent
		for ; due >= segment; due -= segment {
			c.arrive(segment)
			sent += segment
		}
		time.Sleep(50 * time.Microsecond)
	}
}

func readAll(t *testing.T, conn *segmentConn, pace *readPace) (total int, calls int) {
	t.Helper()
	buffer := make([]byte, 64<<10)
	for {
		n, err := pace.read(conn, buffer)
		total += n
		if err != nil {
			require.ErrorIs(t, err, io.EOF)
			return total, calls
		}
		calls++
	}
}

// A fast download is read in batches: the reads of a connection that brings 20 MB a second find
// tens of segments waiting, not one, and nothing of it is lost or held back.
func TestH_ReadPaceBatchesAFastDownload(t *testing.T) {
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	const rate = 20 << 20
	conn := newSegmentConn()
	var sent int
	go func() {
		sent = feed(conn, rate, 1500*time.Millisecond)
		conn.end()
	}()
	var pace readPace
	started := time.Now()
	total, calls := readAll(t, conn, &pace)
	took := time.Since(started)
	require.Equal(t, sent, total, "every byte is read")
	require.Less(t, took, 1700*time.Millisecond, "the download is not held back")
	perRead := total / calls
	t.Logf("%d bytes in %d reads: %d bytes a read, %.0f reads a second", total, calls, perRead, float64(calls)/took.Seconds())
	require.Greater(t, perRead, 8*1400, "a paced read takes many segments")
}

// A slow connection is not paced: each read returns as soon as its data arrives.
func TestH_ReadPaceLeavesASlowConnectionAlone(t *testing.T) {
	conn := newSegmentConn()
	var pace readPace
	buffer := make([]byte, 64<<10)
	// a request and its answer, again and again: 1400 bytes every 2 ms is 700 KB a second
	for range 200 {
		go func() {
			time.Sleep(2 * time.Millisecond)
			conn.arrive(1400)
		}()
		asked := time.Now()
		n, err := pace.read(conn, buffer)
		require.NoError(t, err)
		require.Equal(t, 1400, n)
		require.Less(t, time.Since(asked), 12*time.Millisecond)
	}
	require.Zero(t, pace.wait, "a slow connection's reads never wait")
}

// A connection that was fast and then slows down is read at once again.
func TestH_ReadPaceStopsWhenTheDownloadSlows(t *testing.T) {
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	conn := newSegmentConn()
	var pace readPace
	done := make(chan struct{})
	go func() {
		feed(conn, 20<<20, 300*time.Millisecond)
		close(done)
		conn.arrive(1400) // a read that began as the feed ended is not left waiting
	}()
	buffer := make([]byte, 64<<10)
	for {
		select {
		case <-done:
		default:
			_, err := pace.read(conn, buffer)
			require.NoError(t, err)
			continue
		}
		break
	}
	require.NotZero(t, pace.wait, "paced while it was fast")
	// now a trickle
	for range 30 {
		go func() {
			time.Sleep(2 * time.Millisecond)
			conn.arrive(1400)
		}()
		_, err := pace.read(conn, buffer)
		require.NoError(t, err)
	}
	require.Zero(t, pace.wait, "not paced once it is slow")
}

// Where the system holds timers back (a process in the background), a short wait turns into a
// long one: after a few of those, pacing goes off for every connection, and reads return at once.
func TestH_ReadPaceGoesOffWhenWaitsComeLate(t *testing.T) {
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	defer func(sleep func(time.Duration)) { paceSleep = sleep }(paceSleep)
	defer pacingOff.Store(0)
	paceSleep = func(time.Duration) { time.Sleep(paceLate + 5*time.Millisecond) }
	conn := newSegmentConn()
	pace := readPace{wait: time.Millisecond, drained: true}
	buffer := make([]byte, 64<<10)
	for i := 0; i < paceLateMax; i++ {
		require.NotZero(t, pace.wait)
		conn.arrive(1400)
		_, err := pace.read(conn, buffer)
		require.NoError(t, err)
		pace.wait, pace.drained = max(pace.wait, 1), true // as a fast connection would set it again
		if i == paceLateMax-1 {
			break
		}
	}
	require.Greater(t, pacingOff.Load(), time.Now().UnixNano(), "pacing is off for a while")
	// another connection, fast: its read does not wait
	other := readPace{wait: time.Millisecond, drained: true}
	conn.arrive(1400)
	asked := time.Now()
	_, err := other.read(conn, buffer)
	require.NoError(t, err)
	require.Less(t, time.Since(asked), paceLate)
	require.Zero(t, other.wait)
}

// answerConn is a peer on the local network that answers at once: each read returns one answer,
// which is there a moment after the read before it returned, and nothing more arrives while the
// reader waits.
type answerConn struct {
	net.Conn
	answer time.Duration // how long the peer takes
	size   int
	last   time.Time // when the read before returned
}

func (c *answerConn) Read(b []byte) (int, error) {
	if ready := c.last.Add(c.answer); time.Now().Before(ready) {
		time.Sleep(time.Until(ready))
	}
	c.last = time.Now()
	return c.size, nil
}

// An exchange of questions and answers with a peer that answers at once (a database, a file
// server on the local network) is fast enough to be paced, and pacing only makes every answer
// late. The trial sees that it got slower and leaves it alone, for longer each time.
func TestH_ReadPaceLeavesAnExchangeAlone(t *testing.T) {
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	conn := &answerConn{answer: 100 * time.Microsecond, size: 8 << 10, last: time.Now()}
	var pace readPace
	buffer := make([]byte, 64<<10)
	run := func(d time.Duration) (bytes int, waited bool) {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			n, err := pace.read(conn, buffer)
			require.NoError(t, err)
			bytes += n
			waited = waited || pace.wait > 0
		}
		return
	}
	_, waited := run(200 * time.Millisecond)
	require.True(t, waited, "it is fast enough to be paced")
	require.Zero(t, pace.wait, "pacing slowed it, so it is left alone")
	require.Equal(t, paceAloneFor, pace.aloneFor)
	require.True(t, pace.alone.After(time.Now().Add(paceAloneFor-time.Second)))
	// and from then on it is as fast as it was
	bytes, waited := run(200 * time.Millisecond)
	require.False(t, waited, "left alone, its reads do not wait")
	require.Greater(t, bytes, 2<<20, "it runs at its own speed")
	// when it is tried again and slows again, it is left alone twice as long
	pace.alone = time.Now()
	run(200 * time.Millisecond)
	require.Zero(t, pace.wait)
	require.Equal(t, 2*paceAloneFor, pace.aloneFor)
}

// datagramConn is a connected UDP socket: a read returns one datagram.
type datagramConn struct {
	net.Conn
	reads int
}

func (c *datagramConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (c *datagramConn) Read(b []byte) (int, error) {
	c.reads++
	return 1200, nil
}

func (c *datagramConn) Close() error { return nil }

type streamAddrConn struct{ net.Conn }

func (c *streamAddrConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

// A datagram socket is not paced: each of its reads returns one datagram, never "all that
// arrived", so a wait before every read made a QUIC connection crawl.
func TestH_ReadPaceLeavesDatagramsAlone(t *testing.T) {
	require.True(t, isStream(&streamAddrConn{}))
	conn := &datagramConn{}
	require.False(t, isStream(conn))
	manager := &ConnectionManager{}
	tracked := manager.TrackConn(conn).(*trackedConn)
	defer tracked.Close()
	buffer := make([]byte, 2048)
	// 20,000 datagrams of 1200 bytes within a moment is far above the rate that paces a stream
	started := time.Now()
	for range 20000 {
		_, err := tracked.Read(buffer)
		require.NoError(t, err)
	}
	require.Less(t, time.Since(started), 500*time.Millisecond, "the reads of a datagram socket waited")
	require.Zero(t, tracked.pace.wait)
}
