package route

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// pacingKept starts a test that needs pacing with pacing on, and returns what tells afterwards
// whether it stayed on: on a machine whose processors are all busy short waits come late, pacing
// goes off as it should, and such a test has nothing to look at.
func pacingKept(t *testing.T) (kept func()) {
	t.Helper()
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	off, trips := pacingOff.Load(), pacingTrips.Load()
	pacingOff.Store(0)
	t.Cleanup(func() {
		pacingOff.Store(off)
		pacingTrips.Store(trips)
	})
	return func() {
		t.Helper()
		if pacingOff.Load() != 0 {
			t.Skip("this machine did not keep its short waits, so pacing went off")
		}
	}
}

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
	kept := pacingKept(t)
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
	kept()
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
	kept := pacingKept(t)
	conn := newSegmentConn()
	var pace readPace
	done := make(chan struct{})
	go func() {
		feed(conn, 20<<20, 300*time.Millisecond)
		close(done)
		conn.arrive(1400) // a read that began as the feed ended is not left waiting
	}()
	buffer := make([]byte, 64<<10)
	var waited bool
	for {
		select {
		case <-done:
		default:
			_, err := pace.read(conn, buffer)
			require.NoError(t, err)
			waited = waited || pace.wait > 0
			continue
		}
		break
	}
	kept()
	if pace.aloneFor != 0 {
		t.Skip("this machine is too busy to feed the connection evenly")
	}
	require.True(t, waited, "paced while it was fast")
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
	const late = 2*time.Millisecond + paceSlack + 3*time.Millisecond
	paceSleep = func(time.Duration) { time.Sleep(late) }
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
	require.Less(t, time.Since(asked), late)
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
	kept := pacingKept(t)
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
	kept()
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
	kept()
	require.Zero(t, pace.wait)
	require.Equal(t, 2*paceAloneFor, pace.aloneFor)
}

// A connection that pacing slows is found out whenever that happens, not only when it is paced
// anew: a download that turns into an exchange of questions and answers on the same connection
// (the next request on a kept-alive connection) is left alone too.
func TestH_ReadPaceWatchesAPacedConnection(t *testing.T) {
	kept := pacingKept(t)
	conn := newSegmentConn()
	var pace readPace
	done := make(chan struct{})
	go func() {
		feed(conn, 20<<20, 600*time.Millisecond)
		close(done)
		conn.arrive(1400)
	}()
	buffer := make([]byte, 64<<10)
	var waited bool
	for {
		select {
		case <-done:
		default:
			_, err := pace.read(conn, buffer)
			require.NoError(t, err)
			waited = waited || pace.wait > 0
			continue
		}
		break
	}
	kept()
	if pace.aloneFor != 0 {
		t.Skip("this machine is too busy to feed the connection evenly")
	}
	require.True(t, waited, "the download is paced")
	require.Positive(t, pace.tries, "and was tried without the waits, which cost it nothing")
	// now the peer answers at once, 16 KB a question: 16 MB a second if nothing holds it back
	exchange := &answerConn{answer: time.Millisecond, size: 16 << 10, last: time.Now()}
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && pace.aloneFor == 0 {
		_, err := pace.read(exchange, buffer)
		require.NoError(t, err)
	}
	kept()
	require.Equal(t, paceAloneFor, pace.aloneFor, "pacing slowed it, so it is left alone")
	require.Zero(t, pace.wait)
}

// windowConn is a sender behind a window, as a multiplexer's stream is: it sends at rate until
// window bytes wait to be read, and then no more until they are read. While full is set it has
// more than any read asks for, as a reader slower than the sender finds it.
type windowConn struct {
	net.Conn
	rate    float64 // bytes a second
	window  int
	full    bool
	waiting int
	last    time.Time // when waiting was last brought up to date
}

func (c *windowConn) Read(b []byte) (int, error) {
	if c.full {
		c.last = time.Now()
		return len(b), nil
	}
	for {
		now := time.Now()
		c.waiting = min(c.window, c.waiting+int(c.rate*now.Sub(c.last).Seconds()))
		c.last = now
		if c.waiting > 0 {
			break
		}
		time.Sleep(5 * time.Microsecond)
	}
	n := min(len(b), c.waiting)
	c.waiting -= n
	return n, nil
}

// A sender behind a window, whose reads pacing holds back, is found out and read at once. A
// yamux download over loopback ran at 4 Gbit/s instead of 11: at first its reader was the slower
// side and never found the socket empty, so it kept its speed while paced; then it found the
// socket empty once, waited 250 microseconds while the stream's 256 KB window filled and the
// sender stopped, and from then on waited before every read, past the trial that watched only
// the first windows of pacing.
func TestH_ReadPaceFindsASenderBehindAWindow(t *testing.T) {
	kept := pacingKept(t)
	require.Equal(t, paceMinWait, paceWait(1<<30), "a very fast connection waits the shortest wait")
	require.Equal(t, paceMaxWait, paceWait(paceFrom))
	require.Zero(t, paceWait(paceFrom-1))

	const rate = 1 << 30
	buffer := make([]byte, 64<<10)
	// run reads as a reader that is the slower side for a while, and then has caught up and finds
	// what the window lets the sender send
	run := func(pace *readPace) (bytes int) {
		// getting up to speed: paced first at 8 MB a second, the rate a slower start takes the
		// place of the connection's own
		ramp := &windowConn{rate: 8 << 20, window: 256 << 10, last: time.Now()}
		for deadline := time.Now().Add(3 * paceWindow); time.Now().Before(deadline); {
			_, err := pace.read(ramp, buffer)
			require.NoError(t, err)
		}
		conn := &windowConn{rate: rate, window: 256 << 10, full: true, last: time.Now()}
		read := func(d time.Duration) (bytes int) {
			deadline := time.Now().Add(d)
			for time.Now().Before(deadline) {
				n, err := pace.read(conn, buffer)
				require.NoError(t, err)
				bytes += n
				if conn.full {
					time.Sleep(50 * time.Microsecond) // about 1 GB a second
				}
			}
			return bytes
		}
		read(8 * paceWindow)
		conn.full = false
		return read(600 * time.Millisecond)
	}
	never := run(&readPace{alone: time.Now().Add(time.Hour)}) // a connection that is left alone
	var pace readPace
	bytes := run(&pace)
	kept()
	t.Logf("%d MB read, %d MB by a connection that is never paced", bytes>>20, never>>20)
	require.Greater(t, float64(bytes), 0.85*float64(never), "the reads of a sender behind a window waited")
	require.Zero(t, pace.wait, "found out, it is read at once")
	require.NotZero(t, pace.aloneFor)
}

// A connection that sends more than it receives is not paced: what comes in, acknowledgements
// and window updates of an upload over HTTP/2 or a multiplexer, is read at once. Read late, they
// held an XHTTP upload at 6.8 Gbit/s where it ran at 9.1.
func TestH_ReadPaceLeavesAnUploadAlone(t *testing.T) {
	kept := pacingKept(t)
	conn := newSegmentConn()
	var pace readPace
	done := make(chan struct{})
	go func() {
		// window updates of 13 bytes, 8 MB a second of them: fast enough to be paced on their own
		feed(conn, 8<<20, 300*time.Millisecond)
		close(done)
		conn.arrive(1400)
	}()
	buffer := make([]byte, 64<<10)
	var waited bool
	for {
		select {
		case <-done:
		default:
			pace.written.Add(64 << 20 / 1000) // the upload: 64 MB a second
			_, err := pace.read(conn, buffer)
			require.NoError(t, err)
			waited = waited || pace.wait > 0
			continue
		}
		break
	}
	kept()
	require.False(t, waited, "the reads of a connection that sends more than it receives waited")
	// the same reads without the upload are paced
	pace = readPace{}
	done = make(chan struct{})
	go func() {
		feed(conn, 8<<20, 300*time.Millisecond)
		close(done)
		conn.arrive(1400)
	}()
	for {
		select {
		case <-done:
		default:
			_, err := pace.read(conn, buffer)
			require.NoError(t, err)
			waited = waited || pace.wait > 0
			continue
		}
		break
	}
	kept()
	require.True(t, waited, "a download as fast is paced")
}

// datagramConn is a connected UDP socket: a read returns one datagram.
type datagramConn struct {
	net.Conn
	reads int
}

func (c *datagramConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (c *datagramConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}

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
