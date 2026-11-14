package route

import (
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// feedWaits lets reads wait gap for the next arrival, one after another, for d of a made-up clock.
func feedWaits(pace *wakePace, at time.Time, gap time.Duration, busy time.Duration, d time.Duration) time.Time {
	end := at.Add(d)
	for at.Before(end) {
		woken := at.Add(gap)
		pace.observe(at, woken)
		at = woken.Add(busy) // reading what arrived
	}
	return at
}

// A socket whose reads wait a moment only for the next arrival is busy, and its wake-ups are
// paced; one whose reads wait long is not, and a paced one that calms down is not either.
func TestH_WakePaceFollowsHowLongReadsWait(t *testing.T) {
	var pace wakePace
	at := time.Unix(1000, 0)
	// 15000 datagrams a second, each read as it arrives: the reads wait 60 microseconds
	at = feedWaits(&pace, at, 60*time.Microsecond, 6*time.Microsecond, 60*time.Millisecond)
	require.GreaterOrEqual(t, pace.wait, wakeMinWait, "a busy socket's wake-ups are paced")
	require.LessOrEqual(t, pace.wait, wakeMaxWait)
	// paced, the reads wait about half as long for the next arrival: still busy
	at = feedWaits(&pace, at, 30*time.Microsecond, time.Millisecond, 60*time.Millisecond)
	require.NotZero(t, pace.wait, "it stays paced while it is busy")
	// a datagram every 2 ms: a call, a game
	at = feedWaits(&pace, at, 2*time.Millisecond, 10*time.Microsecond, 60*time.Millisecond)
	require.Zero(t, pace.wait, "a calm socket is read at once")
	// bursts: a few datagrams close together, then nothing for 5 ms
	for range 20 {
		at = feedWaits(&pace, at, 20*time.Microsecond, 5*time.Microsecond, 100*time.Microsecond)
		at = feedWaits(&pace, at, 5*time.Millisecond, 5*time.Microsecond, 5*time.Millisecond)
	}
	require.Zero(t, pace.wait, "bursts with pauses between them are not a busy socket")
	// after a long silence, a busy moment shorter than a window does not pace
	at = at.Add(10 * time.Second)
	feedWaits(&pace, at, 60*time.Microsecond, 6*time.Microsecond, 5*time.Millisecond)
	require.Zero(t, pace.wait)
}

// fakeRawConn is a socket's raw connection for a test: each arrival makes one read attempt
// succeed, and a read that finds nothing waits for the next arrival.
type fakeRawConn struct {
	arrivals chan struct{}
}

func (c *fakeRawConn) Control(f func(fd uintptr)) error { f(0); return nil }

func (c *fakeRawConn) Write(f func(fd uintptr) (done bool)) error { f(0); return nil }

func (c *fakeRawConn) Read(f func(fd uintptr) (done bool)) error {
	for !f(0) {
		if _, open := <-c.arrivals; !open {
			return net.ErrClosed
		}
	}
	return nil
}

// A reader of a busy socket's raw connection is held back a moment when it is woken, so that it
// finds a batch; the reads themselves are the reader's own, untouched.
func TestH_PacedRawConnWaitsAfterAWakeUp(t *testing.T) {
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	defer func(sleep func(time.Duration)) { paceSleep = sleep }(paceSleep)
	var pauses atomic.Int32
	paceSleep = func(time.Duration) { pauses.Add(1) }

	raw := &fakeRawConn{arrivals: make(chan struct{}, 1)}
	var pace wakePace
	paced := paceRawConn(raw, &pace)
	_, isPaced := paced.(*pacedRawConn)
	require.True(t, isPaced)

	var waiting atomic.Int32 // datagrams in the socket
	read := func() int {     // takes all that wait, as a batch reader does
		var got int
		require.NoError(t, paced.Read(func(fd uintptr) bool {
			got = int(waiting.Swap(0))
			return got > 0
		}))
		return got
	}
	arrive := func() {
		waiting.Add(1)
		select {
		case raw.arrivals <- struct{}{}:
		default:
		}
	}
	// busy: an arrival 50 microseconds after each read went to wait
	var total int
	deadline := time.Now().Add(120 * time.Millisecond)
	for time.Now().Before(deadline) {
		go func() {
			time.Sleep(50 * time.Microsecond)
			arrive()
		}()
		total += read()
	}
	require.Positive(t, total)
	require.NotZero(t, pace.wait, "the socket is busy")
	require.Positive(t, pauses.Load(), "its reader was held back after wake-ups")

	// calm: an arrival every 3 ms
	for range 30 {
		go func() {
			time.Sleep(3 * time.Millisecond)
			arrive()
		}()
		read()
	}
	require.Zero(t, pace.wait, "a calm socket is not paced")
	before := pauses.Load()
	go func() {
		time.Sleep(3 * time.Millisecond)
		arrive()
	}()
	read()
	require.Equal(t, before, pauses.Load(), "and its reader is not held back")
}

// Where the system does not keep short waits, pacing goes off for every socket, and for longer
// each time it happens again.
func TestH_WakePaceGoesOffWhenWaitsComeLate(t *testing.T) {
	defer func(sleep func(time.Duration)) { paceSleep = sleep }(paceSleep)
	defer pacingOff.Store(0)
	defer pacingTrips.Store(pacingTrips.Load())
	paceSleep = func(time.Duration) { time.Sleep(wakeLate + 2*time.Millisecond) }
	pacingTrips.Store(0)
	pace := wakePace{wait: wakeMinWait}
	for range paceLateMax {
		pace.pause(time.Now())
	}
	require.Zero(t, pace.wait)
	first := time.Duration(pacingOff.Load() - time.Now().UnixNano())
	require.Greater(t, first, paceOffFor-time.Second)
	require.LessOrEqual(t, first, paceOffFor)
	// another socket does not wait while pacing is off
	other := wakePace{wait: wakeMinWait}
	started := time.Now()
	other.pause(started)
	require.Less(t, time.Since(started), wakeLate)
	require.Zero(t, other.wait)
	// the next time it is off for twice as long, and never longer than paceOffMax
	pacingTripped(time.Now())
	require.Greater(t, time.Duration(pacingOff.Load()-time.Now().UnixNano()), 2*paceOffFor-time.Second)
	for range 20 {
		pacingTripped(time.Now())
	}
	require.LessOrEqual(t, time.Duration(pacingOff.Load()-time.Now().UnixNano()), paceOffMax)
}

// A tracked datagram socket is read through the tracker (its reader is not replaceable), so that
// QUIC and the batch readers get the paced raw connection; a stream's reader stays replaceable.
func TestH_TrackedDatagramSocketKeepsItsReader(t *testing.T) {
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	manager := &ConnectionManager{}
	udpServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer udpServer.Close()
	udpConn, err := net.DialUDP("udp", nil, udpServer.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	tracked := manager.TrackConn(udpConn).(*trackedConn)
	defer tracked.Close()
	require.False(t, tracked.stream)
	require.False(t, tracked.ReaderReplaceable())
	require.True(t, tracked.WriterReplaceable())
	rawConn, err := tracked.SyscallConn()
	require.NoError(t, err)
	_, isPaced := rawConn.(*pacedRawConn)
	require.True(t, isPaced, "the raw connection of a tracked socket is paced")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	tcpConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	trackedStream := manager.TrackConn(tcpConn).(*trackedConn)
	defer trackedStream.Close()
	require.True(t, trackedStream.stream)
	require.True(t, trackedStream.ReaderReplaceable())
	rawConn, err = trackedStream.SyscallConn()
	require.NoError(t, err)
	_, isPaced = rawConn.(*pacedRawConn)
	require.False(t, isPaced, "a stream's raw connection is its own: only its reads are paced")

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	trackedPacket := manager.TrackPacketConn(packetConn).(*trackedPacketConn)
	defer trackedPacket.Close()
	require.False(t, trackedPacket.ReaderReplaceable())
	rawConn, err = trackedPacket.SyscallConn()
	require.NoError(t, err)
	_, isPaced = rawConn.(*pacedRawConn)
	require.True(t, isPaced)
}

var _ syscall.RawConn = (*fakeRawConn)(nil)
