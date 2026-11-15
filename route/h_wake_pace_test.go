package route

import (
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// far is a path with a round trip of 50 ms, which allows the longest wait.
func far(pace *wakePace) *wakePace {
	pace.path.answered.Store(true)
	pace.path.roundTrip.Store(int64(50 * time.Millisecond))
	return pace
}

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
	far(&pace)
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
	far(&pace)
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
	const late = 2*wakeMinWait + paceSlack + 2*time.Millisecond
	paceSleep = func(time.Duration) { time.Sleep(late) }
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
	require.Less(t, time.Since(started), late)
	require.Zero(t, other.wait)
	// the next time it is off for twice as long, and never longer than paceOffMax
	pacingTripped(time.Now())
	require.Greater(t, time.Duration(pacingOff.Load()-time.Now().UnixNano()), 2*paceOffFor-time.Second)
	for range 20 {
		pacingTripped(time.Now())
	}
	require.LessOrEqual(t, time.Duration(pacingOff.Load()-time.Now().UnixNano()), paceOffMax)
	// pacing that was then kept for long starts over
	pacingOff.Store(time.Now().Add(-paceOffMax - time.Minute).UnixNano())
	pacingTripped(time.Now())
	again := time.Duration(pacingOff.Load() - time.Now().UnixNano())
	require.Greater(t, again, paceOffFor-time.Second)
	require.LessOrEqual(t, again, paceOffFor)
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

// A wait is a small part of the path's round trip, or there is none: a socket whose peer is this
// machine or nearby, or whose round trip is not known, is never held back. Over loopback, waits of
// 0.2 to 1 ms after the wake-ups made a Hysteria2 download run at a third of its speed, QUIC and
// OpenVPN uploads 20 to 30% slower, and a round trip take 0.3 ms where it had taken 0.18.
func TestH_WakePaceNeedsALongPath(t *testing.T) {
	const busy = 40 * time.Microsecond // how long the reads wait for the next arrival
	for _, test := range []struct {
		name      string
		roundTrip time.Duration
		local     bool
		wait      time.Duration
	}{
		{"not known", 0, false, 0},
		{"this machine", 80 * time.Millisecond, true, 0},
		{"the local network", 300 * time.Microsecond, false, 0},
		{"a server nearby", 4 * time.Millisecond, false, 0},
		{"12.8 ms away", 12800 * time.Microsecond, false, 400 * time.Microsecond},
		{"far away", 80 * time.Millisecond, false, 24 * busy},
	} {
		var path pathRTT
		path.roundTrip.Store(int64(test.roundTrip))
		path.local.Store(test.local)
		require.Equal(t, test.wait, wakeWait(busy, path.longestWait()), test.name)
	}
	// through a socket's pace: busy, and not paced until the path's round trip is known
	var pace wakePace
	at := feedWaits(&pace, time.Unix(1000, 0), 60*time.Microsecond, 6*time.Microsecond, 60*time.Millisecond)
	require.Zero(t, pace.wait, "a socket whose round trip is not known is not paced")
	far(&pace)
	feedWaits(&pace, at, 60*time.Microsecond, 6*time.Microsecond, 60*time.Millisecond)
	require.NotZero(t, pace.wait, "a busy socket on a long path is paced")
}

// A socket so busy that the shortest wait would gather more than a socket buffer of the default
// size holds is not paced: its reads find a batch anyway.
func TestH_WakePaceLeavesAVeryBusySocketAlone(t *testing.T) {
	const longest = wakeMaxWait
	require.Zero(t, wakeWait(2*time.Microsecond, longest), "an arrival every 2 microseconds")
	require.Equal(t, wakeMinWait, wakeWait(5*time.Microsecond, longest), "the shortest wait gathers 40")
	require.Equal(t, 480*time.Microsecond, wakeWait(20*time.Microsecond, longest))
	require.Equal(t, wakeMaxWait, wakeWait(200*time.Microsecond, longest))
	require.Zero(t, wakeWait(2*time.Millisecond, longest), "a calm socket")
}

// The round trip of a socket's path is the time from the first datagram written to the first
// one that arrives, and nothing else: not a later answer, not an answer that was there before
// the reader looked, not one the reader came too late for.
func TestH_PathRoundTripIsTheFirstAnswer(t *testing.T) {
	at := time.Now()
	newPath := func() *pathRTT {
		path := &pathRTT{}
		path.init(nil)
		path.created = at.UnixNano()
		return path
	}
	path := newPath()
	require.Zero(t, path.longestWait())
	path.written.Store(at.Add(time.Millisecond).UnixNano())
	path.wrote() // a second datagram does not move the first
	require.Equal(t, at.Add(time.Millisecond).UnixNano(), path.written.Load())
	path.arrived(at.Add(2*time.Millisecond), at.Add(65*time.Millisecond))
	require.Equal(t, int64(64*time.Millisecond), path.roundTrip.Load())
	require.Equal(t, 2*time.Millisecond, path.longestWait())
	path.arrived(at.Add(time.Second), at.Add(5*time.Second))
	require.Equal(t, int64(64*time.Millisecond), path.roundTrip.Load(), "only the first answer is timed")

	// nothing was seen written: the socket's age is the longest the answer can have taken
	path = newPath()
	path.arrived(at.Add(time.Millisecond), at.Add(40*time.Millisecond))
	require.Equal(t, int64(40*time.Millisecond), path.roundTrip.Load())

	// the answer was there before the reader looked: nothing tells when it arrived
	path = newPath()
	path.wrote()
	path.read()
	path.arrived(at.Add(time.Second), at.Add(2*time.Second))
	require.Zero(t, path.roundTrip.Load())

	// the reader began to wait long after the first datagram was written: what it is woken for
	// is not the first answer
	path = newPath()
	path.written.Store(at.UnixNano())
	path.arrived(at.Add(pathLate+time.Millisecond), at.Add(time.Second))
	require.Zero(t, path.roundTrip.Load())

	// a peer on this machine
	path = newPath()
	path.wroteTo(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	path.arrived(at, at.Add(80*time.Millisecond))
	require.NotZero(t, path.roundTrip.Load())
	require.Zero(t, path.longestWait(), "nothing is held back on the way to this machine")
	path = newPath()
	path.wroteTo(&net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 443})
	require.False(t, path.local.Load())
}

// A tracked socket measures its path with its first exchange, whichever way it is written and
// read: a connected socket's Write and Read, a packet socket's WriteTo and its raw connection.
func TestH_TrackedSocketsMeasureTheirPath(t *testing.T) {
	if pacingDisabled {
		t.Skip("pacing is off")
	}
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer server.Close()
	const answersAfter = 30 * time.Millisecond
	go func() { // a peer that takes a moment to answer
		buffer := make([]byte, 2048)
		for {
			n, from, err := server.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			time.Sleep(answersAfter)
			server.WriteToUDP(buffer[:n], from)
		}
	}()
	manager := &ConnectionManager{}
	check := func(path *pathRTT) {
		t.Helper()
		roundTrip := time.Duration(path.roundTrip.Load())
		require.GreaterOrEqual(t, roundTrip, answersAfter)
		require.Less(t, roundTrip, answersAfter+200*time.Millisecond)
		require.True(t, path.local.Load(), "the peer is this machine")
		require.Zero(t, path.longestWait())
	}

	// a connected socket, as OpenVPN and Hysteria use
	dialed, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	tracked := manager.TrackConn(dialed).(*trackedConn)
	defer tracked.Close()
	time.Sleep(10 * time.Millisecond) // the socket is older than its first datagram
	buffer := make([]byte, 2048)
	_, err = tracked.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, tracked.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := tracked.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buffer[:n]))
	check(&tracked.wake.path)

	// a packet socket read through its raw connection, as QUIC reads it
	listened, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	trackedPacket := manager.TrackPacketConn(listened).(*trackedPacketConn)
	defer trackedPacket.Close()
	time.Sleep(10 * time.Millisecond)
	_, err = trackedPacket.WriteTo([]byte("hello"), server.LocalAddr())
	require.NoError(t, err)
	rawConn, err := trackedPacket.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, listened.SetReadDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, rawConn.Read(func(fd uintptr) bool {
		var readErr error
		n, _, readErr = syscall.Recvfrom(int(fd), buffer, 0)
		return readErr != syscall.EAGAIN
	}))
	require.Equal(t, "hello", string(buffer[:n]))
	check(&trackedPacket.wake.path)
}

var _ syscall.RawConn = (*fakeRawConn)(nil)
