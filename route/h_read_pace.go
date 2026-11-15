package route

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The reads of a fast download are paced.
//
// A TCP socket becomes readable with every segment that arrives, about 1400 bytes, and the
// goroutine reading it is woken for each batch the kernel has by then: a wake of its thread, a
// poll of the kernel, a read, a read that finds nothing, and back to sleep. With several
// connections each bringing a few megabytes a second, most reads find a segment or two, and the
// proxy spends more on those wakes than on the data.
//
// So once a connection brings more than paceFrom bytes a second, a read that would find the
// socket empty waits a moment first and then takes everything that arrived meanwhile in one
// call. The wait is the time paceBatch bytes take to arrive, between paceMinWait and
// paceMaxWait, and the socket's own buffer holds what arrives during it. A connection that slows
// down is read at once again.
//
// Pacing helps a download, whose data keeps coming whether it is read or not. It hurts a sender
// that waits for its data to be read: a peer that answers questions at once (a database, a file
// server on the local network), and a stream behind a multiplexer's window, which stops when
// the window is full (a yamux download over loopback, 11 Gbit/s, ran at 4 with a wait of 250
// microseconds before every read of the emptied socket). So a paced connection is tried without
// the waits now and then: after paceProbeFirst windows of pacing, after paceProbeEvery windows
// the next time and twice as long each time after that, up to paceProbeMax, and at once when it
// brings less than paceKeep of what it brought when it was last read at once, paceSlow windows
// in a row. A try reads it at once for paceProbe windows. If it is then paceGain times as fast
// as it was while paced, the waits held it back, and it is left alone, for paceAloneFor at first
// and twice as long each time it happens again. If it is not, the waits cost it nothing, and it
// is paced on from that rate. The tries do not count on the rate the connection had when pacing
// began: a stream that was paced while it was still getting up to speed never seemed slower
// than that, and the yamux download stayed at 4 Gbit/s.
//
// A connection that sends more than it receives is not paced at all: what comes in answers what
// it sends, acknowledgements and window updates, and an upload over HTTP/2 or a multiplexer
// waits for them. Read late, they held an XHTTP upload at 6.8 Gbit/s where it ran at 9.1.
//
// Measured on macOS, six downloads at once at 500 to 700 Mbit/s together: 10 to 15% less CPU for
// VMess and Snell, 25% for VLESS over HTTP, 35% for XHTTP over HTTP/2. One download over XHTTP
// with HTTP/2 over loopback: 20% less CPU, at the same speed. A single connection read by a
// plain TCP proxy was already read in large pieces and gains nothing.
const (
	paceFrom    = 4 << 20                // bytes a second from which a connection's reads are paced
	paceBatch   = 48 << 10               // bytes a paced read aims to find waiting
	paceMinWait = 250 * time.Microsecond // the shortest wait worth a timer
	paceMaxWait = 2 * time.Millisecond   // the longest: what a paced connection may be late by
	paceWindow  = 25 * time.Millisecond  // the rate is measured over this long
	paceLook    = 64 << 10               // a connection that is not paced reads the clock once in this many bytes
	paceSlack   = 500 * time.Microsecond // a wait that took twice as long and this much more was not kept by the system
	paceOffFor  = 30 * time.Second       // how long pacing stays off after waits that came late, the first time
	paceOffMax  = 16 * time.Minute       // and at most: it doubles each time
	paceLateMax = 3                      // late waits in a row before it goes off

	paceTrial      = 4               // windows a paced connection has to keep its speed for, to be trusted again
	paceKeep       = 0.85            // of its rate read at once: what it has to keep while it is paced
	paceSlow       = 2               // windows in a row below that before it is tried without the waits
	paceProbe      = 3               // windows of a try without the waits
	paceProbeFirst = 8               // windows of pacing before the first try
	paceProbeEvery = 80              // before the second, and twice as many before each one after it
	paceProbeMax   = 1200            // and at most
	paceGain       = 1.15            // how much faster it has to be without the waits, for them to be what held it back
	paceAloneFor   = 5 * time.Second // how long a connection that pacing slowed is left alone, the first time
	paceAloneMax   = 2 * time.Minute // and at most: it doubles each time
)

// paceCameLate reports a wait of wait that took took: the system did not keep it. A machine whose
// processors are all busy wakes a sleeper late, and then every wait costs more than it saves.
func paceCameLate(wait time.Duration, took time.Duration) bool {
	return took > 2*wait+paceSlack
}

// pacingOff is when pacing may be used again (unix nanoseconds), after the system let its waits
// run late: timers held back for a process in the background would turn each short wait into a
// long one, and the download would crawl. Reading at once is always correct.
var pacingOff atomic.Int64

// pacingTrips counts how often pacing went off: on a system that never keeps short waits (a
// coarse clock, a process the system holds back, a machine whose processors are all busy) it is
// tried less and less often. It starts over when pacing was kept for paceOffMax after it came
// back on.
var pacingTrips atomic.Int32

// pacingTripped turns pacing off for a while, from at.
func pacingTripped(at time.Time) {
	if last := pacingOff.Load(); last != 0 && time.Duration(at.UnixNano()-last) > paceOffMax {
		pacingTrips.Store(0)
	}
	off := paceOffFor << min(pacingTrips.Add(1)-1, 8)
	pacingOff.Store(at.Add(min(off, paceOffMax)).UnixNano())
}

// pacingDisabled turns pacing off for good: HIDDIFY_NO_READ_PACE=1, to compare with and without.
var pacingDisabled = os.Getenv("HIDDIFY_NO_READ_PACE") == "1"

// paceSleep is the wait; a test makes it late.
var paceSleep = time.Sleep

// readPace is the pacing of one connection's reads. Only the goroutine that reads uses it.
type readPace struct {
	start   time.Time     // of the window the rate is measured over
	bytes   int           // read in it
	unseen  int           // read since the clock was last read, while it is not paced
	wait    time.Duration // before a read of the empty socket; 0 while the connection is not paced
	drained bool          // the last read took everything the socket had
	late    int           // waits in a row that came late

	written  atomic.Int64  // bytes sent since the window began, by the goroutine that writes
	free     float64       // bytes a second when it was last read at once
	kept     int           // windows in a row in which it kept its speed while paced
	slow     int           // windows in a row in which it did not
	measured int           // bytes in the slow windows, or in the windows of a try
	measure  time.Duration // and how long they took
	since    int           // bytes in the windows paced since the last try
	sinceFor time.Duration // and how long they took
	windows  int           // windows paced since the last try
	tries    int           // tries since pacing began
	paced    float64       // bytes a second while paced, before the try
	probe    int           // windows left of a try without the waits
	aloneFor time.Duration // how long it was last left alone after pacing slowed it
	alone    time.Time     // until when it is left alone
}

func (p *readPace) read(conn net.Conn, b []byte) (int, error) {
	if p.wait > 0 && p.drained {
		p.pause()
	}
	n, err := conn.Read(b)
	p.drained = n < len(b)
	if n > 0 && !pacingDisabled {
		p.count(n)
	}
	return n, err
}

// pause waits for more data to arrive, unless waits have been coming late.
func (p *readPace) pause() {
	before := time.Now()
	if before.UnixNano() < pacingOff.Load() {
		p.wait = 0
		return
	}
	paceSleep(p.wait)
	if !paceCameLate(p.wait, time.Since(before)) {
		p.late = 0
		return
	}
	p.late++
	if p.late >= paceLateMax {
		p.late = 0
		p.wait = 0
		pacingTripped(before)
	}
}

// count adds n bytes just read, and at the end of each window sets the wait from the rate.
func (p *readPace) count(n int) {
	p.bytes += n
	if p.wait == 0 {
		// a connection that is not paced can be very fast: its reads are counted, the clock is
		// read once in a while
		p.unseen += n
		if p.unseen < paceLook {
			return
		}
		p.unseen = 0
	}
	now := time.Now()
	if p.start.IsZero() {
		p.start = now
	}
	elapsed := now.Sub(p.start)
	if elapsed < paceWindow {
		return
	}
	rate := float64(p.bytes) / elapsed.Seconds()
	received := p.bytes
	p.start, p.bytes = now, 0
	if p.written.Swap(0) > int64(received) {
		// it sends more than it receives: what comes in answers it, and is not held back
		p.wait, p.slow, p.probe, p.measured, p.measure = 0, 0, 0, 0, 0
		return
	}
	paced := p.wait > 0
	tried := false
	switch {
	case p.probe > 0:
		// read at once for a moment, to see whether the waits hold it back
		p.measured += received
		p.measure += elapsed
		p.probe--
		if p.probe > 0 {
			return
		}
		rate = float64(p.measured) / p.measure.Seconds()
		p.measured, p.measure = 0, 0
		if rate >= paceGain*p.paced {
			// faster without the waits: its data comes when it is asked for, not by itself
			p.aloneFor = min(max(p.aloneFor*2, paceAloneFor), paceAloneMax)
			p.alone = now.Add(p.aloneFor)
			p.tries = 0
			return
		}
		// as fast either way: it slowed down by itself, and is paced on from this rate
		tried = true
	case paced && rate < paceKeep*p.free:
		p.kept = 0
		p.slow++
		p.measured += received
		p.measure += elapsed
		if p.slow == paceSlow {
			p.try(float64(p.measured) / p.measure.Seconds())
			return
		}
	case paced:
		p.slow, p.measured, p.measure = 0, 0, 0
		p.kept++
		if p.kept == paceTrial {
			p.aloneFor = 0
		}
		p.windows++
		p.since += received
		p.sinceFor += elapsed
		due := paceProbeFirst
		if p.tries > 0 {
			due = min(paceProbeEvery<<min(p.tries-1, 8), paceProbeMax)
		}
		if p.windows >= due {
			p.try(float64(p.since) / p.sinceFor.Seconds())
			return
		}
	}
	p.wait = paceWait(rate)
	if now.Before(p.alone) {
		p.wait = 0
	}
	if p.wait > 0 && !paced {
		p.free, p.kept, p.slow = rate, 0, 0
		p.windows, p.since, p.sinceFor = 0, 0, 0
		if !tried {
			p.tries = 0 // paced anew: the first try comes soon again
		}
	}
}

// try reads the connection at once for a while, to see whether the waits hold it back: it
// brought paced bytes a second while paced.
func (p *readPace) try(paced float64) {
	p.paced = paced
	p.tries++
	p.wait, p.slow, p.probe = 0, 0, paceProbe
	p.measured, p.measure = 0, 0
	p.windows, p.since, p.sinceFor = 0, 0, 0
}

// paceWait is the wait before a read of the emptied socket of a connection that brings rate
// bytes a second: the time a batch takes to arrive, or nothing for a connection too slow to be
// paced.
func paceWait(rate float64) time.Duration {
	if rate < paceFrom {
		return 0
	}
	return min(max(time.Duration(paceBatch/rate*float64(time.Second)), paceMinWait), paceMaxWait)
}

// hPace is what a tracked connection keeps to pace its reads. //H
type hPace struct {
	stream  bool            // TCP: a stream of bytes, not datagrams
	pace    readPace        // of a stream's reads
	wake    wakePace        // of the wake-ups of the reads through the raw connection, see h_wake_pace.go
	raw     syscall.RawConn // the socket's raw connection, paced; nil when it has none
	rate    datagramRate    // of a datagram socket's plain reads
	reading sync.Mutex      // one plain read of a busy datagram socket at a time
	read    datagramRead
}

func (p *hPace) init(conn net.Conn) {
	p.stream = isStream(conn)
	if p.stream || pacingDisabled {
		return
	}
	p.wake.path.init(conn)
	if syscallConn, isSyscallConn := conn.(syscall.Conn); isSyscallConn {
		if rawConn, err := syscallConn.SyscallConn(); err == nil {
			p.raw = paceRawConn(rawConn, &p.wake)
		}
	}
}

// hSyscallConn is the socket's raw connection: a datagram socket's is paced. A stream's is not:
// through a raw connection nothing tells how much a read brought, so a trial as readPace's
// cannot tell a download from a fast exchange of questions and answers, which pacing would hold
// back at every answer.
func (c *trackedConn) hSyscallConn(conn syscall.Conn) (syscall.RawConn, error) {
	if c.stream {
		return conn.SyscallConn()
	}
	return hPacedSyscallConn(conn, &c.wake)
}

// Read paces the reads of a fast download: a stream's by how much each read brings (readPace), a
// datagram socket's by how often its reads are woken (wakePace). //H
func (c *trackedConn) Read(p []byte) (int, error) {
	if !c.stream {
		return c.readDatagram(p)
	}
	return c.pace.read(c.Conn, p)
}

// Write counts what a stream sends, for its read pacing, and tells the round trip of a datagram
// socket's path that something was written. //H
func (c *trackedConn) Write(p []byte) (int, error) {
	if !c.stream {
		c.wake.path.wrote()
		return c.Conn.Write(p)
	}
	n, err := c.Conn.Write(p)
	if n > 0 && !pacingDisabled {
		c.pace.written.Add(int64(n))
	}
	return n, err
}

// isStream reports a connection that is a stream of bytes (TCP), not datagrams.
func isStream(conn net.Conn) bool {
	if addr := conn.LocalAddr(); addr != nil {
		switch addr.Network() {
		case "tcp", "tcp4", "tcp6":
			return true
		}
	}
	return false
}
