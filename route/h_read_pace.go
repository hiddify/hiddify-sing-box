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
// call. The wait is short (at most paceMaxWait, and only on a connection that is already pouring
// data in), and the socket's own buffer holds what arrives during it. A connection that slows
// down is read at once again.
//
// That helps a download, whose data keeps coming whether it is read or not. It hurts an exchange
// of questions and answers with a peer that answers at once, a database or a file server on the
// local network: nothing more arrives while the read waits, and every answer is only late. So
// the first windows of a paced connection are a trial: if it then brings less than paceKeep of
// what it brought before, it is left alone, for paceAloneFor at first and twice as long each time
// it happens again.
//
// Measured on macOS, six downloads at once at 500 to 700 Mbit/s together: 10 to 15% less CPU for
// VMess and Snell, 25% for VLESS over HTTP, 35% for XHTTP over HTTP/2; a single connection that
// fills the line was already read in large pieces and gains nothing.
const (
	paceFrom    = 4 << 20                // bytes a second from which a connection's reads are paced
	paceBatch   = 48 << 10               // bytes a paced read aims to find waiting
	paceMinWait = 250 * time.Microsecond // the shortest wait worth a timer
	paceMaxWait = 2 * time.Millisecond   // the longest: what a paced connection may be late by
	paceWindow  = 25 * time.Millisecond  // the rate is measured over this long
	paceLate    = 20 * time.Millisecond  // a wait that took this long was not kept by the system
	paceOffFor  = 30 * time.Second       // how long pacing stays off after waits that came late, the first time
	paceOffMax  = 16 * time.Minute       // and at most: it doubles each time
	paceLateMax = 3                      // late waits in a row before it goes off

	paceTrial    = 4               // windows a connection that is paced anew is watched for
	paceKeep     = 0.7             // of its rate before: what it has to keep in them
	paceAloneFor = 5 * time.Second // how long a connection that pacing slowed is left alone, the first time
	paceAloneMax = 2 * time.Minute // and at most: it doubles each time
)

// pacingOff is when pacing may be used again (unix nanoseconds), after the system let its waits
// run late: timers held back for a process in the background would turn each short wait into a
// long one, and the download would crawl. Reading at once is always correct.
var pacingOff atomic.Int64

// pacingTrips counts how often pacing went off: on a system that never keeps short waits (a
// coarse clock, a process the system holds back) it is tried less and less often.
var pacingTrips atomic.Int32

// pacingTripped turns pacing off for a while, from at.
func pacingTripped(at time.Time) {
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
	wait    time.Duration // before a read of the empty socket; 0 while the connection is not fast
	drained bool          // the last read took everything the socket had
	late    int           // waits in a row that came late

	free     float64       // bytes a second in the window before it was paced
	trial    int           // windows of the trial that are left
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
	if time.Since(before) < paceLate {
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
	now := time.Now()
	if p.start.IsZero() {
		p.start = now
	}
	p.bytes += n
	elapsed := now.Sub(p.start)
	if elapsed < paceWindow {
		return
	}
	rate := float64(p.bytes) / elapsed.Seconds()
	p.start, p.bytes = now, 0
	paced := p.wait > 0
	if paced && p.trial > 0 {
		if rate < paceKeep*p.free {
			// slower since its reads wait: its data comes when it is asked for, not by itself
			p.aloneFor = min(max(p.aloneFor*2, paceAloneFor), paceAloneMax)
			p.alone = now.Add(p.aloneFor)
			p.wait, p.trial = 0, 0
			return
		}
		p.trial--
		if p.trial == 0 {
			p.aloneFor = 0
		}
	}
	if rate < paceFrom || now.Before(p.alone) {
		p.wait = 0
		return
	}
	if !paced {
		p.free, p.trial = rate, paceTrial
	}
	p.wait = min(max(time.Duration(paceBatch/rate*float64(time.Second)), paceMinWait), paceMaxWait)
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
