package route

import (
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// The wake-ups of a busy socket are paced.
//
// A reader that waits for a socket is woken for the first datagram (or segment) that arrives, and
// takes what is there: on a tunnel that brings 15000 datagrams a second, one or two. Each wake-up
// costs a wake of a thread, a poll of the kernel and a read that finds the socket empty again, and
// on a QUIC or WireGuard tunnel it runs through the whole receive path: the packet is decrypted,
// an acknowledgement is sent for every second packet, the stream's reader is woken, a small write
// goes to the application. Almost all the CPU such a tunnel uses goes into these wake-ups and
// system calls, not into the data.
//
// So a reader that is woken on a busy socket waits a moment before it reads, and then takes
// everything that arrived meanwhile: the batch readers of QUIC, WireGuard and the UDP relay fill
// their batches, one acknowledgement answers the whole batch, and the application gets one large
// write.
//
// Busy is measured where the cost is: by how long the reads wait for the next arrival. While they
// wait wakeBusyGap or less on average, which is 4000 wake-ups a second or more, the socket is
// paced, with a wait of about wakeBatch arrivals, at most wakeMaxWait. A socket that is not busy
// (a call, a game, DNS, a page that loads) is read at once, as before, and a paced one that calms
// down is too after one window. The socket's own buffer holds what arrives during the wait.
//
// A wait is never more than a small part of the path's round trip (see h_path_rtt.go): on this
// machine, on the local network and to a server nearby nothing is paced, because there a wait is
// several round trips, which slows the peer down and makes every answer late. And a socket so
// busy that the shortest wait would gather more than wakeBatchMax arrivals is not paced either:
// its reads find a batch anyway, and more would not fit a small socket buffer.
//
// This is what a network card does with its interrupts (interrupt moderation), one level up. It
// works at the raw connection (syscall.RawConn) every reader below gets its socket from, so it is
// the same on every system.
const (
	wakeBusyGap  = 250 * time.Microsecond // reads waiting this long or less for the next arrival, on average: a busy socket
	wakeBatch    = 24                     // arrivals a paced wake-up aims to find waiting
	wakeBatchMax = 64                     // and at most: what a socket buffer of the default size holds
	wakeMinWait  = 200 * time.Microsecond // the shortest wait worth a timer
	wakeMaxWait  = time.Millisecond       // the longest: what a paced socket may be late by
	wakeMinWaits = 8                      // waits a window needs before their average says anything
)

// wakePace is the pacing of one socket's wake-ups. The socket's read lock, which every read
// through its raw connection holds, guards it.
type wakePace struct {
	start time.Time     // of the window the waits are measured over
	waits int           // reads in it that found the socket empty and waited
	idle  time.Duration // how long they waited for the next arrival, together
	wait  time.Duration // after a wake-up, before the read; 0 while the socket is not paced
	late  int           // waits in a row that came late
	path  pathRTT       // the round trip of the socket's path, which bounds the wait
}

// woke is called when a read that found the socket empty at since is woken for an arrival.
func (p *wakePace) woke(since time.Time) {
	now := time.Now()
	p.path.arrived(since, now)
	p.observe(since, now)
	if p.wait > 0 {
		p.pause(now)
	}
}

// observe counts a read that waited from since to now, and at the end of each window sets the
// wait from how long the window's reads waited.
func (p *wakePace) observe(since time.Time, now time.Time) {
	if p.start.IsZero() {
		p.start = since
	}
	p.waits++
	p.idle += now.Sub(since)
	if now.Sub(p.start) >= paceWindow {
		p.measure()
		p.start, p.waits, p.idle = now, 0, 0
	}
}

// measure sets the wait from how long the reads of the window waited.
func (p *wakePace) measure() {
	if p.waits < wakeMinWaits {
		p.wait = 0
		return
	}
	p.wait = wakeWait(p.idle/time.Duration(p.waits), p.path.longestWait())
}

// wakeWait is the wait after a wake-up of a socket whose reads wait gap for the next arrival, on
// a path that allows a wait of longest.
func wakeWait(gap time.Duration, longest time.Duration) time.Duration {
	if gap > wakeBusyGap {
		return 0 // not busy
	}
	longest = min(longest, wakeMaxWait)
	if longest < wakeMinWait {
		return 0 // a short path, or one not measured: the wait would be a large part of its round trip
	}
	if wakeBatchMax*gap < wakeMinWait {
		return 0 // so busy that its reads find a batch anyway
	}
	return min(max(wakeBatch*gap, wakeMinWait), longest)
}

// pause lets more arrive, unless waits have been coming late.
func (p *wakePace) pause(before time.Time) {
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

// pacedRawConn is a socket's raw connection whose reads are paced.
type pacedRawConn struct {
	syscall.RawConn
	pace  *wakePace
	read  wakeRead    // of the one read that runs at a time, as a rule
	inUse atomic.Bool // read is taken
}

// paceRawConn returns rawConn with its reads paced by pace.
func paceRawConn(rawConn syscall.RawConn, pace *wakePace) syscall.RawConn {
	if pacingDisabled {
		return rawConn
	}
	conn := &pacedRawConn{RawConn: rawConn, pace: pace}
	conn.read.pace = pace
	conn.read.step = conn.read.tryRead
	return conn
}

// hPacedSyscallConn is the raw connection of a tracked socket: the socket's own, paced by pace.
func hPacedSyscallConn(conn syscall.Conn, pace *wakePace) (syscall.RawConn, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return paceRawConn(rawConn, pace), nil
}

// The writes of a tracked datagram socket tell its path's round trip that something was written,
// and its plain reads that something arrived.

func (c *trackedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.wake.path.wroteTo(addr)
	return c.NetPacketConn.WriteTo(p, addr)
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.wake.path.written.Load() == 0 {
		if destination.Addr.IsLoopback() {
			c.wake.path.local.Store(true)
		}
		c.wake.path.wrote()
	}
	return c.NetPacketConn.WritePacket(buffer, destination)
}

func (c *trackedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.NetPacketConn.ReadFrom(p)
	if n > 0 {
		c.wake.path.read()
	}
	return n, addr, err
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.NetPacketConn.ReadPacket(buffer)
	if err == nil {
		c.wake.path.read()
	}
	return destination, err
}

func (c *pacedRawConn) Read(f func(fd uintptr) (done bool)) error {
	read := &c.read
	own := c.inUse.CompareAndSwap(false, true)
	if !own {
		// a second read of the same socket at the same time
		read = &wakeRead{pace: c.pace}
		read.step = read.tryRead
	}
	read.f, read.waiting = f, time.Time{}
	err := c.RawConn.Read(read.step)
	read.f = nil
	if own {
		c.inUse.Store(false)
	}
	return err
}

// Write tells the path's round trip that something was written.
func (c *pacedRawConn) Write(f func(fd uintptr) (done bool)) error {
	c.pace.path.wrote()
	return c.RawConn.Write(f)
}

// wakeRead is one read through a pacedRawConn: f is tried, and each time it finds the socket
// empty the read waits for the socket and is woken (step is called again) when something arrives.
type wakeRead struct {
	pace    *wakePace
	f       func(fd uintptr) (done bool)
	waiting time.Time             // since when the read waits for the socket; zero before
	step    func(fd uintptr) bool // tryRead, bound once
}

func (r *wakeRead) tryRead(fd uintptr) bool {
	waited := !r.waiting.IsZero()
	if waited {
		r.pace.woke(r.waiting)
	}
	if r.f(fd) {
		if !waited {
			r.pace.path.read()
		}
		return true
	}
	r.waiting = time.Now()
	return false
}

// datagramRate tells whether a datagram socket is busy enough for its plain reads to go through
// the paced raw connection: the reads of a socket below datagramBusy stay exactly as they were.
// Only the goroutine that reads uses it.
type datagramRate struct {
	start     time.Time
	datagrams int
	busy      bool
}

const (
	datagramBusy = 3000 // datagrams a second
	datagramLook = 16   // the clock is read once in this many datagrams
)

func (r *datagramRate) count() {
	r.datagrams++
	if r.datagrams%datagramLook != 0 {
		return
	}
	now := time.Now()
	if r.start.IsZero() {
		r.start, r.datagrams = now, 0
		return
	}
	elapsed := now.Sub(r.start)
	if elapsed < paceWindow {
		return
	}
	r.busy = float64(r.datagrams) >= datagramBusy*elapsed.Seconds()
	r.start, r.datagrams = now, 0
}
