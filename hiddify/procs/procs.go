// Package procs keeps the number of Go processors (GOMAXPROCS) as low as the load allows.
//
// Go runs goroutines on as many processors as the machine has cores. A proxy's data path is a
// chain of goroutines that hand each packet to the next: the socket reader, the QUIC or WireGuard
// connection, the stream's reader, the writer of acknowledgements. With spare processors the
// runtime wakes another thread for every such hand-over, and that thread finds the work already
// taken, looks for more for a moment, and goes back to sleep. On a tunnel that carries thousands
// of packets a second these wake-ups are most of the CPU the proxy uses, more than the encryption
// and the system calls together: with one processor the same download takes half the CPU, at the
// same speed, because a goroutine that is handed a packet simply runs next on the thread that is
// already awake.
//
// So the Governor starts with Min processors (one) and looks at how long goroutines wait for a
// processor, which the runtime measures. The waits of a tick, added up and divided by its length,
// are how many goroutines were waiting on average: the load, as a system's load average. With a
// load of UpLoad or more there is more work than the processors can take, and it adds one (two
// when the load is several times that). After a quiet time it takes one away again and watches:
// if the load is back at once, it returns the processor and waits twice as long before the next
// try. A machine that is busy for a moment (a start, a test of hundreds of proxies, a gigabit
// download) gets its cores within a tick or two; the rest of the time the proxy stays on one.
//
// One processor has a price: the garbage collector takes its share of that processor in slices,
// so a few times a second, under a heavy download, a goroutine may wait a few milliseconds. That
// does not count as load, and it is the trade for half the CPU. Min set to 2 avoids it.
package procs

import (
	"math"
	"runtime"
	"runtime/metrics"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// These are variables for tests.
var (
	// Tick is how often the load is looked at. While nothing runs it is looked at less and less
	// often, from IdleTick up to MaxIdleTick, so that an idle proxy is not woken for it.
	Tick        = 100 * time.Millisecond
	IdleTick    = 500 * time.Millisecond
	MaxIdleTick = 2 * time.Second
	// UpLoad is the load (goroutines waiting for a processor, on average over a tick) from which
	// a processor is added, and DownLoad the load under which one may be taken away.
	UpLoad   = 1.0
	DownLoad = 0.25
	// Hold is the quiet time before a processor is taken away, MaxHold what it grows to when
	// taking one away keeps failing, and Probe how long a lower number is watched.
	Hold    = 3 * time.Second
	MaxHold = 2 * time.Minute
	Probe   = time.Second
)

const (
	latencies = "/sched/latencies:seconds"
	// The runtime measures one in eight of the times a goroutine waits to run (gTrackingPeriod).
	sampling = 8
)

// Options configures a Governor.
type Options struct {
	Min    int // the least processors; 0 is one
	Max    int // the most; 0 is what the runtime started with (the machine's cores, or GOMAXPROCS)
	Logger logger.Logger
}

// Governor sets GOMAXPROCS from the load until it is closed.
type Governor struct {
	min, max int
	logger   logger.Logger
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once

	sample []metrics.Sample
	seen   []uint64  // the runtime's count of waits of each length, at the last read
	readAt time.Time // when that was
}

var (
	access   sync.Mutex
	running  *Governor
	original int // GOMAXPROCS before the first Governor
)

// Start starts a Governor. GOMAXPROCS belongs to the whole process, so only one runs at a time:
// a second Start returns nil, which is safe to Close.
func Start(options Options) *Governor {
	access.Lock()
	defer access.Unlock()
	if running != nil {
		return nil
	}
	original = runtime.GOMAXPROCS(0)
	g := &Governor{
		min:    max(options.Min, 1),
		max:    options.Max,
		logger: options.Logger,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		sample: []metrics.Sample{{Name: latencies}},
	}
	if g.max <= 0 {
		g.max = original
	}
	g.max = max(g.max, g.min)
	metrics.Read(g.sample)
	if g.sample[0].Value.Kind() != metrics.KindFloat64Histogram {
		return nil // a runtime without the measure: leave it alone
	}
	g.read()
	running = g
	go g.run()
	return g
}

// Range is the least and the most processors the Governor uses.
func (g *Governor) Range() (least int, most int) {
	return g.min, g.max
}

// Close stops the Governor and gives the runtime back the processors it started with.
func (g *Governor) Close() error {
	if g == nil {
		return nil
	}
	g.once.Do(func() {
		close(g.stop)
		<-g.done
		access.Lock()
		if running == g {
			running = nil
			runtime.GOMAXPROCS(original)
		}
		access.Unlock()
	})
	return nil
}

// read returns the load since the last read: how many goroutines were waiting for a processor,
// on average. It is the time goroutines waited, all together, over the time that passed.
func (g *Governor) read() float64 {
	metrics.Read(g.sample)
	now := time.Now()
	histogram := g.sample[0].Value.Float64Histogram()
	if g.seen == nil {
		g.seen = make([]uint64, len(histogram.Counts))
		copy(g.seen, histogram.Counts)
		g.readAt = now
		return 0
	}
	var waited float64 // seconds
	for i, count := range histogram.Counts {
		if count == g.seen[i] {
			continue
		}
		waited += float64(count-g.seen[i]) * bucketWait(histogram.Buckets[i], histogram.Buckets[i+1])
		g.seen[i] = count
	}
	elapsed := now.Sub(g.readAt).Seconds()
	g.readAt = now
	if elapsed <= 0 {
		return 0
	}
	return waited * sampling / elapsed
}

// bucketWait is the wait a histogram bucket [from, to) stands for, in seconds.
func bucketWait(from, to float64) float64 {
	switch {
	case math.IsInf(from, -1):
		return max(to, 0) / 2
	case math.IsInf(to, 1):
		return from
	default:
		return (from + to) / 2
	}
}

// state is what the Governor decides from: the processors in use and when and how they changed.
type state struct {
	min, max   int
	procs      int
	hold       time.Duration // the quiet time before the next processor is taken away
	changed    time.Time     // when the number last changed
	probing    bool          // a processor was taken away and the lower number is being watched
	probeUntil time.Time
}

func newState(least, most int, now time.Time) *state {
	return &state{min: least, max: most, procs: least, hold: Hold, changed: now}
}

// step takes the load of the tick that ended at now and returns the number of processors to use.
func (s *state) step(load float64, now time.Time) int {
	switch {
	case load >= UpLoad && s.procs < s.max:
		if s.probing {
			// it was needed after all: try later next time
			s.hold = min(s.hold*2, MaxHold)
		}
		add := 1
		if load >= UpLoad*4 {
			add = 2
		}
		s.procs = min(s.procs+add, s.max)
		s.changed, s.probing = now, false
	case s.probing && now.After(s.probeUntil):
		// the lower number was enough
		s.probing = false
		s.hold = Hold
	case load < DownLoad && !s.probing && s.procs > s.min && now.Sub(s.changed) >= s.hold:
		s.procs--
		s.changed, s.probing, s.probeUntil = now, true, now.Add(Probe)
	}
	return s.procs
}

func (g *Governor) run() {
	defer close(g.done)
	current := newState(g.min, g.max, time.Now())
	runtime.GOMAXPROCS(current.procs)
	g.read()
	var (
		idleTick time.Duration // the tick while nothing runs; 0 while something does
		timer    = time.NewTimer(Tick)
	)
	defer timer.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-timer.C:
		}
		load := g.read()
		before := current.procs
		procs := current.step(load, time.Now())
		if procs != before {
			runtime.GOMAXPROCS(procs)
			if g.logger != nil {
				g.logger.Debug("procs: ", before, " to ", procs, ", load ", int(load*100), "%")
			}
		}
		if procs == g.min && load == 0 {
			idleTick = min(max(idleTick*2, IdleTick), MaxIdleTick)
			timer.Reset(idleTick)
		} else {
			idleTick = 0
			timer.Reset(Tick)
		}
	}
}
