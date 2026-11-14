package procs

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fast makes the governor's clock short for a test and returns what restores it.
func fast(t *testing.T) {
	t.Helper()
	tick, idleTick, maxIdleTick, hold, maxHold, probe := Tick, IdleTick, MaxIdleTick, Hold, MaxHold, Probe
	Tick, IdleTick, MaxIdleTick, Hold, MaxHold, Probe = 20*time.Millisecond, 20*time.Millisecond, 40*time.Millisecond, 200*time.Millisecond, 2*time.Second, 100*time.Millisecond
	t.Cleanup(func() {
		Tick, IdleTick, MaxIdleTick, Hold, MaxHold, Probe = tick, idleTick, maxIdleTick, hold, maxHold, probe
	})
}

func waitProcs(t *testing.T, within time.Duration, ok func(procs int) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok(runtime.GOMAXPROCS(0)) {
		if time.Now().After(deadline) {
			t.Fatalf("GOMAXPROCS is %d: %s", runtime.GOMAXPROCS(0), what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// busy runs n goroutines that compute without a pause until the returned function is called.
func busy(n int) (stop func()) {
	var done atomic.Bool
	var group sync.WaitGroup
	for range n {
		group.Add(1)
		go func() {
			defer group.Done()
			x := 0
			for !done.Load() {
				x++
			}
			_ = x
		}()
	}
	return func() {
		done.Store(true)
		group.Wait()
	}
}

// The governor starts on one processor, adds processors while more goroutines want to run than it
// has, takes them away again when the work is over, and gives the runtime its own number back
// when it is closed.
func TestH_GovernorFollowsTheLoad(t *testing.T) {
	if runtime.NumCPU() < 4 {
		t.Skip("needs four cores")
	}
	fast(t)
	before := runtime.GOMAXPROCS(0)
	governor := Start(Options{Max: 4})
	require.NotNil(t, governor)
	defer governor.Close()
	waitProcs(t, time.Second, func(procs int) bool { return procs == 1 }, "it starts on one processor")

	stop := busy(8)
	waitProcs(t, 3*time.Second, func(procs int) bool { return procs == 4 }, "eight busy goroutines get every processor allowed")
	stop()
	waitProcs(t, 10*time.Second, func(procs int) bool { return procs == 1 }, "with nothing to do it goes back to one")

	require.NoError(t, governor.Close())
	require.Equal(t, before, runtime.GOMAXPROCS(0), "closing gives the runtime its number back")
}

// pipeline sends bursts of packets through a chain of three goroutines for d, as a proxy's data
// path does, and returns how many went through and the most processors in use meanwhile.
func pipeline(d time.Duration) (passed int64, most int) {
	first, second, third := make(chan int, 64), make(chan int, 64), make(chan int, 64)
	var count atomic.Int64
	done := make(chan struct{})
	go func() {
		for packet := range first {
			second <- packet + 1
		}
		close(second)
	}()
	go func() {
		for packet := range second {
			third <- packet + 1
		}
		close(third)
	}()
	go func() {
		for range third {
			count.Add(1)
		}
		close(done)
	}()
	most = 1
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		// a burst of packets every 200 microseconds: 80000 packets a second
		for i := range 16 {
			first <- i
		}
		time.Sleep(200 * time.Microsecond)
		most = max(most, runtime.GOMAXPROCS(0))
	}
	close(first)
	<-done
	return count.Load(), most
}

// A chain of goroutines that hand each packet to the next runs on one processor: nobody waits
// long, however many packets go through. (A machine busy with other work makes goroutines wait
// too, and then more processors are right: so one quiet run out of three is enough.)
func TestH_GovernorKeepsAPipelineOnOneProcessor(t *testing.T) {
	fast(t)
	governor := Start(Options{Max: 4})
	require.NotNil(t, governor)
	defer governor.Close()
	var most int
	for range 3 {
		waitProcs(t, 10*time.Second, func(procs int) bool { return procs == 1 }, "it settles on one processor")
		var passed int64
		passed, most = pipeline(1500 * time.Millisecond)
		require.Greater(t, passed, int64(20000), "the packets went through")
		if most == 1 {
			return
		}
	}
	t.Fatalf("a pipeline used %d processors", most)
}

// The decisions, on a made-up clock: a processor more when goroutines wait, two when many do;
// one less after a quiet time, watched, and given back at once with a longer wait before the
// next try when it was needed; never more than Max or less than Min.
func TestH_GovernorDecisions(t *testing.T) {
	at := time.Unix(1000, 0)
	tick := func(s *state, load float64) int {
		at = at.Add(Tick)
		return s.step(load, at)
	}
	quiet := func(s *state, d time.Duration) int {
		procs := s.procs
		for end := at.Add(d); at.Before(end); {
			procs = tick(s, 0.05)
		}
		return procs
	}
	s := newState(1, 4, at)
	require.Equal(t, 1, tick(s, 0.3), "some waiting is not load")
	require.Equal(t, 2, tick(s, 1.2), "goroutines wait: one more")
	require.Equal(t, 4, tick(s, 5), "many wait: two more")
	require.Equal(t, 4, tick(s, 9), "never more than Max")

	require.Equal(t, 4, quiet(s, Hold-2*Tick), "not before the quiet time is over")
	require.Equal(t, 3, quiet(s, 3*Tick), "one less after it")
	require.True(t, s.probing)
	require.Equal(t, 3, tick(s, 0.5), "watched: no further change while it is")
	require.Equal(t, 4, tick(s, 1.5), "needed after all: back at once")
	require.Equal(t, 2*Hold, s.hold, "and the next try waits twice as long")
	require.Equal(t, 4, quiet(s, 2*Hold-2*Tick))
	require.Equal(t, 3, quiet(s, 3*Tick))
	require.Equal(t, 3, quiet(s, Probe+Tick), "this time it was enough")
	require.Equal(t, Hold, s.hold, "so the wait is the usual one again")
	require.Equal(t, 1, quiet(s, 3*(Hold+Probe)+time.Second), "and with nothing to do it goes down to Min")
	require.Equal(t, 1, quiet(s, time.Minute), "never less than Min")

	// the wait before a try never grows past MaxHold
	for range 20 {
		tick(s, 2)
		quiet(s, s.hold+Tick)
		require.True(t, s.probing)
		tick(s, 2)
	}
	require.Equal(t, MaxHold, s.hold)
}

// Only one governor runs in a process: GOMAXPROCS is the whole process's.
func TestH_GovernorIsAlone(t *testing.T) {
	fast(t)
	before := runtime.GOMAXPROCS(0)
	first := Start(Options{})
	require.NotNil(t, first)
	second := Start(Options{})
	require.Nil(t, second, "a second one is not started")
	require.NoError(t, second.Close(), "and closing it is harmless")
	waitProcs(t, time.Second, func(procs int) bool { return procs == 1 }, "the first one still governs")
	require.NoError(t, first.Close())
	require.Equal(t, before, runtime.GOMAXPROCS(0))
	third := Start(Options{Min: 2})
	require.NotNil(t, third, "after the first is closed another can start")
	waitProcs(t, time.Second, func(procs int) bool { return procs == 2 }, "and starts at its minimum")
	require.NoError(t, third.Close())
	require.Equal(t, before, runtime.GOMAXPROCS(0))
}
