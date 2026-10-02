package task

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestH_RunAllSucceed(t *testing.T) {
	t.Parallel()
	var count atomic.Int32
	tasks := make([]func() error, 5)
	for i := range tasks {
		tasks[i] = func() error {
			count.Add(1)
			return nil
		}
	}
	require.NoError(t, Run(context.Background(), tasks...))
	require.Equal(t, int32(5), count.Load())
	require.NoError(t, Run(context.Background()))
}

func TestH_RunReturnsFirstError(t *testing.T) {
	t.Parallel()
	expected := errors.New("boom")
	block := make(chan struct{})
	defer close(block)
	err := Run(context.Background(),
		func() error { <-block; return nil },
		func() error { return expected },
	)
	require.ErrorIs(t, err, expected)
}

func TestH_RunHonoursContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	block := make(chan struct{})
	defer close(block)
	err := Run(ctx, func() error { <-block; return nil })
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestH_OnSuccess(t *testing.T) {
	t.Parallel()
	var order []string
	f := OnSuccess(func() error { order = append(order, "f"); return nil }, func() error { order = append(order, "g"); return nil })
	require.NoError(t, f())
	require.Equal(t, []string{"f", "g"}, order)

	expected := errors.New("f failed")
	called := false
	f = OnSuccess(func() error { return expected }, func() error { called = true; return nil })
	require.ErrorIs(t, f(), expected)
	require.False(t, called)
}

type closer struct{ closed bool }

func (c *closer) Close() error {
	c.closed = true
	return nil
}

func TestH_Close(t *testing.T) {
	t.Parallel()
	c := &closer{}
	require.NoError(t, Close(c)())
	require.True(t, c.closed)
	require.NoError(t, Close("not closable")())
}

func TestH_PeriodicRunsAndStops(t *testing.T) {
	t.Parallel()
	var count atomic.Int32
	p := &Periodic{
		Interval: 10 * time.Millisecond,
		Execute: func() error {
			count.Add(1)
			return nil
		},
	}
	require.NoError(t, p.Start())
	require.GreaterOrEqual(t, count.Load(), int32(1))
	require.NoError(t, p.Start())
	require.Eventually(t, func() bool { return count.Load() >= 3 }, 3*time.Second, 5*time.Millisecond)
	require.NoError(t, p.Close())
	time.Sleep(30 * time.Millisecond)
	stopped := count.Load()
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, stopped, count.Load())
}

func TestH_PeriodicStopsOnError(t *testing.T) {
	t.Parallel()
	expected := errors.New("stop")
	var count atomic.Int32
	p := &Periodic{
		Interval: 5 * time.Millisecond,
		Execute: func() error {
			if count.Add(1) >= 2 {
				return expected
			}
			return nil
		},
	}
	require.NoError(t, p.Start())
	require.Eventually(t, func() bool { return p.hasClosed() }, 3*time.Second, 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	require.Equal(t, int32(2), count.Load())

	failing := &Periodic{Interval: time.Hour, Execute: func() error { return expected }}
	require.ErrorIs(t, failing.Start(), expected)
	require.True(t, failing.hasClosed())
}
