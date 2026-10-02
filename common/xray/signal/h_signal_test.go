package signal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestH_NotifierCoalesces(t *testing.T) {
	t.Parallel()
	n := NewNotifier()
	n.Signal()
	n.Signal()
	n.Signal()
	select {
	case <-n.Wait():
	default:
		t.Fatal("expected signal")
	}
	select {
	case <-n.Wait():
		t.Fatal("signals should coalesce")
	default:
	}
}

func TestH_ActivityTimerCancelsAfterInactivity(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	CancelAfterInactivity(ctx, cancel, 50*time.Millisecond)
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("timer did not fire")
	}
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
}

func TestH_ActivityTimerUpdateKeepsAlive(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := CancelAfterInactivity(ctx, cancel, 100*time.Millisecond)
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		timer.Update()
		require.NoError(t, ctx.Err())
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("timer did not fire after updates stopped")
	}
}

func TestH_ActivityTimerSetTimeout(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := CancelAfterInactivity(ctx, cancel, time.Hour)
	timer.SetTimeout(30 * time.Millisecond)
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("shortened timeout did not fire")
	}

	calls := 0
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	timer2 := CancelAfterInactivity(ctx2, func() { calls++; cancel2() }, time.Hour)
	timer2.SetTimeout(0)
	require.Error(t, ctx2.Err())
	timer2.SetTimeout(0)
	timer2.SetTimeout(time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, 1, calls)
}
