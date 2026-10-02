package done

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestH_DoneCloseIdempotent(t *testing.T) {
	t.Parallel()
	d := New()
	require.False(t, d.Done())
	select {
	case <-d.Wait():
		t.Fatal("closed too early")
	default:
	}
	waited := make(chan struct{})
	go func() {
		<-d.Wait()
		close(waited)
	}()
	require.NoError(t, d.Close())
	require.NoError(t, d.Close())
	require.True(t, d.Done())
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("waiter not released")
	}
}
