package semaphore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_SemaphorePermits(t *testing.T) {
	t.Parallel()
	s := New(2)
	acquire := func() bool {
		select {
		case <-s.Wait():
			return true
		default:
			return false
		}
	}
	require.True(t, acquire())
	require.True(t, acquire())
	require.False(t, acquire())
	s.Signal()
	require.True(t, acquire())
	require.False(t, acquire())

	empty := New(0)
	select {
	case <-empty.Wait():
		t.Fatal("zero permit semaphore yielded")
	default:
	}
}
