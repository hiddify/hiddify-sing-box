package pubsub

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func receive(t *testing.T, sub *Subscriber) any {
	t.Helper()
	select {
	case msg := <-sub.Wait():
		return msg
	case <-time.After(time.Second):
		t.Fatal("no message")
		return nil
	}
}

func TestH_PublishSubscribe(t *testing.T) {
	t.Parallel()
	s := NewService()
	defer s.ctask.Close()
	a := s.Subscribe("topic")
	b := s.Subscribe("topic")
	other := s.Subscribe("other")

	s.Publish("topic", 1)
	require.Equal(t, 1, receive(t, a))
	require.Equal(t, 1, receive(t, b))
	select {
	case <-other.Wait():
		t.Fatal("unexpected message on other topic")
	default:
	}

	require.NoError(t, b.Close())
	require.True(t, b.IsClosed())
	s.Publish("topic", 2)
	require.Equal(t, 2, receive(t, a))
	select {
	case <-b.Wait():
		t.Fatal("closed subscriber received message")
	default:
	}
}

func TestH_PublishDropsWhenFull(t *testing.T) {
	t.Parallel()
	s := NewService()
	defer s.ctask.Close()
	sub := s.Subscribe("t")
	for i := 0; i < 100; i++ {
		s.Publish("t", i)
	}
	require.Len(t, sub.buffer, cap(sub.buffer))
	require.Equal(t, 0, receive(t, sub))
}

func TestH_Cleanup(t *testing.T) {
	t.Parallel()
	s := NewService()
	defer s.ctask.Close()
	require.Error(t, s.Cleanup())
	a := s.Subscribe("a")
	b := s.Subscribe("b")
	b2 := s.Subscribe("b")
	a.Close()
	b.Close()
	require.NoError(t, s.Cleanup())
	s.RLock()
	_, hasA := s.subs["a"]
	require.False(t, hasA)
	require.Equal(t, []*Subscriber{b2}, s.subs["b"])
	s.RUnlock()
	b2.Close()
	require.NoError(t, s.Cleanup())
	require.Error(t, s.Cleanup())
}
