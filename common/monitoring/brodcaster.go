package monitoring

import (
	"context"
	"sync"
)

type Broadcaster[T any] struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu   sync.RWMutex
	subs map[chan T]struct{}
	once sync.Once
}

func NewBroadcaster[T any](parent context.Context) *Broadcaster[T] {
	ctx, cancel := context.WithCancel(parent)
	b := &Broadcaster[T]{
		ctx:    ctx,
		cancel: cancel,
		subs:   make(map[chan T]struct{}),
	}

	go b.watchContext()
	return b
}

func (b *Broadcaster[T]) watchContext() {
	<-b.ctx.Done()
	b.closeAll()
}

func (b *Broadcaster[T]) Subscribe(buffer int) <-chan T {
	ch := make(chan T, buffer)

	b.mu.Lock()
	defer b.mu.Unlock()

	select {
	case <-b.ctx.Done():
		close(ch)
	default:
		b.subs[ch] = struct{}{}
	}

	return ch
}

func (b *Broadcaster[T]) Unsubscribe(ch <-chan T) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for sub := range b.subs {
		if sub == ch {
			delete(b.subs, sub)
			close(sub)
			return
		}
	}
}

func (b *Broadcaster[T]) Publish(event T) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subs {
		select {
		case ch <- event:
		case <-b.ctx.Done():
			return
		default:
			// slow subscriber → drop event
		}
	}
}

func (b *Broadcaster[T]) Close() {
	b.once.Do(func() {
		b.cancel()
	})
}

func (b *Broadcaster[T]) closeAll() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for ch := range b.subs {
		close(ch)
	}
	b.subs = nil
}
