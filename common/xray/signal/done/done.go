package done

import (
	"sync"
)

type Instance struct {
	once sync.Once
	c    chan struct{}
}

// New returns a new Done.
func New() *Instance {
	return &Instance{
		c: make(chan struct{}),
	}
}

// Done returns true if Close() is called.
func (d *Instance) Done() bool {
	select {
	case <-d.c:
		return true
	default:
		return false
	}
}

// Wait returns a channel for waiting for done.
func (d *Instance) Wait() <-chan struct{} {
	return d.c
}

// Close marks this Done 'done'. This method may be called multiple times.
// All calls after the first call have no effect.
func (d *Instance) Close() error {
	d.once.Do(func() {
		close(d.c)
	})
	return nil
}
