package adapter

import (
	"sync/atomic"
)

// Status is the connection state of an outbound or an endpoint. //H
type Status uint8

const (
	// StatusReady: it carries traffic.
	StatusReady Status = iota
	// StatusConnecting: it has not connected yet.
	StatusConnecting
	// StatusReconnecting: it was connected and lost the connection.
	StatusReconnecting
	// StatusSearching: it looks for a server or an endpoint that answers.
	StatusSearching
	// StatusFailed: it gave up, or cannot work as configured.
	StatusFailed
	// StatusRegistering: it registers an account or a device with its service (WARP).
	StatusRegistering
)

func (s Status) String() string {
	switch s {
	case StatusReady:
		return "ready"
	case StatusConnecting:
		return "connecting"
	case StatusReconnecting:
		return "reconnecting"
	case StatusSearching:
		return "searching"
	case StatusFailed:
		return "failed"
	case StatusRegistering:
		return "registering"
	}
	return "unknown"
}

// IsReady reports whether outbound carries traffic.
func IsReady(outbound Outbound) bool {
	return outbound.Status() == StatusReady
}

// StatusTracker gives the status of a connection from whether it carries traffic now:
// connecting until it was first ready, reconnecting after. The zero value is ready to use.
type StatusTracker struct {
	wasReady atomic.Bool
}

func (t *StatusTracker) Status(ready bool) Status {
	if ready {
		t.wasReady.Store(true)
		return StatusReady
	}
	if t.wasReady.Load() {
		return StatusReconnecting
	}
	return StatusConnecting
}

// StatusErrorer is an outbound or an endpoint that can say why it is not ready: the error that
// failed it, or the one its last attempt to connect ended with.
type StatusErrorer interface {
	StatusError() error
}

// StatusError is why outbound is not ready; nil when it is ready or does not say.
func StatusError(outbound Outbound) error {
	if outbound.Status() == StatusReady {
		return nil
	}
	if errorer, ok := outbound.(StatusErrorer); ok {
		return errorer.StatusError()
	}
	return nil
}

// LastError keeps the last error of something that retries. The zero value is ready to use.
type LastError struct {
	err atomic.Pointer[error]
}

// Set keeps err; nil clears it.
func (l *LastError) Set(err error) {
	if err == nil {
		l.err.Store(nil)
		return
	}
	l.err.Store(&err)
}

// Get is the error kept, or nil.
func (l *LastError) Get() error {
	if err := l.err.Load(); err != nil {
		return *err
	}
	return nil
}
