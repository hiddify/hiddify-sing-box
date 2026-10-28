package adapter

import (
	"strings"
	"sync/atomic"
	"time"
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

// HourglassFlip are the frames of the connecting marks: an hourglass that flips each second.
var HourglassFlip = []string{"⏳", "⌛"}

// Mark is what DisplayType adds for the status; nothing when ready. The hourglass of the
// connecting marks flips each second, so a display that refreshes shows it turning.
func (s Status) Mark() string {
	return s.mark(HourglassFlip[time.Now().Unix()%int64(len(HourglassFlip))])
}

func (s Status) mark(hourglass string) string {
	switch s {
	case StatusConnecting:
		return " " + hourglass + " Connecting..."
	case StatusReconnecting:
		return " " + hourglass + " Reconnecting..."
	case StatusSearching:
		return " 🔍 Searching..."
	case StatusFailed:
		return " ❌ Failed"
	case StatusRegistering:
		return " 🔑 Registering..."
	}
	return ""
}

// IsReady reports whether outbound carries traffic.
func IsReady(outbound Outbound) bool {
	return outbound.Status() == StatusReady
}

// SplitStatus separates a display type from its status mark, which is always last; mark is
// empty when it has none.
func SplitStatus(display string) (base string, mark string) {
	for _, status := range []Status{StatusConnecting, StatusReconnecting, StatusSearching, StatusFailed, StatusRegistering} {
		for _, hourglass := range HourglassFlip {
			if suffix := status.mark(hourglass); strings.HasSuffix(display, suffix) {
				return strings.TrimSuffix(display, suffix), strings.TrimSpace(suffix)
			}
		}
	}
	return display, ""
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
