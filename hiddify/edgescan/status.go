package edgescan

import (
	"net/netip"
	"sync"
)

// Status is what the scanner of an outbound is doing, for its display type. Scans may overlap
// (MASQUE auto mode scans its HTTP/3 and HTTP/2 endpoints at once): an endpoint found by one
// is kept while the others end without one.
type Status struct {
	access   sync.Mutex
	state    statusState
	endpoint netip.AddrPort
	// active counts the scans in progress; roundFound is whether one of the overlapping scans
	// since active was last zero found an endpoint.
	active     int
	roundFound bool
	// exhausted: the last search found nothing within its time (see Search); deep: a deep
	// search was asked for and runs, or waits for the next search
	exhausted bool
	deep      bool
}

// Exhausted marks a search that found nothing within its time, or clears the mark.
func (s *Status) Exhausted(exhausted bool) {
	s.access.Lock()
	s.exhausted = exhausted
	s.access.Unlock()
}

// DeepSearchAvailable reports whether the last search found nothing within its time, and no
// deep search runs: the user may start one (see adapter.DeepSearcher).
func (s *Status) DeepSearchAvailable() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.exhausted && !s.deep
}

// TryStartDeep marks a deep search asked for, and reports whether it was not already: one caller
// starts it.
func (s *Status) TryStartDeep() bool {
	s.access.Lock()
	defer s.access.Unlock()
	if s.deep {
		return false
	}
	s.deep = true
	s.exhausted = false
	return true
}

// Deep marks a deep search asked for, or ended; it clears the exhausted mark. A search clears it
// only when it was a deep one: a deep search asked for while a normal one ran is kept for after.
func (s *Status) Deep(deep bool) {
	s.access.Lock()
	s.deep = deep
	if deep {
		s.exhausted = false
	}
	s.access.Unlock()
}

// IsDeep reports whether a deep search was asked for and has not ended.
func (s *Status) IsDeep() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.deep
}

type statusState int

const (
	statusIdle statusState = iota
	statusScanning
	statusFound
	statusNotFound
)

// Begin marks a scan in progress.
func (s *Status) Begin() {
	s.access.Lock()
	if s.active == 0 {
		s.roundFound = false
	}
	s.active++
	if !s.roundFound {
		s.state = statusScanning
	}
	s.access.Unlock()
}

// Found marks the endpoint the scan chose.
func (s *Status) Found(endpoint netip.AddrPort) {
	s.access.Lock()
	if s.active > 0 {
		s.active--
	}
	s.roundFound = true
	s.state = statusFound
	s.endpoint = endpoint
	s.access.Unlock()
}

// NotFound marks a scan that found no endpoint that answers; while another scan is still
// running, or one of them found an endpoint, that one decides.
func (s *Status) NotFound() {
	s.access.Lock()
	defer s.access.Unlock()
	if s.active > 0 {
		s.active--
		if s.roundFound || s.active > 0 {
			return
		}
	}
	s.state = statusNotFound
}

// IsScanning reports whether a scan is in progress; the outbound then shows as searching.
func (s *Status) IsScanning() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.state == statusScanning
}

// String is the part of the display type for the scanner: the endpoint it chose, or that it
// found none; empty before the first scan and while scanning, when the status is searching.
func (s *Status) String() string {
	if s == nil {
		return ""
	}
	s.access.Lock()
	defer s.access.Unlock()
	if s.deep && s.state == statusScanning {
		return " · 🔍 Deep search"
	}
	switch s.state {
	case statusFound:
		return " · 🔍 " + s.endpoint.String()
	case statusNotFound:
		return " · 🔍 Not found"
	}
	return ""
}
