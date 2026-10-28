package warpscan

import (
	"net/netip"
	"sync"
)

// Status is what the scanner of an outbound is doing, for its display type.
type Status struct {
	access   sync.Mutex
	state    statusState
	endpoint netip.AddrPort
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
	s.state = statusScanning
	s.access.Unlock()
}

// Found marks the endpoint the scan chose.
func (s *Status) Found(endpoint netip.AddrPort) {
	s.access.Lock()
	s.state = statusFound
	s.endpoint = endpoint
	s.access.Unlock()
}

// NotFound marks a scan that found no endpoint that answers.
func (s *Status) NotFound() {
	s.access.Lock()
	s.state = statusNotFound
	s.access.Unlock()
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
	switch s.state {
	case statusFound:
		return " · 🔍 " + s.endpoint.String()
	case statusNotFound:
		return " · 🔍 Not found"
	}
	return ""
}
