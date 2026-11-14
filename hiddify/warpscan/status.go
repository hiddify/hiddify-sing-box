package warpscan

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
	switch s.state {
	case statusFound:
		return " · 🔍 " + s.endpoint.String()
	case statusNotFound:
		return " · 🔍 Not found"
	}
	return ""
}
