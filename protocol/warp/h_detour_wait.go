package warp

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

const (
	// detourReadyWait is how long auto mode waits for its detour to carry traffic before it races
	// the tunnels, and detourReadyPoll how often it looks.
	detourReadyWait = 30 * time.Second
	detourReadyPoll = 250 * time.Millisecond
)

// waitDetour holds the race of auto mode until the detour carries traffic. Every handshake of the
// race goes through the detour: while it is itself still connecting (warp in warp starts the
// inner WARP and this one together, and the inner one is racing its own tunnels), all of them
// stay silent for raceTimeout, and the tunnel is then chosen without a race and without its
// rating, with a "no tunnel answered" warning. It stops waiting when the start ends, when the
// detour fails or is unknown, and after detourReadyWait: a detour that does not become ready is
// raced through as before. It reports false when the start ended.
func (w *WARPEndpoint) waitDetour(done <-chan struct{}) bool {
	var status func() adapter.Status
	if w.options.Detour != "" {
		if manager := service.FromContext[adapter.OutboundManager](w.ctx); manager != nil {
			if detour, loaded := manager.Outbound(w.options.Detour); loaded {
				status = detour.Status
			}
		}
	}
	return waitReady(done, status, detourReadyWait, detourReadyPoll)
}

// waitReady polls status until it is ready, no longer on its way to it, or limit has passed.
func waitReady(done <-chan struct{}, status func() adapter.Status, limit, poll time.Duration) bool {
	if status == nil {
		return !ended(done)
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if ended(done) {
			return false
		}
		switch status() {
		case adapter.StatusReady, adapter.StatusFailed:
			return true
		}
		select {
		case <-done:
			return false
		case <-deadline.C:
			return true
		case <-ticker.C:
		}
	}
}

func ended(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
