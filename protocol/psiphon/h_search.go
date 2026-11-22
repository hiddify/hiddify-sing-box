package psiphon

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// As the first hop (with the scanner), Psiphon searches for a way through for the scanner's
// search_timeout (1 minute): edge scans and tunnel core attempts, one after the other. When no
// tunnel comes up within it, the outbound offers a deep search (adapter.DeepSearcher) and goes on
// trying as before, with the restart backoff; the app starts the deep search when the user
// agrees, at once, ending the attempt that runs: the tunnel core then tries
// with no time limit in its aggressive mode, with more workers, and the scans with
// deep_concurrency. A search_timeout below zero, or above 3 minutes, is a deep search from the
// start. A new network starts a normal search again. Behind another proxy there is no search
// time: Psiphon retries as before.

var _ adapter.DeepSearcher = (*Outbound)(nil)

// minAttempt is the shortest establish time an attempt is given near the end of the search, and
// deepAttempt the time of an attempt of a deep search without a limit.
const (
	minAttempt  = 30 * time.Second
	deepAttempt = 10 * time.Minute
)

func (h *Outbound) searchOptions() *option.EdgeSearchOptions {
	if h.scanner == nil {
		return nil
	}
	return &h.scanner.options.EdgeSearchOptions
}

// limitSearch fits the next attempt into the search: the tunnel core gives up at the end of the
// search time, or keeps on, in its aggressive mode, in a deep search (see edgescan.SearchLimit).
func (h *Outbound) limitSearch(searchStart time.Time) {
	if h.scanner == nil {
		return
	}
	config := h.psiphon.config
	timeout, deep := edgescan.SearchLimit(h.searchOptions(), h.scanner.status.IsDeep())
	config.AggressiveEstablishment = deep
	left := max(timeout-time.Since(searchStart), minAttempt)
	switch {
	case timeout == 0:
		// no limit, in attempts of deepAttempt: each starts with a scan of the edges, so a
		// deep search follows what it learns and the network it is on
		config.EstablishTunnelTimeoutSeconds = durationToSecondsPtr(deepAttempt)
	case deep:
		config.EstablishTunnelTimeoutSeconds = durationToSecondsPtr(left)
	default:
		config.EstablishTunnelTimeoutSeconds = durationToSecondsPtr(min(h.establishTimeout, left))
	}
}

// searchFound ends the search: a tunnel is up.
func (h *Outbound) searchFound() {
	if h.scanner == nil {
		return
	}
	h.scanner.status.Exhausted(false)
	h.scanner.status.Deep(false)
	select { // a deep search or a network change asked for meanwhile is done
	case <-h.reconnectCh:
	default:
	}
}

// searchExhausted reports whether the search time is up without a tunnel, and marks it so: a
// deep search is offered. A deep search is exhausted at the end of its own time, if it has one,
// and offers another.
func (h *Outbound) searchExhausted(searchStart time.Time) bool {
	if h.scanner == nil {
		return false
	}
	deep := h.scanner.status.IsDeep()
	timeout, _ := edgescan.SearchLimit(h.searchOptions(), deep)
	if timeout <= 0 || time.Since(searchStart) < timeout {
		return false
	}
	if deep {
		h.scanner.status.Deep(false)
	}
	h.scanner.status.Exhausted(true)
	h.logger.Warn("psiphon: no tunnel in ", timeout, "; a deep search may find one")
	return true
}

// searchWoken starts the search over when the loop is woken: by a deep search asked for, which
// it runs, or by another network, where a normal search runs again and no deep search is offered
// until it gives up too.
func (h *Outbound) searchWoken() {
	if h.scanner != nil && !h.scanner.status.IsDeep() {
		h.scanner.status.Exhausted(false)
	}
}

// DeepSearchAvailable reports whether the search found no tunnel within its time, and no deep
// search runs.
func (h *Outbound) DeepSearchAvailable() bool {
	return h.scanner != nil && h.scanner.status.DeepSearchAvailable()
}

// StartDeepSearch starts a deep search, once a search gave up: see the top of this file.
func (h *Outbound) StartDeepSearch() error {
	if h.scanner == nil {
		return E.New("psiphon: no search behind another proxy")
	}
	if !h.scanner.status.DeepSearchAvailable() || !h.scanner.status.TryStartDeep() {
		return nil // nothing gave up, or a deep search runs
	}
	h.logger.Info("psiphon: deep search")
	if !h.psiphon.IsConnected() { // the attempt of the normal search ends now, not at its timeout
		h.psiphon.stop()
	}
	h.requestReconnect()
	return nil
}
