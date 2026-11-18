package warp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// A search for an endpoint goes on, round after round, for the scanner's search_timeout (3
// minutes): the first round usually finds one, and on a network that filters most of them the
// next rounds walk on through the ranges. When it finds nothing, the endpoint uses the profile's
// endpoint as before, and offers a deep search (adapter.DeepSearcher): no time limit and more
// workers, which the app starts when the user agrees. A search_timeout below zero, or above 3
// minutes, is a deep search from the start.

var _ adapter.DeepSearcher = (*WARPEndpoint)(nil)

// warpSearch is what a search found: the endpoints, and the noise they answered with.
type warpSearch struct {
	results []warpscan.Result
	noise   string
}

// search runs scanWith round after round, for the search time, or without a limit in a deep
// search (see edgescan.SearchLimit). The WARP endpoints that search the same network with the same
// probe at the same time share one search (see edgescan.Store.Do); each keeps the answers it does
// not exclude, and searches by itself when none is left.
func (w *WARPEndpoint) search(ctx context.Context, failover *warpFailover, exclude []netip.AddrPort) ([]warpscan.Result, error) {
	return w.searchWithin(ctx, failover, exclude, false, false)
}

// searchWithin is search; capped keeps it to DefaultSearchTimeout, as a normal search: the start
// does not wait for a deep one, which goes on after it (see connect). deepAsked makes it the deep
// search the user asked for, whatever the status says meanwhile.
func (w *WARPEndpoint) searchWithin(ctx context.Context, failover *warpFailover, exclude []netip.AddrPort, capped bool, deepAsked bool) ([]warpscan.Result, error) {
	timeout, deep := edgescan.SearchLimit(searchOptions(w.options.Scanner), deepAsked)
	if capped && deep {
		timeout, deep = edgescan.DefaultSearchTimeout, false
	}
	if !edgescan.Direct(w.ctx, w.options.Detour) {
		timeout, deep = -1, false // behind another proxy: one round, as before (see edgescan.Search)
	}
	run := func(ctx context.Context) (any, error) {
		var noise string
		results, err := edgescan.Search(ctx, w.logger, timeout, func(ctx context.Context) ([]warpscan.Result, error) {
			results, found, err := w.scanWith(ctx, failover, exclude, deep)
			noise = found
			return results, err
		})
		return warpSearch{results, noise}, err
	}
	w.scanStatus.Begin()
	var (
		value any
		err   error
	)
	if failover.store != nil {
		value, err = failover.store.Do(ctx, w.searchKey(failover, deep), run)
	} else {
		value, err = run(ctx)
	}
	found, _ := value.(warpSearch)
	results := excludeResults(found.results, exclude)
	if err == nil && len(results) == 0 { // every answer of the shared search is excluded here
		value, err = run(ctx)
		found, _ = value.(warpSearch)
		results = found.results
	}
	switch {
	case err == nil && len(results) > 0:
		w.useNoise(failover, found.noise)
		w.scanStatus.Found(results[0].AddrPort)
		w.scanStatus.Exhausted(false)
		if deepAsked {
			w.scanStatus.Deep(false)
		}
		return results, nil
	case errors.Is(err, edgescan.ErrSearchExhausted):
		w.scanStatus.NotFound()
		if deepAsked {
			w.scanStatus.Deep(false) // a deep search with a limit ended: another may be asked for
		}
		w.scanStatus.Exhausted(true)
		w.logger.WarnContext(w.ctx, "WARP scanner: nothing answered in ", timeout, "; a deep search may find an endpoint")
	default:
		w.scanStatus.NotFound()
	}
	if err == nil {
		err = E.New("WARP scanner: nothing answered")
	}
	return nil, err
}

// searchKey names a search for sharing: the network, the tunnel the probe is for, its noise and
// the scanner's options.
func (w *WARPEndpoint) searchKey(failover *warpFailover, deep bool) string {
	content, _ := json.Marshal(struct {
		Mode    string
		Noise   any
		AWG     any
		Scanner any
		Ports   any
		Deep    bool
	}{w.activeMode(), w.options.Noise, w.options.AWG, w.options.Scanner, failover.config.Peers[0].Endpoint.Ports, deep})
	sum := sha256.Sum256(content)
	return edgescan.KindWARP + "|" + failover.currentNetwork().Name + "|" + hex.EncodeToString(sum[:8])
}

// excludeResults is results without the endpoints of exclude.
func excludeResults(results []warpscan.Result, exclude []netip.AddrPort) []warpscan.Result {
	if len(exclude) == 0 {
		return results
	}
	kept := make([]warpscan.Result, 0, len(results))
	for _, result := range results {
		if !slices.Contains(exclude, result.AddrPort) {
			kept = append(kept, result)
		}
	}
	return kept
}

// masqueSearcher is the inner MASQUE tunnel, which searches by itself, or nil.
func (w *WARPEndpoint) masqueSearcher() adapter.DeepSearcher {
	if w.activeMode() != modeMASQUE {
		return nil
	}
	searcher, _ := w.currentEndpoint().(adapter.DeepSearcher)
	return searcher
}

// DeepSearchAvailable reports whether the last search found no endpoint and no deep search runs.
func (w *WARPEndpoint) DeepSearchAvailable() bool {
	if searcher := w.masqueSearcher(); searcher != nil {
		return searcher.DeepSearchAvailable()
	}
	return w.scanStatus.DeepSearchAvailable()
}

// StartDeepSearch searches on, without a time limit, and switches to the endpoint it finds. It does
// nothing unless a search gave up (DeepSearchAvailable): during the start's own search, the
// endpoint the deep one found would be overwritten by the start's.
func (w *WARPEndpoint) StartDeepSearch() error {
	if searcher := w.masqueSearcher(); searcher != nil {
		return searcher.StartDeepSearch()
	}
	session := w.session()
	w.mtx.Lock()
	failover := session.failover
	w.mtx.Unlock()
	if failover == nil {
		return E.New("WARP: the scanner is off")
	}
	if !w.scanStatus.DeepSearchAvailable() || !w.scanStatus.TryStartDeep() {
		return nil // nothing gave up, or a deep search runs
	}
	w.logger.InfoContext(w.ctx, "WARP scanner: deep search")
	go func() {
		failover.access.Lock() // no check meanwhile
		defer failover.access.Unlock()
		var exclude []netip.AddrPort
		if failover.current.IsValid() {
			exclude = append(exclude, failover.current)
		}
		results, err := w.searchWithin(session.ctx, failover, exclude, false, true)
		if err != nil {
			w.scanStatus.Deep(false)
			if session.ctx.Err() == nil {
				w.logger.WarnContext(w.ctx, "WARP scanner: deep search: ", err)
			}
			return
		}
		best := results[0].AddrPort
		replaced, err := w.replaceInner(session.done, failover.config, best.Addr().String(), best.Port())
		if err != nil {
			w.logger.ErrorContext(w.ctx, err)
			return
		}
		if !replaced {
			return
		}
		failover.current = best
		failover.connectedAt = time.Now()
		failover.recorded = true
		failover.lastTx = 0
		w.logger.InfoContext(w.ctx, "WARP scanner: deep search found ", best, " (", results[0].RTT, ")")
	}()
	return nil
}

// searchOptions are the search options of the scanner, nil without one.
func searchOptions(scanner *option.WARPScannerOptions) *option.EdgeSearchOptions {
	if scanner == nil {
		return nil
	}
	return &scanner.EdgeSearchOptions
}
