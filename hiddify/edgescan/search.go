package edgescan

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// DefaultSearchTimeout is how long a search goes on before it offers a deep search. It is short:
// while the unblocker hop searches, the VPN is on and nothing loads, and users gave up before the
// offer came (it was 3 minutes).
const DefaultSearchTimeout = time.Minute

// deepSearchAbove is the search_timeout above which a search is a deep one from the start, with
// that limit.
const deepSearchAbove = 3 * time.Minute

// minRound spaces the rounds of a search, so a small space is not probed in a tight loop.
var minRound = 5 * time.Second

// ErrSearchExhausted is the error of a search that found nothing within its time: a deep search
// (see Search) may still find something, in hours.
var ErrSearchExhausted = errors.New("search exhausted")

// SearchLimit is how long a search of options goes on, 0 for no limit, and whether it is a deep
// one (more workers, see Request.Deep). search_timeout is the one setting: 1 minute by default;
// a deep search has no limit (below zero) or a long one (above deepSearchAbove, 3 minutes). A
// deep search the user asked for keeps a long search_timeout, and otherwise has no limit.
func SearchLimit(options *option.EdgeSearchOptions, deepAsked bool) (time.Duration, bool) {
	timeout := DefaultSearchTimeout
	if options != nil && options.SearchTimeout != 0 {
		timeout = time.Duration(options.SearchTimeout)
	}
	switch {
	case timeout < 0:
		return 0, true
	case timeout > deepSearchAbove:
		return timeout, true
	case deepAsked:
		return 0, true
	}
	return timeout, false
}

// ConfiguredDeep reports whether options ask for a deep search from the start.
func ConfiguredDeep(options *option.EdgeSearchOptions) bool {
	_, deep := SearchLimit(options, false)
	return deep
}

// Search runs round after round of scan until one finds something, for timeout (no limit when
// zero). Each round goes on with the walk where the last stopped, so a long search covers the
// whole space. It returns ErrSearchExhausted, with the last round's error, when the time is up.
// It only searches while the box has a network (see WaitReachable): without one it waits, and
// the wait does not count toward timeout, so a phone without Wi-Fi or mobile data spends nothing
// on probes, and a search is not given up because the network was away.
//
// A negative timeout is a single round: a scanner behind another proxy (see Direct) searches
// that proxy's network, where waiting minutes for an answer only delays the fallback.
func Search(ctx context.Context, logger logger.ContextLogger, timeout time.Duration, scan func(ctx context.Context) ([]Result, error)) ([]Result, error) {
	if timeout < 0 {
		if _, ok := WaitReachable(ctx, logger); !ok {
			return nil, ctx.Err()
		}
		return scan(ctx)
	}
	remaining := timeout
	for round := 1; ; round++ {
		if _, ok := WaitReachable(ctx, logger); !ok {
			return nil, ctx.Err()
		}
		start := time.Now()
		roundCtx, cancel := ctx, context.CancelFunc(func() {})
		if timeout > 0 {
			roundCtx, cancel = context.WithTimeout(ctx, remaining)
		}
		results, err := scan(roundCtx)
		if err == nil {
			cancel()
			return results, nil
		}
		if ctx.Err() != nil {
			cancel()
			return nil, ctx.Err()
		}
		logger.DebugContext(ctx, "search round ", round, ": ", err)
		if wait := minRound - time.Since(start); wait > 0 {
			select {
			case <-roundCtx.Done():
			case <-time.After(wait):
			}
		}
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if timeout > 0 {
			remaining -= time.Since(start)
			if remaining <= 0 {
				return nil, E.Errors(ErrSearchExhausted, err)
			}
		}
	}
}

// probeSlots bounds the probes of every scan of the process at once: several WARP endpoints and
// Psiphon, each with its own concurrency, do not add up to more than the device takes.
var probeSlots = make(chan struct{}, PlatformDefault(32, 128))

// acquireProbe waits for a probe slot; false when ctx ends first.
func acquireProbe(ctx context.Context) bool {
	select {
	case probeSlots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func releaseProbe() { <-probeSlots }
