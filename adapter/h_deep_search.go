package adapter

import "sync"

// DeepSearcher is an outbound or an endpoint that searches for a way through (a WARP endpoint, a
// CDN edge for Psiphon) and gave up after its search time (search_timeout, 1 minute by
// default). A deep search goes on much longer, hours maybe, with more workers: it costs battery
// and CPU, so the app asks the user before it starts one.
type DeepSearcher interface {
	// DeepSearchAvailable reports whether the last search found nothing and no deep search runs.
	DeepSearchAvailable() bool
	// StartDeepSearch starts a deep search: no time limit (see deep_search_timeout) and
	// deep_concurrency workers, until something answers.
	StartDeepSearch() error
}

// DeepSearchAvailable reports whether outbound offers a deep search now (see DeepSearcher).
func DeepSearchAvailable(outbound any) bool {
	searcher, ok := outbound.(DeepSearcher)
	return ok && searcher.DeepSearchAvailable()
}

// deepSearchListeners hear when a DeepSearcher starts or stops offering a deep search. The app
// learns of it from the proxy list, which is otherwise sent again only with news of the
// monitoring: a search gives up between two of its tests, and the offer waited for the next one,
// minutes later.
var deepSearchListeners struct {
	sync.Mutex
	channels map[chan struct{}]struct{}
}

// SubscribeDeepSearch returns a channel that receives when a deep search is offered or no longer
// is, and the function that ends the subscription. Changes close together are one receive.
func SubscribeDeepSearch() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	deepSearchListeners.Lock()
	if deepSearchListeners.channels == nil {
		deepSearchListeners.channels = make(map[chan struct{}]struct{})
	}
	deepSearchListeners.channels[ch] = struct{}{}
	deepSearchListeners.Unlock()
	return ch, func() {
		deepSearchListeners.Lock()
		delete(deepSearchListeners.channels, ch)
		deepSearchListeners.Unlock()
	}
}

// DeepSearchChanged tells the listeners that a DeepSearcher started or stopped offering a deep
// search.
func DeepSearchChanged() {
	deepSearchListeners.Lock()
	defer deepSearchListeners.Unlock()
	for ch := range deepSearchListeners.channels {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
