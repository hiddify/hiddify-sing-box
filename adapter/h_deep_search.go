package adapter

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
