package masque

import "time"

// reconnectBackoff is the wait after the given number of failed connects in a row (from 1): the
// configured delay when there is one, else a backoff as the client's, doubling from
// reconnectBackoffInitial up to reconnectBackoffMax. Without it a detour that fails at once
// would be redialed in a busy loop.
func reconnectBackoff(configured time.Duration, failures int) time.Duration {
	if configured > 0 {
		return configured
	}
	delay := reconnectBackoffInitial
	for i := 1; i < failures && delay < reconnectBackoffMax; i++ {
		delay *= 2
	}
	return min(delay, reconnectBackoffMax)
}
