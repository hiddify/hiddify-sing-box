package call

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/transport/call"
	"github.com/sagernet/sing/common/logger"
)

// connectRetryDelays are the waits between failed connects; the last repeats.
var connectRetryDelays = []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, time.Minute}

// connectWithRetry connects until it works or ctx ends, and stores the bridge. afterFirst runs
// after the first try, whatever its result, so dials waiting for the start do not wait for the
// retries.
func connectWithRetry(ctx context.Context, logger logger.ContextLogger, connect func() (*call.Bridge, error), store func(*call.Bridge), afterFirst func()) {
	for attempt := 0; ; attempt++ {
		bridge, err := connect()
		if err == nil {
			store(bridge)
		}
		if attempt == 0 && afterFirst != nil {
			afterFirst()
		}
		if err == nil || ctx.Err() != nil {
			return
		}
		delay := connectRetryDelays[min(attempt, len(connectRetryDelays)-1)]
		logger.ErrorContext(ctx, err, ", retrying in ", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}
