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
//
// The one who cancels ctx closes the stored bridge after cancelling. A bridge that comes in
// after that is closed here: it was stored and left open, its call session running on with
// nobody to close it.
func connectWithRetry(ctx context.Context, logger logger.ContextLogger, connect func() (*call.Bridge, error), store func(*call.Bridge), afterFirst func()) {
	for attempt := 0; ; attempt++ {
		bridge, err := connect()
		if err == nil {
			store(bridge)
			if ctx.Err() != nil {
				bridge.Close()
			}
		}
		if attempt == 0 && afterFirst != nil {
			afterFirst()
		}
		// TODO(hiddify): a bridge whose session ends by itself is not connected again (call page,
		// known limitation 1): have the bridge report its end (a Done channel) and go on here.
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
