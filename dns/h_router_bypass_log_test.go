package dns

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// hLevelLogger records the error and debug messages a router logs.
type hLevelLogger struct {
	log.ContextLogger
	access sync.Mutex
	errors []string
	debugs []string
}

func (l *hLevelLogger) ErrorContext(_ context.Context, args ...any) {
	l.access.Lock()
	l.errors = append(l.errors, fmt.Sprint(args...))
	l.access.Unlock()
}

func (l *hLevelLogger) DebugContext(_ context.Context, args ...any) {
	l.access.Lock()
	l.debugs = append(l.debugs, fmt.Sprint(args...))
	l.access.Unlock()
}

// A server failure that bypass_if_failed passes on is not an error: the next rule answers. A Fake
// DNS rule fails every non-address query (HTTPS, TXT, ...) and falls through, and logging each of
// those at error level filled the log.
func TestH_ExchangeBypassIfFailedLogsAtDebug(t *testing.T) {
	t.Parallel()
	logger := &hLevelLogger{ContextLogger: log.NewNOPFactory().NewLogger("dns")}
	router := newTestRouterWithContextAndLogger(t, context.Background(), []option.DNSRule{
		hRouteRule("example.com", "primary", true),
		hRouteRule("example.com", "secondary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary", "secondary"), hExchangeClient(&hTagRecorder{}, map[string]string{
		"secondary": "1.2.3.4",
	}), logger)

	response, err := router.Exchange(context.Background(), hQuery("example.com"), adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, MessageToAddresses(response))
	require.Empty(t, logger.errors)
	require.NotEmpty(t, logger.debugs)
}

// A failure with no bypass is still an error.
func TestH_ExchangeFailureWithoutBypassLogsError(t *testing.T) {
	t.Parallel()
	logger := &hLevelLogger{ContextLogger: log.NewNOPFactory().NewLogger("dns")}
	router := newTestRouterWithContextAndLogger(t, context.Background(), []option.DNSRule{
		hRouteRule("example.com", "primary", false),
		hLegacyModeRule(),
	}, hTransportManager("default", "primary"), hExchangeClient(&hTagRecorder{}, map[string]string{}), logger)

	_, err := router.Exchange(context.Background(), hQuery("example.com"), adapter.DNSQueryOptions{})
	require.Error(t, err)
	require.NotEmpty(t, logger.errors)
}
