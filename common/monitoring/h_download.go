package monitoring

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
)

// downloadTestError is an outbound's failed download test (option.MonitoringOptions.DownloadTestURL):
// its URL test answered, so the test URL is not what failed.
type downloadTestError struct{ error }

func (e downloadTestError) Unwrap() error { return e.error }

// isDownloadTestError says whether err is a failed download test.
func isDownloadTestError(err error) bool {
	var failed downloadTestError
	return errors.As(err, &failed)
}

// downloadTest runs the download test of an outbound whose URL test answered: a byte gap of the
// URL test timeout in the body fails it, and all of it may take three. Only a body that stops
// fails the outbound; a test that got no body tells nothing of it, and the URL test result
// stands. The device's own outbounds are not proxies and are not tested.
func (m *OutboundMonitoring) downloadTest(parent context.Context, tag string, out adapter.Outbound, factor time.Duration) error {
	switch out.Type() {
	case C.TypeDirect, C.TypeBlock, C.TypeDNS:
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 3*factor*m.urlTestTimeout)
	defer cancel()
	err := urltest.URLTestDownload(ctx, m.downloadTestURL, out, factor*m.urlTestTimeout)
	switch {
	case err == nil:
		return nil
	case parent.Err() != nil:
		return parent.Err()
	case errors.Is(err, urltest.ErrDownloadInconclusive):
		m.logger.Warn("MONITORING ", tag, ": the download test tells nothing, its URL test stands: ", err)
		return nil
	}
	return downloadTestError{err}
}
