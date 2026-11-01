package ipinfo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func traceServer(t *testing.T, body string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

// The trace endpoint answers key=value lines: ip and loc are the measurement, the rest is noise.
func TestH_CloudflareTraceProvider(t *testing.T) {
	server := traceServer(t, "fl=123abc\nh=cloudflare.com\nip=104.28.229.14\nts=1.0\nvisit_scheme=https\nloc=DE\ncolo=FRA\n")
	provider := NewCloudflareTraceProvider()
	provider.URL = server.URL + "/cdn-cgi/trace"
	dialer := &loopbackDialer{addr: server.Listener.Addr().String()}
	info, delay, err := provider.GetIPInfo(testCtx(t), dialer)
	require.NoError(t, err)
	require.Equal(t, "104.28.229.14", info.IP)
	require.Equal(t, "DE", info.CountryCode)
	require.Less(t, delay, uint16(65535))
}

// A page without ip= (a challenge or a redirect answered) is no measurement, not an empty one.
func TestH_CloudflareTraceProviderWithoutIP(t *testing.T) {
	server := traceServer(t, "<html>checking your browser</html>")
	provider := NewCloudflareTraceProvider()
	provider.URL = server.URL + "/cdn-cgi/trace"
	dialer := &loopbackDialer{addr: server.Listener.Addr().String()}
	info, _, err := provider.GetIPInfo(testCtx(t), dialer)
	require.Error(t, err)
	require.Nil(t, info)
}
