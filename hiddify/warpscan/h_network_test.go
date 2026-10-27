package warpscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestH_ParseTrace(t *testing.T) {
	address, location, err := parseTrace(strings.NewReader("fl=29f\nh=www.cloudflare.com\nip=2.176.10.20\nts=1\nloc=IR\nwarp=off\n"))
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("2.176.10.20"), address)
	require.Equal(t, "IR", location)
	_, _, err = parseTrace(strings.NewReader("<html>blocked</html>"))
	require.Error(t, err)
}

// Addresses of one carrier pool or a changing ISP address map to one network.
func TestH_PublicPrefix(t *testing.T) {
	require.Equal(t, netip.MustParsePrefix("2.176.0.0/16"), publicPrefix(netip.MustParseAddr("2.176.10.20")))
	require.Equal(t, publicPrefix(netip.MustParseAddr("2.176.10.20")), publicPrefix(netip.MustParseAddr("2.176.200.1")))
	require.Equal(t, netip.MustParsePrefix("2a01:5ec0::/32"), publicPrefix(netip.MustParseAddr("2a01:5ec0:1234:5678::1")))
	require.Equal(t, netip.MustParsePrefix("5.6.0.0/16"), publicPrefix(netip.MustParseAddr("::ffff:5.6.7.8")))
}

func TestH_DetectNetwork(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer failing.Close()
	tracing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ip=93.115.4.9\nloc=DE\n"))
	}))
	defer tracing.Close()
	urls := TraceURLs
	defer func() { TraceURLs = urls }()

	TraceURLs = []string{failing.URL, tracing.URL}
	require.Equal(t, "unknown/DE/93.115.0.0/16", DetectNetwork(context.Background(), log.NewNOPFactory().Logger(), N.SystemDialer).Name, "the next trace answers")

	TraceURLs = []string{failing.URL}
	require.Equal(t, "unknown", DetectNetwork(context.Background(), log.NewNOPFactory().Logger(), N.SystemDialer).Name, "no trace: the interface type alone")
}
