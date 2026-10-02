package ipinfo

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type loopbackDialer struct {
	addr  string
	dials atomic.Int32
	last  atomic.Value
}

func (d *loopbackDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	d.last.Store(destination.String())
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.addr)
}

func (d *loopbackDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func jsonServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Value) {
	var ua atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.Header.Get("User-Agent"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &ua
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

type urlProvider interface {
	Provider
	base() *BaseProvider
}

func (p *FreeIpApiProvider) base() *BaseProvider       { return &p.BaseProvider }
func (p *IpApiCoProvider) base() *BaseProvider         { return &p.BaseProvider }
func (p *IpApiProvider) base() *BaseProvider           { return &p.BaseProvider }
func (p *IpInfoIoProvider) base() *BaseProvider        { return &p.BaseProvider }
func (p *IpSbProvider) base() *BaseProvider            { return &p.BaseProvider }
func (p *IpWhoIsProvider) base() *BaseProvider         { return &p.BaseProvider }
func (p *CountryIsProvider) base() *BaseProvider       { return &p.BaseProvider }
func (p *MyIPProvider) base() *BaseProvider            { return &p.BaseProvider }
func (p *MyIPExpertProvider) base() *BaseProvider      { return &p.BaseProvider }
func (p *MyIPioProvider) base() *BaseProvider          { return &p.BaseProvider }
func (p *ReallyFreeGeoIPProvider) base() *BaseProvider { return &p.BaseProvider }

func TestH_IpInfoProviderParsing(t *testing.T) {
	cases := []struct {
		name     string
		provider urlProvider
		body     string
		want     IpInfo
	}{
		{
			name:     "freeipapi",
			provider: NewFreeIpApiProvider(),
			body:     `{"ipAddress":"1.2.3.4","countryCode":"DE","regionName":"Hesse","cityName":"Frankfurt","latitude":50.1,"longitude":8.6,"zipCode":"60311"}`,
			want:     IpInfo{IP: "1.2.3.4", CountryCode: "DE", Region: "Hesse", City: "Frankfurt", Latitude: 50.1, Longitude: 8.6, PostalCode: "60311"},
		},
		{
			name:     "ipapi.co",
			provider: NewIpApiCoProvider(),
			body:     `{"ip":"1.2.3.4","country_code":"US","region":"California","city":"LA","asn":"AS15169","org":"Google LLC","latitude":34.05,"longitude":-118.24,"postal":"90001"}`,
			want:     IpInfo{IP: "1.2.3.4", CountryCode: "US", Region: "California", City: "LA", ASN: 15169, Org: "Google LLC", Latitude: 34.05, Longitude: -118.24, PostalCode: "90001"},
		},
		{
			name:     "ipapi.co bad asn",
			provider: NewIpApiCoProvider(),
			body:     `{"ip":"1.2.3.4","asn":"ASxyz"}`,
			want:     IpInfo{IP: "1.2.3.4"},
		},
		{
			name:     "ip-api.com",
			provider: NewIpApiProvider(),
			body:     `{"status":"success","query":"5.6.7.8","countryCode":"NL","region":"NH","city":"Amsterdam","zip":"1012","lat":52.37,"lon":4.89,"org":"Example BV","as":"AS1136 KPN B.V."}`,
			want:     IpInfo{IP: "5.6.7.8", CountryCode: "NL", Region: "NH", City: "Amsterdam", PostalCode: "1012", Latitude: 52.37, Longitude: 4.89, Org: "Example BV", ASN: 1136},
		},
		{
			name:     "ip-api.com failure status",
			provider: NewIpApiProvider(),
			body:     `{"status":"fail","query":"5.6.7.8","countryCode":"NL"}`,
			want:     IpInfo{},
		},
		{
			name:     "ipinfo.io",
			provider: NewIpInfoIoProvider(),
			body:     `{"ip":"8.8.8.8","city":"Mountain View","region":"California","country":"US","loc":"37.4056,-122.0775","org":"AS15169 Google LLC","postal":"94043"}`,
			want:     IpInfo{IP: "8.8.8.8", City: "Mountain View", Region: "California", CountryCode: "US", Latitude: 37.4056, Longitude: -122.0775, ASN: 15169, Org: "Google LLC", PostalCode: "94043"},
		},
		{
			name:     "ipinfo.io org without asn and bad loc",
			provider: NewIpInfoIoProvider(),
			body:     `{"ip":"8.8.8.8","loc":"garbage","org":"Hosting"}`,
			want:     IpInfo{IP: "8.8.8.8", Org: "Hosting"},
		},
		{
			name:     "ip.sb",
			provider: NewIpSbProvider(),
			body:     `{"ip":"9.9.9.9","country_code":"CH","region":"Zurich","city":"Zurich","asn":19281,"asn_organization":"Quad9","latitude":47.37,"longitude":8.54,"postal_code":"8000"}`,
			want:     IpInfo{IP: "9.9.9.9", CountryCode: "CH", Region: "Zurich", City: "Zurich", ASN: 19281, Org: "Quad9", Latitude: 47.37, Longitude: 8.54, PostalCode: "8000"},
		},
		{
			name:     "ipwho.is",
			provider: NewIpWhoIsProvider(),
			body:     `{"ip":"1.1.1.1","country_code":"AU","region":"QLD","city":"Brisbane","connection":{"asn":13335,"org":"Cloudflare"},"latitude":-27.4,"longitude":153.0,"postal":"4000"}`,
			want:     IpInfo{IP: "1.1.1.1", CountryCode: "AU", Region: "QLD", City: "Brisbane", ASN: 13335, Org: "Cloudflare", Latitude: -27.4, Longitude: 153.0, PostalCode: "4000"},
		},
		{
			name:     "country.is",
			provider: NewCountryIsProvider(),
			body:     `{"ip":"2.2.2.2","country":"FR"}`,
			want:     IpInfo{IP: "2.2.2.2", CountryCode: "FR"},
		},
		{
			name:     "myip.com",
			provider: NewMyIPProvider(),
			body:     `{"ip":"3.3.3.3","country":"Japan","cc":"JP"}`,
			want:     IpInfo{IP: "3.3.3.3", CountryCode: "JP"},
		},
		{
			name:     "myip.expert",
			provider: NewMyIPExpertProvider(),
			body:     `{"userIp":"4.4.4.4","userCountryCode":"Germany","userRegion":"Berlin","userCity":"Berlin","userLatitude":52.5,"userLongitude":13.4,"userOrg":"Example GmbH","userHost":"AS3320 Deutsche Telekom"}`,
			want:     IpInfo{IP: "4.4.4.4", CountryCode: "DE", Region: "Berlin", City: "Berlin", Latitude: 52.5, Longitude: 13.4, Org: "Example GmbH", ASN: 3320},
		},
		{
			name:     "my-ip.io",
			provider: NewMyIPioProvider(),
			body:     `{"success":true,"ip":"6.6.6.6","country":{"code":"GB","name":"UK"},"region":"England","city":"London","location":{"lat":51.5,"lon":-0.12},"asn":{"number":2856,"name":"BT"}}`,
			want:     IpInfo{IP: "6.6.6.6", CountryCode: "GB", Region: "England", City: "London", Latitude: 51.5, Longitude: -0.12, ASN: 2856, Org: "BT"},
		},
		{
			name:     "my-ip.io unsuccessful",
			provider: NewMyIPioProvider(),
			body:     `{"success":false,"ip":"6.6.6.6"}`,
			want:     IpInfo{},
		},
		{
			name:     "reallyfreegeoip",
			provider: NewReallyFreeGeoIPProvider(),
			body:     `{"ip":"7.7.7.7","country_code":"CA","region_name":"Ontario","city":"Toronto","zip_code":"M5H","latitude":43.65,"longitude":-79.38}`,
			want:     IpInfo{IP: "7.7.7.7", CountryCode: "CA", Region: "Ontario", City: "Toronto", PostalCode: "M5H", Latitude: 43.65, Longitude: -79.38},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := jsonServer(t, http.StatusOK, tc.body)
			tc.provider.base().URL = server.URL + "/json"
			info, delay, err := tc.provider.GetIPInfo(testCtx(t), nil)
			require.NoError(t, err)
			require.Less(t, delay, uint16(65535))
			require.Equal(t, tc.want, *info)
		})
	}
}

func TestH_IpInfoFetchThroughDialer(t *testing.T) {
	server, ua := jsonServer(t, http.StatusOK, `{"ip":"2.2.2.2","country":"FR"}`)
	dialer := &loopbackDialer{addr: server.Listener.Addr().String()}
	p := NewCountryIsProvider()
	p.URL = "http://country.example/"
	info, _, err := p.GetIPInfo(testCtx(t), dialer)
	require.NoError(t, err)
	require.Equal(t, "FR", info.CountryCode)
	require.Equal(t, int32(1), dialer.dials.Load())
	require.Equal(t, "country.example:80", dialer.last.Load())
	require.NotEmpty(t, ua.Load(), "a default user agent is sent")

	co := NewIpApiCoProvider()
	co.URL = "http://ipapi.example:8080/json/"
	_, _, err = co.GetIPInfo(testCtx(t), dialer)
	require.NoError(t, err)
	require.Equal(t, "ipapi.example:8080", dialer.last.Load())
	require.Equal(t, "curl/8.7.1", ua.Load())
}

func TestH_IpInfoFetchErrors(t *testing.T) {
	server, _ := jsonServer(t, http.StatusTooManyRequests, `{}`)
	p := NewIpSbProvider()
	p.URL = server.URL
	_, delay, err := p.GetIPInfo(testCtx(t), nil)
	require.Error(t, err)
	require.Equal(t, uint16(65535), delay)

	server, _ = jsonServer(t, http.StatusOK, `not json`)
	p.URL = server.URL
	_, _, err = p.GetIPInfo(testCtx(t), nil)
	require.Error(t, err)

	p.URL = "http://[::1"
	_, _, err = p.GetIPInfo(testCtx(t), nil)
	require.Error(t, err)

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.invalid/", http.StatusFound)
	}))
	defer redirect.Close()
	p.URL = redirect.URL
	_, _, err = p.GetIPInfo(testCtx(t), nil)
	require.Error(t, err, "redirects are not followed")
}

func TestH_IpInfoDomains(t *testing.T) {
	domains := GetAllIPCheckerDomainsDomains()
	require.Len(t, domains, len(providers))
	require.Contains(t, domains, "ipapi.co")
	require.Contains(t, domains, "ipinfo.io")
	for _, d := range domains {
		require.Nil(t, net.ParseIP(d))
	}
}

func TestH_IpInfoGetIpInfoFallback(t *testing.T) {
	oldProviders, oldFallback := providers, fallbackProviders
	t.Cleanup(func() { providers, fallbackProviders = oldProviders, oldFallback })
	logger := log.NewNOPFactory().NewLogger("ipinfo")

	failing, _ := jsonServer(t, http.StatusInternalServerError, `{}`)
	ok, _ := jsonServer(t, http.StatusOK, `{"ip":"3.3.3.3","cc":"JP"}`)
	newFailing := func() Provider {
		p := NewIpSbProvider()
		p.URL = failing.URL
		return p
	}
	good := NewMyIPProvider()
	good.URL = ok.URL

	providers = []Provider{newFailing(), newFailing()}
	fallbackProviders = []Provider{newFailing(), good}
	info, _, err := GetIpInfo(logger, testCtx(t), nil)
	require.NoError(t, err)
	require.Equal(t, "JP", info.CountryCode)

	providers = []Provider{good, newFailing()}
	fallbackProviders = []Provider{newFailing()}
	for range 5 {
		info, _, err = GetIpInfo(logger, testCtx(t), nil)
		require.NoError(t, err)
		require.Equal(t, "3.3.3.3", info.IP)
	}

	providers = []Provider{newFailing()}
	fallbackProviders = []Provider{newFailing()}
	_, delay, err := GetIpInfo(logger, testCtx(t), nil)
	require.Error(t, err)
	require.Equal(t, uint16(65535), delay)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = GetIpInfo(logger, ctx, nil)
	require.ErrorIs(t, err, context.Canceled)
}

func TestH_IpInfoString(t *testing.T) {
	s := (&IpInfo{IP: "1.1.1.1", CountryCode: "AU", ASN: 13335}).String()
	require.Contains(t, s, "IP: 1.1.1.1")
	require.Contains(t, s, "Country: AU")
	require.Contains(t, s, "ASN: 13335")
}
