package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"

	C "github.com/sagernet/sing-box/constant"

	"github.com/sagernet/sing-box/log"

	"time"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var providers = []Provider{
	NewFreeIpApiProvider(),
	NewIpApiCoProvider(),
	NewIpApiProvider(),
	NewIpInfoIoProvider(),
	NewIpSbProvider(),
	NewIpWhoIsProvider(),
	// NewCloudflareTraceProvider(),
	NewCountryIsProvider(),
	NewMyIPExpertProvider(),
	NewMyIPioProvider(),
	NewReallyFreeGeoIPProvider(),
}

var fallbackProviders = []Provider{
	NewMyIPProvider(),
	NewCountryIsProvider(),
	// NewCloudflareTraceProvider(),
}

// Provider interface for all IP providers.
type Provider interface {
	GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error)
	GetName() string
}

// IpInfo stores the IP information from the API response.
type IpInfo struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	ASN         int     `json:"asn,omitempty"`
	Org         string  `json:"org,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	PostalCode  string  `json:"postal_code,omitempty"`
}

func (ip *IpInfo) String() string {
	return fmt.Sprintf("IP: %s, Country: %s, Region: %s, City: %s, ASN: %d, Org: %s, Latitude: %.6f, Longitude: %.6f, Postal Code: %s",
		ip.IP, ip.CountryCode, ip.Region, ip.City, ip.ASN, ip.Org, ip.Latitude, ip.Longitude, ip.PostalCode)
}

// BaseProvider struct to handle common logic (HTTP request).
type BaseProvider struct {
	URL       string
	UserAgent string
}

func (p *BaseProvider) GetName() string {
	return p.URL
}

// fetchData retrieves the data from the provider's URL with a custom user agent and dialer.
func (p *BaseProvider) fetchData(ctx context.Context, detour N.Dialer) (map[string]interface{}, uint16, error) {
	link := p.URL
	linkURL, err := url.Parse(link)
	if err != nil {
		return nil, 65535, err
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		return nil, 65535, err
	}
	if p.UserAgent == "" {
		p.UserAgent = C.DefaultBrowserAgent
	}
	req.Header.Set("User-Agent", p.UserAgent)
	start := time.Now()
	var client http.Client
	if detour != nil {
		instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
		if err != nil {
			return nil, 65535, err
		}
		defer instance.Close()
		if earlyConn, isEarlyConn := common.Cast[N.EarlyConn](instance); isEarlyConn && earlyConn.NeedHandshake() {
			start = time.Now()
		}

		client = http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return instance, nil
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else {
		client = http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 65535, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 65535, fmt.Errorf("non-200 response from [%s]: %d", p.URL, resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 65535, fmt.Errorf("failed to read response from [%s]: %v", p.URL, err)
	}
	t := uint16(time.Since(start) / time.Millisecond)
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return nil, 65535, fmt.Errorf("failed to parse JSON from [%s]: %v", p.URL, err)
	}

	return jsonResponse, t, nil

}

// getCurrentIpInfo iterates over the providers to fetch and parse IP information.
func GetIpInfo(logger log.Logger, ctx context.Context, detour N.Dialer) (*IpInfo, uint16, error) {
	var lastErr error
	startIndex := rand.Intn(len(providers))
	for i := 0; i < len(providers); i++ {
		provider := providers[(i+startIndex)%len(providers)]
		testCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
		ipInfo, t, err := provider.GetIPInfo(testCtx, detour)
		cancel()
		if err != nil {
			logger.Warn("Failed try ", i, " to get IP info: ", provider.GetName(), " ", err)
			lastErr = err
			continue
		}
		return ipInfo, t, nil
	}
	startIndex = rand.Intn(len(fallbackProviders))
	for i := 0; i < len(fallbackProviders); i++ {
		provider := fallbackProviders[(i+startIndex)%len(fallbackProviders)]
		testCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
		ipInfo, t, err := provider.GetIPInfo(testCtx, detour)
		cancel()
		if err != nil {
			logger.Warn("Failed try ", i, " to get IP info: ", provider.GetName(), " ", err)
			continue
		}
		return ipInfo, t, nil
	}
	return nil, 65535, fmt.Errorf("unable to retrieve IP info: %v", lastErr)
}

// func init() {
// 	// Instantiate the providers.

// 	for _, provider := range providers {
// 		x, _, err := provider.GetIPInfo(context.Background(), nil)
// 		fmt.Printf("%s:   %++v\n%++v\n", provider, x, err)
// 	}
// 	// Get IP information.

// 	os.Exit(0)
// }
