package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// providers that currently return usable JSON without challenge pages / dead hosts.
var providers = []Provider{
	// first because WARP is Cloudflare: its own trace endpoint does not rate-limit the way the
	// JSON providers do, and on a busy network the others answer 429 or time out and the core is
	// left with no measurement at all.
	NewCloudflareTraceProvider(),
	NewIpApiCoProvider(),
	NewIpApiProvider(),
	NewIpInfoIoProvider(),
	NewIpSbProvider(),
	NewIpWhoIsProvider(),
	NewCountryIsProvider(),
	NewMyIPioProvider(),
}

var fallbackProviders = []Provider{
	NewCloudflareTraceProvider(),
	NewCountryIsProvider(),
	NewMyIPioProvider(),
}

func GetAllIPCheckerDomainsDomains() []string {
	var domains []string
	for _, provider := range providers {
		d, err := url.Parse(provider.GetName())
		if err == nil {
			if net.ParseIP(d.Hostname()) == nil {
				domains = append(domains, d.Hostname())
			}

		}
	}
	return domains
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

// fetchData retrieves the JSON a provider answers with, from its URL, with a custom user agent
// and dialer.
func (p *BaseProvider) fetchData(ctx context.Context, detour N.Dialer) (map[string]interface{}, uint16, error) {
	body, t, err := p.fetchBody(ctx, detour)
	if err != nil {
		return nil, t, err
	}
	var jsonResponse map[string]interface{}
	if err = json.Unmarshal(body, &jsonResponse); err != nil {
		return nil, 65535, fmt.Errorf("failed to parse JSON from [%s]: %v", p.URL, err)
	}
	return jsonResponse, t, nil
}

// fetchBody is fetchData without the JSON step, for the providers that answer plain text.
func (p *BaseProvider) fetchBody(ctx context.Context, detour N.Dialer) ([]byte, uint16, error) {
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 65535, fmt.Errorf("failed to read response from [%s]: %v", p.URL, err)
	}
	t := uint16(time.Since(start) / time.Millisecond)
	return body, t, nil
}

// GetIpInfo iterates over the providers to fetch and parse IP information.
// When customURL is non-empty (subscription `ipinfo-url`), that endpoint is
// tried first with the custom ipapi-compatible parser.
func GetIpInfo(logger log.Logger, ctx context.Context, detour N.Dialer, customURL ...string) (*IpInfo, uint16, error) {
	var lastErr error
	if len(customURL) > 0 {
		if u := strings.TrimSpace(customURL[0]); u != "" {
			p := NewCustomIpApiProvider(u)
			testCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
			ipInfo, t, err := p.GetIPInfo(testCtx, detour)
			cancel()
			if err == nil {
				return ipInfo, t, nil
			}
			logger.Warn("custom ipinfo-url failed, falling back: ", p.GetName(), " ", err)
			lastErr = err
		}
	}
	startIndex := rand.Intn(len(providers))
	for i := 0; i < len(providers); i++ {
		select {
		case <-ctx.Done():
			return nil, 65535, ctx.Err()
		default:
		}
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
		select {
		case <-ctx.Done():
			return nil, 65535, ctx.Err()
		default:
		}
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
