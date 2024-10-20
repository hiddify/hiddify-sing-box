package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"time"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var providers = []Provider{
	NewIpWhoIsProvider(),
	NewIpSbProvider(),
	NewIpApiCoProvider(),
	NewIpInfoIoProvider(),
}

// Provider interface for all IP providers.
type Provider interface {
	GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error)
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

// BaseProvider struct to handle common logic (HTTP request).
type BaseProvider struct {
	URL string
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

	start := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return nil, 65535, err
	}
	defer instance.Close()
	if earlyConn, isEarlyConn := common.Cast[N.EarlyConn](instance); isEarlyConn && earlyConn.NeedHandshake() {
		start = time.Now()
	}
	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		return nil, 65535, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0")

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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

// IpWhoIsProvider struct and implementation.
type IpWhoIsProvider struct {
	BaseProvider
}

func NewIpWhoIsProvider() *IpWhoIsProvider {
	return &IpWhoIsProvider{
		BaseProvider: BaseProvider{URL: "https://ipwho.is/"},
	}
}

func (p *IpWhoIsProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["ip"].(string); ok {
		info.IP = ip
	}
	if countryCode, ok := data["country_code"].(string); ok {
		info.CountryCode = countryCode
	}
	if region, ok := data["region"].(string); ok {
		info.Region = region
	}
	if city, ok := data["city"].(string); ok {
		info.City = city
	}

	if connection, ok := data["connection"].(map[string]interface{}); ok {
		if asn, ok := connection["asn"].(float64); ok {
			info.ASN = int(asn)
		}
		if org, ok := connection["org"].(string); ok {
			info.Org = org
		}
	}

	if latitude, ok := data["latitude"].(float64); ok {
		info.Latitude = latitude
	}
	if longitude, ok := data["longitude"].(float64); ok {
		info.Longitude = longitude
	}
	if postalCode, ok := data["postal"].(string); ok {
		info.PostalCode = postalCode
	}
	return info, t, nil
}

// IpSbProvider struct and implementation.
type IpSbProvider struct {
	BaseProvider
}

func NewIpSbProvider() *IpSbProvider {
	return &IpSbProvider{
		BaseProvider: BaseProvider{URL: "https://api.ip.sb/geoip/"},
	}
}

func (p *IpSbProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["ip"].(string); ok {
		info.IP = ip
	}
	if countryCode, ok := data["country_code"].(string); ok {
		info.CountryCode = countryCode
	}
	if region, ok := data["region"].(string); ok {
		info.Region = region
	}
	if city, ok := data["city"].(string); ok {
		info.City = city
	}
	if asn, ok := data["asn"].(float64); ok {
		info.ASN = int(asn)
	}
	if org, ok := data["asn_organization"].(string); ok {
		info.Org = org
	}
	if latitude, ok := data["latitude"].(float64); ok {
		info.Latitude = latitude
	}
	if longitude, ok := data["longitude"].(float64); ok {
		info.Longitude = longitude
	}
	if postalCode, ok := data["postal_code"].(string); ok {
		info.PostalCode = postalCode
	}
	return info, t, nil
}

// IpApiCoProvider struct and implementation.
type IpApiCoProvider struct {
	BaseProvider
}

func NewIpApiCoProvider() *IpApiCoProvider {
	return &IpApiCoProvider{
		BaseProvider: BaseProvider{URL: "https://ipapi.co/json/"},
	}
}

func (p *IpApiCoProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["ip"].(string); ok {
		info.IP = ip
	}
	if countryCode, ok := data["country_code"].(string); ok {
		info.CountryCode = countryCode
	}
	if region, ok := data["region"].(string); ok {
		info.Region = region
	}
	if city, ok := data["city"].(string); ok {
		info.City = city
	}
	if asnstr, ok := data["asn"].(string); ok {
		if strings.HasPrefix(asnstr, "AS") {
			if asn, ok := strconv.ParseInt(strings.TrimPrefix(asnstr, "AS"), 10, 64); ok == nil {
				info.ASN = int(asn)
			}
		}
	}
	if org, ok := data["org"].(string); ok {
		info.Org = org
	}
	if latitude, ok := data["latitude"].(float64); ok {
		info.Latitude = latitude
	}
	if longitude, ok := data["longitude"].(float64); ok {
		info.Longitude = longitude
	}

	if postalCode, ok := data["postal"].(string); ok {
		info.PostalCode = postalCode
	}
	return info, t, nil
}

// IpInfoIoProvider struct and implementation.
type IpInfoIoProvider struct {
	BaseProvider
}

func NewIpInfoIoProvider() *IpInfoIoProvider {
	return &IpInfoIoProvider{
		BaseProvider: BaseProvider{URL: "https://ipinfo.io/json/"},
	}
}

func (p *IpInfoIoProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["ip"].(string); ok {
		info.IP = ip
	}
	if city, ok := data["city"].(string); ok {
		info.City = city
	}
	if region, ok := data["region"].(string); ok {
		info.Region = region
	}
	if country, ok := data["country"].(string); ok {
		info.CountryCode = country
	}
	if loc, ok := data["loc"].(string); ok {
		// Split loc into latitude and longitude
		coords := strings.Split(loc, ",")
		if len(coords) == 2 {
			if latitude, err := strconv.ParseFloat(coords[0], 64); err == nil {
				info.Latitude = latitude
			}
			if longitude, err := strconv.ParseFloat(coords[1], 64); err == nil {
				info.Longitude = longitude
			}
		}
	}
	if org, ok := data["org"].(string); ok {
		// Split the org string to extract ASN and Organization
		orgParts := strings.SplitN(org, " ", 2) // Split into 2 parts
		if len(orgParts) > 0 {
			if strings.HasPrefix(orgParts[0], "AS") {
				if asn, ok := strconv.ParseInt(strings.TrimPrefix(orgParts[0], "AS"), 10, 64); ok == nil {
					info.ASN = int(asn)
				}
			}
		}
		info.Org = orgParts[len(orgParts)-1]
	}
	if postal, ok := data["postal"].(string); ok {
		info.PostalCode = postal
	}

	return info, t, nil
}

// getCurrentIpInfo iterates over the providers to fetch and parse IP information.
func GetIpInfo(ctx context.Context, detour N.Dialer) (*IpInfo, uint16, error) {
	var lastErr error
	startIndex := rand.Intn(len(providers))
	for i := 0; i < len(providers); i++ {
		provider := providers[(i+startIndex)%len(providers)]

		ipInfo, t, err := provider.GetIPInfo(ctx, detour)
		if err != nil {
			log.Printf("Failed to get IP info: %v", err)
			lastErr = err
			continue
		}
		return ipInfo, t, nil
	}

	return nil, 65535, fmt.Errorf("unable to retrieve IP info: %v", lastErr)
}

// func init() {
// 	// Instantiate the providers.
//

// 	for _, provider := range providers {
// 		x, _ := provider.GetIPInfo()
// 		fmt.Printf("%s:   %++v\n\n", provider, x)
// 	}
// 	// Get IP information.
// 	ipInfo, err := getCurrentIpInfo(providers)
// 	if err != nil {
// 		log.Fatalf("Error fetching IP info: %v", err)
// 	}

// 	fmt.Printf("IP Info: %+v\n", *ipInfo)
// 	os.Exit(0)
// }
