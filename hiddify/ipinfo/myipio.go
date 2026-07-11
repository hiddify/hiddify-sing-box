package ipinfo

import (
	"context"

	N "github.com/sagernet/sing/common/network"
)

// MyIPioProvider struct and implementation.
type MyIPioProvider struct {
	BaseProvider
}

// NewMyIPioProvider initializes a new MyIPioProvider.
func NewMyIPioProvider() *MyIPioProvider {
	return &MyIPioProvider{
		BaseProvider: BaseProvider{URL: "https://api.my-ip.io/v2/ip.json"},
	}
}

// GetIPInfo fetches and parses IP information from api.my-ip.io.
func (p *MyIPioProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if success, ok := data["success"].(bool); ok && success {
		if ip, ok := data["ip"].(string); ok {
			info.IP = ip
		}
		if country, ok := data["country"].(map[string]interface{}); ok {
			if code, ok := country["code"].(string); ok {
				info.CountryCode = code
			}
		}
		if region, ok := data["region"].(string); ok {
			info.Region = region
		}
		if city, ok := data["city"].(string); ok {
			info.City = city
		}
		if location, ok := data["location"].(map[string]interface{}); ok {
			if lat, ok := location["lat"].(float64); ok {
				info.Latitude = lat
			}
			if lon, ok := location["lon"].(float64); ok {
				info.Longitude = lon
			}
		}
		if asn, ok := data["asn"].(map[string]interface{}); ok {
			if asnNumber, ok := asn["number"].(float64); ok {
				info.ASN = int(asnNumber)
			}
			if asnName, ok := asn["name"].(string); ok {
				info.Org = asnName
			}
		}
	}

	return info, t, nil
}
