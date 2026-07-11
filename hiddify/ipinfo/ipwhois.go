package ipinfo

import (
	"context"

	N "github.com/sagernet/sing/common/network"
)

// IpWhoIsProvider struct and implementation.
type IpWhoIsProvider struct {
	BaseProvider
}

func NewIpWhoIsProvider() *IpWhoIsProvider {
	return &IpWhoIsProvider{
		BaseProvider: BaseProvider{URL: "http://ipwho.is/"},
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
