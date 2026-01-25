package ipinfo

import (
	"context"

	N "github.com/sagernet/sing/common/network"
)

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
