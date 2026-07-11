package ipinfo

import (
	"context"
	"strconv"
	"strings"

	N "github.com/sagernet/sing/common/network"
)

// IpApiCoProvider struct and implementation.
type IpApiCoProvider struct {
	BaseProvider
}

func NewIpApiCoProvider() *IpApiCoProvider {
	return &IpApiCoProvider{
		BaseProvider: BaseProvider{URL: "https://ipapi.co/json/", UserAgent: "curl/8.7.1"},
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
