package ipinfo

import (
	"context"
	"strconv"
	"strings"

	N "github.com/sagernet/sing/common/network"
)

type IpApiProvider struct {
	BaseProvider
}

// NewIpApiProvider initializes a new IpApiProvider.
func NewIpApiProvider() *IpApiProvider {
	return &IpApiProvider{
		BaseProvider: BaseProvider{URL: "http://ip-api.com/json/"},
	}
}

// GetIPInfo fetches and parses IP information from ip-api.com.
func (p *IpApiProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if status, ok := data["status"].(string); ok && status == "success" {
		if ip, ok := data["query"].(string); ok {
			info.IP = ip
		}
		if countryCode, ok := data["countryCode"].(string); ok {
			info.CountryCode = countryCode
		}
		if region, ok := data["region"].(string); ok {
			info.Region = region
		}
		if city, ok := data["city"].(string); ok {
			info.City = city
		}
		if zip, ok := data["zip"].(string); ok {
			info.PostalCode = zip
		}
		if latitude, ok := data["lat"].(float64); ok {
			info.Latitude = latitude
		}
		if longitude, ok := data["lon"].(float64); ok {
			info.Longitude = longitude
		}
		if org, ok := data["org"].(string); ok {
			info.Org = org
		}
		if asnStr, ok := data["as"].(string); ok && strings.HasPrefix(asnStr, "AS") {
			if asn, err := strconv.ParseInt(strings.TrimPrefix(strings.Fields(asnStr)[0], "AS"), 10, 64); err == nil {
				info.ASN = int(asn)
			}
		}
	}

	return info, t, nil
}
