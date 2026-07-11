package ipinfo

import (
	"context"
	"strconv"
	"strings"

	N "github.com/sagernet/sing/common/network"
)

// IpInfoIoProvider struct and implementation.
type IpInfoIoProvider struct {
	BaseProvider
}

func NewIpInfoIoProvider() *IpInfoIoProvider {
	return &IpInfoIoProvider{
		BaseProvider: BaseProvider{URL: "http://ipinfo.io/json"},
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
