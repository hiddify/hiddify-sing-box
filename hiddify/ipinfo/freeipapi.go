package ipinfo

import (
	"context"

	N "github.com/sagernet/sing/common/network"
)

// FreeIpApiProvider struct and implementation.
type FreeIpApiProvider struct {
	BaseProvider
}

// NewFreeIpApiProvider initializes a new FreeIpApiProvider.
func NewFreeIpApiProvider() *FreeIpApiProvider {
	return &FreeIpApiProvider{
		BaseProvider: BaseProvider{URL: "https://free.freeipapi.com/api/json/"},
	}
}

// GetIPInfo fetches and parses IP information from freeipapi.com.
func (p *FreeIpApiProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["ipAddress"].(string); ok {
		info.IP = ip
	}
	if countryCode, ok := data["countryCode"].(string); ok {
		info.CountryCode = countryCode
	}
	if region, ok := data["regionName"].(string); ok {
		info.Region = region
	}
	if city, ok := data["cityName"].(string); ok {
		info.City = city
	}
	if latitude, ok := data["latitude"].(float64); ok {
		info.Latitude = latitude
	}
	if longitude, ok := data["longitude"].(float64); ok {
		info.Longitude = longitude
	}
	if postalCode, ok := data["zipCode"].(string); ok {
		info.PostalCode = postalCode
	}

	return info, t, nil
}
