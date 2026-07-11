package ipinfo

import (
	"context"

	N "github.com/sagernet/sing/common/network"
)

// CountryIsProvider struct and implementation.
type CountryIsProvider struct {
	BaseProvider
}

// NewCountryIsProvider initializes a new CountryIsProvider.
func NewCountryIsProvider() *CountryIsProvider {
	return &CountryIsProvider{
		BaseProvider: BaseProvider{URL: "https://api.country.is/"},
	}
}

// GetIPInfo fetches and parses IP information from country.is.
func (p *CountryIsProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["ip"].(string); ok {
		info.IP = ip
	}
	if country, ok := data["country"].(string); ok {
		info.CountryCode = country
	}

	return info, t, nil
}
