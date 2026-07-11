package ipinfo

import (
	"context"

	N "github.com/sagernet/sing/common/network"
)

// MyIPProvider struct and implementation.
type MyIPProvider struct {
	BaseProvider
}

// NewMyIPProvider initializes a new MyIPProvider.
func NewMyIPProvider() *MyIPProvider {
	return &MyIPProvider{
		BaseProvider: BaseProvider{URL: "https://api.myip.com"},
	}
}

// GetIPInfo fetches and parses IP information from api.myip.com.
func (p *MyIPProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["ip"].(string); ok {
		info.IP = ip
	}
	if countryCode, ok := data["cc"].(string); ok {
		info.CountryCode = countryCode
	}

	return info, t, nil
}
