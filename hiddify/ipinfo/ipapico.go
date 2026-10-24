package ipinfo

import (
	"context"

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
	parseIpApiJSON(data, info)
	return info, t, nil
}
