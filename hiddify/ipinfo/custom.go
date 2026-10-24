package ipinfo

import (
	"context"
	"fmt"

	N "github.com/sagernet/sing/common/network"
)

// CustomIpApiProvider hits a subscription-provided `ipinfo-url` that returns
// ipapi.co-compatible JSON (see parseIpApiJSON).
type CustomIpApiProvider struct {
	BaseProvider
}

// NewCustomIpApiProvider builds a provider for a panel/custom endpoint.
func NewCustomIpApiProvider(rawURL string) *CustomIpApiProvider {
	return &CustomIpApiProvider{
		BaseProvider: BaseProvider{URL: rawURL, UserAgent: "curl/8.7.1"},
	}
}

func (p *CustomIpApiProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}
	parseIpApiJSON(data, info)
	if info.IP == "" {
		return nil, t, fmt.Errorf("custom ipinfo-url returned no IP")
	}
	return info, t, nil
}
