package ipinfo

import (
	"context"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// CloudflareTraceProvider asks Cloudflare's own trace endpoint, which answers plain text:
//
//	fl=...
//	ip=104.28.229.14
//	loc=DE
//
// It is a fallback provider: it does not rate-limit the way the JSON providers do, which on a
// busy network answer 429 or time out and leave the core with no measurement to report, but it
// answers only the address and the country, where the JSON providers also give the network.
type CloudflareTraceProvider struct {
	BaseProvider
}

func NewCloudflareTraceProvider() *CloudflareTraceProvider {
	return &CloudflareTraceProvider{
		BaseProvider: BaseProvider{URL: "https://cloudflare.com/cdn-cgi/trace"},
	}
}

// GetIPInfo parses the key=value lines: ip is the address the request came from, loc the country
// Cloudflare placed it in.
func (p *CloudflareTraceProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	body, t, err := p.fetchBody(ctx, dialer)
	if err != nil {
		return nil, t, err
	}
	info := &IpInfo{}
	for _, line := range strings.Split(string(body), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "ip":
			info.IP = value
		case "loc":
			info.CountryCode = value
		}
	}
	// no ip means a page or a redirect answered instead, which is not a measurement
	if info.IP == "" {
		return nil, t, E.New("cloudflare trace: no ip in the answer")
	}
	return info, t, nil
}
