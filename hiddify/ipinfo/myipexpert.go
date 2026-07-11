package ipinfo

import (
	"context"
	"strconv"
	"strings"

	"github.com/biter777/countries"
	N "github.com/sagernet/sing/common/network"
)

// MyIPExpertProvider struct and implementation.
type MyIPExpertProvider struct {
	BaseProvider
}

// NewMyIPExpertProvider initializes a new MyIPExpertProvider.
func NewMyIPExpertProvider() *MyIPExpertProvider {
	return &MyIPExpertProvider{
		BaseProvider: BaseProvider{URL: "https://myip.expert/api/"},
	}
}

// GetIPInfo fetches and parses IP information from myip.expert.
func (p *MyIPExpertProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["userIp"].(string); ok {
		info.IP = ip
	}
	if countryCode, ok := data["userCountryCode"].(string); ok {
		country := countries.ByName(countryCode)

		info.CountryCode = country.Alpha2()
	}
	if region, ok := data["userRegion"].(string); ok {
		info.Region = region
	}

	if city, ok := data["userCity"].(string); ok {
		info.City = city
	}
	if latitude, ok := data["userLatitude"].(float64); ok {
		info.Latitude = latitude
	}
	if longitude, ok := data["userLongitude"].(float64); ok {
		info.Longitude = longitude
	}
	// if isp, ok := data["userIsp"].(string); ok {
	// 	info.ISP = isp
	// }
	if org, ok := data["userOrg"].(string); ok {
		info.Org = org
	}
	if userHost, ok := data["userHost"].(string); ok && strings.HasPrefix(userHost, "AS") {
		if asn, err := strconv.ParseInt(strings.TrimPrefix(strings.Fields(userHost)[0], "AS"), 10, 64); err == nil {
			info.ASN = int(asn)
		}
	}

	return info, t, nil
}
