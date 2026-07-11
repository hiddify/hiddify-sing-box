package ipinfo

// // CloudflareTraceProvider struct and implementation.
// type CloudflareTraceProvider struct {
// 	BaseProvider
// }

// // NewCloudflareTraceProvider initializes a new CloudflareTraceProvider.
// func NewCloudflareTraceProvider() *CloudflareTraceProvider {
// 	return &CloudflareTraceProvider{
// 		BaseProvider: BaseProvider{URL: "https://cloudflare.com/cdn-cgi/trace"},
// 	}
// }

// // GetIPInfo fetches and parses IP information from Cloudflare's trace endpoint.
// func (p *CloudflareTraceProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
// 	info := &IpInfo{}
// 	data, t, err := p.fetchData(ctx, dialer)
// 	if err != nil {
// 		return nil, t, err
// 	}

// 	// Parse the plain text response.
// 	for _, line := range strings.Split(string(data), "\n") {
// 		parts := strings.SplitN(line, "=", 2)
// 		if len(parts) != 2 {
// 			continue
// 		}
// 		key, value := parts[0], parts[1]
// 		switch key {
// 		case "ip":
// 			info.IP = value
// 		case "loc":
// 			info.CountryCode = value
// 		}
// 	}

// 	return info, t, nil
// }
