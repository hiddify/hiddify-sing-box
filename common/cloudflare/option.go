package cloudflare

import (
	"context"
	"net"
	"net/http"
)

type CloudflareApiOption func(api *CloudeflareApi)

func WithDialContext(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) CloudflareApiOption {
	return func(api *CloudeflareApi) {
		api.client.Transport = &http.Transport{
			DialContext: dialContext,
		}
	}
}
