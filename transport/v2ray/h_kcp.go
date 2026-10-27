package v2ray

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	kcpServerConstructor ServerConstructor[option.V2RayKCPOptions]
	kcpClientConstructor ClientConstructor[option.V2RayKCPOptions]
)

func RegisterKCPConstructor(server ServerConstructor[option.V2RayKCPOptions], client ClientConstructor[option.V2RayKCPOptions]) {
	kcpServerConstructor = server
	kcpClientConstructor = client
}

func NewKCPServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayKCPOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	if kcpServerConstructor == nil {
		return nil, C.ErrKCPNotIncluded
	}
	return kcpServerConstructor(ctx, logger, options, tlsConfig, handler)
}

func NewKCPClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayKCPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if kcpClientConstructor == nil {
		return nil, C.ErrKCPNotIncluded
	}
	return kcpClientConstructor(ctx, dialer, serverAddr, options, tlsConfig)
}
