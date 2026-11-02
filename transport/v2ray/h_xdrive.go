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
	xdriveServerConstructor ServerConstructor[option.V2RayXDriveOptions]
	xdriveClientConstructor ClientConstructor[option.V2RayXDriveOptions]
)

func RegisterXDriveConstructor(server ServerConstructor[option.V2RayXDriveOptions], client ClientConstructor[option.V2RayXDriveOptions]) {
	xdriveServerConstructor = server
	xdriveClientConstructor = client
}

func NewXDriveServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayXDriveOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	if xdriveServerConstructor == nil {
		return nil, C.ErrXDriveNotIncluded
	}
	return xdriveServerConstructor(ctx, logger, options, tlsConfig, handler)
}

func NewXDriveClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXDriveOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if xdriveClientConstructor == nil {
		return nil, C.ErrXDriveNotIncluded
	}
	return xdriveClientConstructor(ctx, dialer, serverAddr, options, tlsConfig)
}
