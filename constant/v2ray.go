package constant

const (
	V2RayTransportTypeHTTP        = "http"
	V2RayTransportTypeWebsocket   = "ws"
	V2RayTransportTypeQUIC        = "quic"
	V2RayTransportTypeGRPC        = "grpc"
	V2RayTransportTypeHTTPUpgrade = "httpupgrade"
	V2RayTransportTypeXHTTP       = "xhttp"
	V2RayTransportTypeRaw         = "raw"  //H
	V2RayTransportTypeKCP         = "mkcp" //H: Xray's network name; "kcp" is accepted too
	V2RayTransportTypeKCPAlias    = "kcp"  //H
)
