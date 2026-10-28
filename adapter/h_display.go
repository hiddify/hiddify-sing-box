package adapter

import C "github.com/sagernet/sing-box/constant"

// DisplayType is what the app shows for an outbound or an endpoint (an Endpoint is an Outbound):
// its own display type (the name of its type when it has none), then C.DisplayConnecting() while
// it is not ready. Outbounds and endpoints give only their name and their own state in
// DisplayType; the connecting mark is added here, for all of them.
func DisplayType(outbound Outbound) string {
	name := C.ProxyDisplayName(outbound.Type())
	if displayer, ok := outbound.(interface{ DisplayType() string }); ok {
		name = displayer.DisplayType()
	}
	if !outbound.IsReady() {
		name += C.DisplayConnecting()
	}
	return name
}
