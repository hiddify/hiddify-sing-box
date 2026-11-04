package adapter

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
)

// DisplayType is what the app shows for an outbound or an endpoint (an Endpoint is an Outbound):
// its own display type (the name of its type when it has none), which says only what its Status
// cannot, such as how many resolvers it uses or the endpoint a scanner found. The app shows the
// status itself. A failed one adds why it failed (StatusError), unless its own display type
// already says it.
func DisplayType(outbound Outbound) string {
	name := C.ProxyDisplayName(outbound.Type())
	if displayer, ok := outbound.(interface{ DisplayType() string }); ok {
		name = displayer.DisplayType()
	}
	if outbound.Status() == StatusFailed {
		if err := StatusError(outbound); err != nil && !strings.Contains(name, err.Error()) {
			name += ": " + err.Error()
		}
	}
	return name
}
