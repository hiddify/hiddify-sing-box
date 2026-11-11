package box

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// H: lazy outbounds. An outbound with "lazy": true is created as a stand-in that keeps its options
// and creates the real outbound when it is first used (adapter/outbound/h_lazy.go).

// lazyOutbound is the type and options to create for an outbound: its own, or those of the
// stand-in when it is lazy.
func lazyOutbound(ctx context.Context, outbound option.Outbound) (string, any) {
	if !outbound.Lazy || !canBeLazy(outbound.Type) {
		return outbound.Type, outbound.Options
	}
	var dependencies []string
	if content, err := json.MarshalContext(ctx, &outbound); err == nil {
		dependencies = outboundDependencies(content)
	}
	return C.TypeHLazy, &option.HLazyOptions{Type: outbound.Type, Options: outbound.Options, Dependencies: dependencies}
}

// canBeLazy leaves out what is not a proxy with connections of its own: the groups, which the
// box and the monitoring know by their kind, and the outbounds that cost nothing to keep.
func canBeLazy(outboundType string) bool {
	switch outboundType {
	case C.TypeSelector, C.TypeURLTest, C.TypeBalancer, C.TypeFallback, C.TypeBond,
		C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeBridge, C.TypeHInvalidConfig, C.TypeHLazy, C.TypeCustom:
		return false
	}
	return true
}
