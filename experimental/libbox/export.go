package libbox

import (
	"context"
	"math"
	"runtime/debug"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/service/oomkiller"
)

func FromContext(ctx context.Context, platformInterface PlatformInterface) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return baseContextWithParent(ctx, platformInterface)
}

func WrapPlatformInterface(platformInterface PlatformInterface) adapter.PlatformInterface {
	if platformInterface == nil {
		return nil
	}
	return &platformInterfaceWrapper{
		iif:       platformInterface,
		useProcFS: platformInterface.UseProcFS(),
	}
}

func SetMemoryLimit(enabled bool) {
	if !enabled {
		debug.SetMemoryLimit(math.MaxInt64)
		return
	}
	limit := sOOMMemoryLimit
	if limit == 0 && C.IsIos {
		limit = oomkiller.DefaultAppleNetworkExtensionMemoryLimit
	}
	if limit > 0 {
		debug.SetMemoryLimit(limit * 3 / 4)
	} else {
		debug.SetMemoryLimit(math.MaxInt64)
	}
}
