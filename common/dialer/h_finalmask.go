package dialer

import (
	"context"
	"net"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/finalmask"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// H: newFinalMaskDialer opens every connection of dialer through the Xray-style final mask.
// It keeps ParallelInterfaceDialer (asserted by the direct outbound) and deliberately has no
// Upstream: common.Cast must not reach the inner dialer and open sockets without the masks.
func newFinalMaskDialer(dialer N.Dialer, masks *finalmask.Masks) N.Dialer {
	if masks == nil {
		return dialer
	}
	maskDialer := finalMaskDialer{dialer: dialer, masks: masks}
	if parallelDialer, isParallel := dialer.(ParallelInterfaceDialer); isParallel {
		return &finalMaskParallelDialer{finalMaskDialer: maskDialer, parallel: parallelDialer}
	}
	return &maskDialer
}

type finalMaskDialer struct {
	dialer N.Dialer
	masks  *finalmask.Masks
}

func (d *finalMaskDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.masks.DialContext(ctx, network, destination, d.dialer.DialContext, d.dialer.ListenPacket)
}

func (d *finalMaskDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.masks.ListenPacket(ctx, destination, d.dialer.DialContext, d.dialer.ListenPacket)
}

type finalMaskParallelDialer struct {
	finalMaskDialer
	parallel ParallelInterfaceDialer
}

// DialParallelInterface and ListenSerialInterfacePacket open every socket under the masks, those
// a mask opens itself included, on the interfaces of the strategy.
func (d *finalMaskParallelDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	dial := func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return d.parallel.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	listen := func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
		return d.parallel.ListenSerialInterfacePacket(ctx, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	return d.masks.DialContext(ctx, network, destination, dial, listen)
}

func (d *finalMaskParallelDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error) {
	dial := func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return d.parallel.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	listen := func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
		return d.parallel.ListenSerialInterfacePacket(ctx, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	return d.masks.ListenPacket(ctx, destination, dial, listen)
}
