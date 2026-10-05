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

// H: newFinalMaskDialer applies the Xray-style final mask to every connection of dialer.
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
	conn, err := d.dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return d.masks.WrapConn(conn, network, destination)
}

func (d *finalMaskDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := d.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return d.masks.WrapPacketConn(conn)
}

type finalMaskParallelDialer struct {
	finalMaskDialer
	parallel ParallelInterfaceDialer
}

func (d *finalMaskParallelDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	conn, err := d.parallel.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	return d.masks.WrapConn(conn, network, destination)
}

func (d *finalMaskParallelDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error) {
	conn, err := d.parallel.ListenSerialInterfacePacket(ctx, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	return d.masks.WrapPacketConn(conn)
}
