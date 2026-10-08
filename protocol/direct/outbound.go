package direct

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/proxyproto"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DirectOutboundOptions](registry, C.TypeDirect, NewOutbound)
}

var (
	_ N.ParallelDialer                = (*Outbound)(nil)
	_ dialer.ParallelNetworkDialer    = (*Outbound)(nil)
	_ dialer.DirectDialer             = (*Outbound)(nil)
	_ adapter.FlowOutbound            = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	ctx            context.Context
	logger         logger.ContextLogger
	network        adapter.NetworkManager
	dialer         dialer.ParallelInterfaceDialer
	domainStrategy C.DomainStrategy
	fallbackDelay  time.Duration
	isEmpty        bool
	myAddresses    common.TypedValue[[]netip.Prefix]
	icmpPort       *ping.Port
	proxyProtocol  uint8 //H
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.Detour != "" {
		return nil, E.New("`detour` is not supported in direct context")
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: true,
		DirectOutbound: true,
	})
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeDirect, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		network: service.FromContext[adapter.NetworkManager](ctx),
		//nolint:staticcheck
		domainStrategy: C.DomainStrategy(options.DomainStrategy),
		fallbackDelay:  time.Duration(options.FallbackDelay),
		dialer:         outboundDialer.(dialer.ParallelInterfaceDialer),
		isEmpty: reflect.DeepEqual(options.DialerOptions, option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{UDPFragmentDefault: true},
		}),
	}
	// H: restored; send a PROXY protocol header (version 1 or 2) on TCP connections
	switch options.ProxyProtocol {
	case 0, 1, 2:
		outbound.proxyProtocol = options.ProxyProtocol
	default:
		return nil, E.New("invalid proxy protocol version: ", options.ProxyProtocol)
	}
	if defaultDialer, isDefaultDialer := common.Cast[*dialer.DefaultDialer](outbound.dialer); isDefaultDialer {
		outbound.icmpPort = ping.NewPort(ctx, logger, func(destination netip.Addr) control.Func {
			return defaultDialer.DialerForICMPDestination(destination).Control
		}, 0)
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStatePostStart, adapter.StartStateStarted:
		if len(h.myAddresses.Load()) == 0 {
			h.fetchMyAddresses()
		}
	}
	return nil
}

func (h *Outbound) fetchMyAddresses() {
	interfaceMonitor := h.network.InterfaceMonitor()
	if interfaceMonitor == nil {
		return
	}
	myInterfaceNames := interfaceMonitor.MyInterfaces()
	if len(myInterfaceNames) == 0 {
		return
	}
	var (
		myAddresses []netip.Prefix
		found       bool
	)
	for _, myInterfaceName := range myInterfaceNames {
		myInterface, err := h.network.InterfaceFinder().ByName(myInterfaceName)
		if err != nil {
			continue
		}
		found = true
		myAddresses = append(myAddresses, myInterface.Addresses...)
	}
	if !found {
		return
	}
	h.myAddresses.Store(myAddresses)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.fetchMyAddresses()
	if h.icmpPort != nil {
		h.icmpPort.Close()
	}
}

func (h *Outbound) isMyLoopbackAddress(addresses ...netip.Addr) bool {
	for _, prefix := range h.myAddresses.Load() {
		for _, address := range addresses {
			if !C.IsDarwin && prefix.Addr() == address {
				continue
			}
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	conn, err := h.dialer.DialContext(ctx, network, destination)
	return h.withProxyProtocol(ctx, network, destination, conn, err)
}

// withProxyProtocol sends the PROXY protocol header on a new TCP connection when configured. //H
func (h *Outbound) withProxyProtocol(ctx context.Context, network string, destination M.Socksaddr, conn net.Conn, err error) (net.Conn, error) {
	if err != nil || h.proxyProtocol == 0 || network != N.NetworkTCP {
		return conn, err
	}
	return proxyproto.WriteHeader(ctx, conn, h.proxyProtocol, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	conn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (h *Outbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	if network == N.NetworkICMP && h.icmpPort != nil {
		return adapter.PreMatchFlow
	}
	return adapter.PreMatchContinue
}

func (h *Outbound) PortAddresses() (netip.Addr, netip.Addr) {
	return h.icmpPort.PortAddresses()
}

func (h *Outbound) PortMTU() uint32 {
	return h.icmpPort.PortMTU()
}

func (h *Outbound) AttachReturn(returnPath tun.Return) error {
	return h.icmpPort.AttachReturn(returnPath)
}

func (h *Outbound) DetachReturn(returnPath tun.Return) error {
	return h.icmpPort.DetachReturn(returnPath)
}

func (h *Outbound) WritePackets(packets [][]byte) error {
	return h.icmpPort.WritePackets(packets)
}

func (h *Outbound) Close() error {
	if h.icmpPort != nil {
		return h.icmpPort.Close()
	}
	return nil
}

func (h *Outbound) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	conn, err := dialer.DialParallelNetwork(ctx, h.dialer, network, destination, destinationAddresses, len(destinationAddresses) > 0 && destinationAddresses[0].Is6(), nil, nil, nil, h.fallbackDelay)
	return h.withProxyProtocol(ctx, network, destination, conn, err)
}

func (h *Outbound) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	conn, err := dialer.DialParallelNetwork(ctx, h.dialer, network, destination, destinationAddresses, len(destinationAddresses) > 0 && destinationAddresses[0].Is6(), networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
	return h.withProxyProtocol(ctx, network, destination, conn, err)
}

func (h *Outbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, netip.Addr{}, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	conn, newDestination, err := dialer.ListenSerialNetworkPacket(ctx, h.dialer, destination, destinationAddresses, networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	return conn, newDestination, nil
}

func (h *Outbound) IsEmpty() bool {
	return h.isEmpty
}
