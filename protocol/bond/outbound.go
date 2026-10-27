//go:build with_bond

package bond

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"

	"github.com/gofrs/uuid/v5"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.BondOutboundOptions](registry, C.TypeBond, NewOutbound)
}

// Outbound opens one connection through every leg for each connection and splits the traffic
// over them by ratio; the bond inbound on the server joins them again.
type Outbound struct {
	outbound.Adapter
	ctx            context.Context
	logger         logger.ContextLogger
	outbounds      []adapter.Outbound
	downloadRatios []uint8
	uploadRatios   []uint8
	uotClient      *uot.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BondOutboundOptions) (adapter.Outbound, error) {
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	if outboundRegistry == nil {
		return nil, E.New("missing outbound registry")
	}
	var outbounds []adapter.Outbound
	var downloadRatios, uploadRatios []uint8
	for _, legOptions := range options.Outbounds {
		count := int(legOptions.Count)
		if count == 0 {
			count = 1
		}
		for range count {
			leg, err := outboundRegistry.CreateOutbound(ctx, router, logger, legOptions.Outbound.Tag, legOptions.Outbound.Type, legOptions.Outbound.Options)
			if err != nil {
				return nil, E.Cause(err, "bond leg ", legOptions.Outbound.Type)
			}
			outbounds = append(outbounds, leg)
			downloadRatios = append(downloadRatios, legOptions.DownloadRatio)
			uploadRatios = append(uploadRatios, legOptions.UploadRatio)
		}
	}
	if len(outbounds) == 0 {
		return nil, E.New("bond: missing outbounds")
	}
	if len(outbounds) > 255 {
		return nil, E.New("bond: more than 255 legs")
	}
	if err := checkRatios("download", downloadRatios); err != nil {
		return nil, err
	}
	if err := checkRatios("upload", uploadRatios); err != nil {
		return nil, err
	}
	bond := &Outbound{
		Adapter:        outbound.NewAdapter(C.TypeBond, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ctx:            ctx,
		logger:         logger,
		outbounds:      outbounds,
		downloadRatios: downloadRatios,
		uploadRatios:   uploadRatios,
	}
	bond.uotClient = &uot.Client{Dialer: bond, Version: uot.Version}
	return bond, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	for _, leg := range h.outbounds {
		lifecycle, isLifecycle := leg.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		if err := scope.Start("outbound/"+leg.Type()+"["+leg.Tag()+"]", lifecycle, stage); err != nil {
			return err
		}
	}
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		return h.uotClient.DialContext(ctx, network, destination)
	}
	connUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	conns := make([]net.Conn, len(h.outbounds))
	var errs []error
	var access sync.Mutex
	var group sync.WaitGroup
	for i, leg := range h.outbounds {
		group.Go(func() {
			conn, err := leg.DialContext(ctx, N.NetworkTCP, Destination)
			if err == nil {
				// the server's download is our upload
				err = WriteRequest(conn, &Request{
					UUID:          connUUID,
					Index:         byte(i),
					Count:         byte(len(h.outbounds)),
					DownloadRatio: h.uploadRatios[i],
					UploadRatio:   h.downloadRatios[i],
					Destination:   destination,
				})
				if err != nil {
					conn.Close()
				}
			}
			access.Lock()
			defer access.Unlock()
			if err != nil {
				errs = append(errs, E.Cause(err, "bond leg ", leg.Tag()))
				return
			}
			conns[i] = conn
		})
	}
	group.Wait()
	if len(errs) > 0 {
		for _, conn := range conns {
			if conn != nil {
				conn.Close()
			}
		}
		return nil, errors.Join(errs...)
	}
	return newBondedConn(conns, h.downloadRatios, h.uploadRatios, nil), nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return h.uotClient.ListenPacket(ctx, destination)
}
