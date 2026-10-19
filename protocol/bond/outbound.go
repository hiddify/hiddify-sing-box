package bond

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/gofrs/uuid/v5"
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
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.BondOutboundOptions](registry, C.TypeBond, NewOutbound)
}

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
	outbounds := make([]adapter.Outbound, 0, len(options.Outbounds))
	downloadRatios := make([]uint8, 0, len(options.Outbounds))
	uploadRatios := make([]uint8, 0, len(options.Outbounds))
	var totalDownloadRatio, totalUploadRatio uint8
	for _, outboundOptions := range options.Outbounds {
		count := outboundOptions.Count
		if count == 0 {
			count = 1
		}
		for range count {
			outbound, err := outboundRegistry.UnsafeCreateOutbound(ctx, router, logger, outboundOptions.Outbound.Tag, outboundOptions.Outbound.Type, outboundOptions.Outbound.Options)
			if err != nil {
				return nil, err
			}
			outbounds = append(outbounds, outbound)
			downloadRatios = append(downloadRatios, outboundOptions.DownloadRatio)
			uploadRatios = append(uploadRatios, outboundOptions.UploadRatio)
			totalDownloadRatio += outboundOptions.DownloadRatio
			totalUploadRatio += outboundOptions.UploadRatio
		}
	}
	if totalDownloadRatio != 100 || totalUploadRatio != 100 {
		return nil, E.New("invalid ratios")
	}
	outbound := &Outbound{
		Adapter:        outbound.NewAdapter(C.TypeBond, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{}),
		ctx:            ctx,
		outbounds:      outbounds,
		downloadRatios: downloadRatios,
		uploadRatios:   uploadRatios,
		logger:         logger,
	}
	outbound.uotClient = &uot.Client{
		Dialer:  outbound,
		Version: uot.Version,
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	for _, outbound := range h.outbounds {
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		err := scope.Start("outbound/"+outbound.Type()+"["+outbound.Tag()+"]", lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *Outbound) References() []string {
	var references []string
	for _, outbound := range h.outbounds {
		referrer, isReferrer := outbound.(adapter.Referrer)
		if isReferrer {
			references = append(references, referrer.References()...)
		} else {
			references = append(references, outbound.Dependencies()...)
		}
	}
	return references
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	for _, outbound := range h.outbounds {
		keeper, isKeeper := outbound.(adapter.IdleConnectionKeeper)
		if isKeeper {
			keeper.SetKeepIdleConnections(keep)
		}
	}
}

func (h *Outbound) CloseIdleConnections() {
	for _, outbound := range h.outbounds {
		keeper, isKeeper := outbound.(adapter.IdleConnectionKeeper)
		if isKeeper {
			keeper.CloseIdleConnections()
		}
	}
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		return h.uotClient.DialContext(ctx, network, destination)
	}
	conns := make([]net.Conn, len(h.outbounds))
	connUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	errs := make([]error, 0, len(conns))
	var mtx sync.Mutex
	var wg sync.WaitGroup
	for i, outbound := range h.outbounds {
		wg.Go(
			func() {
				conn, err := outbound.DialContext(ctx, network, Destination)
				if err != nil {
					mtx.Lock()
					errs = append(errs, err)
					mtx.Unlock()
					return
				}
				err = WriteRequest(
					conn,
					&Request{
						UUID:          connUUID,
						Index:         byte(i),
						Count:         byte(len(h.outbounds)),
						DownloadRatio: h.uploadRatios[i],
						UploadRatio:   h.downloadRatios[i],
						Destination:   destination,
					},
				)
				if err != nil {
					conn.Close()
					mtx.Lock()
					errs = append(errs, err)
					mtx.Unlock()
					return
				}
				conns[i] = conn
			},
		)
	}
	wg.Wait()
	if len(errs) != 0 {
		for _, conn := range conns {
			if conn != nil {
				conn.Close()
			}
		}
		return nil, errors.Join(errs...)
	}
	conn := NewBondedConn(conns, h.downloadRatios, h.uploadRatios)
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return h.uotClient.ListenPacket(ctx, destination)
}
