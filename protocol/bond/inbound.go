package bond

import (
	"context"
	"net"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/kmutex"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/shtorm-7/go-cache/v2"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.BondInboundOptions](registry, C.TypeBond, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	logger   logger.ContextLogger
	router   adapter.ConnectionRouterEx
	inbounds []adapter.Inbound
	conns    *cache.Cache[uuid.UUID, map[uint8]*ratioConn]

	mtx *kmutex.Kmutex[uuid.UUID]
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BondInboundOptions) (adapter.Inbound, error) {
	if len(options.Inbounds) == 0 {
		return nil, E.New("missing tags")
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeBond, tag),
		logger:  logger,
		router:  uot.NewRouter(router, logger),
		conns:   cache.New[uuid.UUID, map[uint8]*ratioConn](C.TCPConnectTimeout, time.Second),
		mtx:     kmutex.New[uuid.UUID](),
	}
	router = NewRouter(router, logger, inbound.connHandler)
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	inbounds := make([]adapter.Inbound, len(options.Inbounds))
	for i, inboundOptions := range options.Inbounds {
		inbound, err := inboundRegistry.UnsafeCreate(ctx, router, logger, inboundOptions.Tag, inboundOptions.Type, inboundOptions.Options)
		if err != nil {
			return nil, err
		}
		inbounds[i] = inbound
	}
	inbound.inbounds = inbounds
	inbound.conns.OnEvicted(func(s uuid.UUID, ratioConns map[uint8]*ratioConn) {
		inbound.mtx.Lock(s)
		defer inbound.mtx.Unlock(s)
		for _, ratioConn := range ratioConns {
			if ratioConn != nil {
				ratioConn.conn.Close()
			}
		}
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	for _, inbound := range h.inbounds {
		err := scope.Start("inbound/"+inbound.Type()+"["+inbound.Tag()+"]", inbound, stage)
		if err != nil {
			return err
		}
	}
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error {
			h.conns.Close()
			return nil
		})
	}
	return nil
}

func (h *Inbound) References() []string {
	var references []string
	for _, inbound := range h.inbounds {
		referrer, isReferrer := inbound.(adapter.Referrer)
		if isReferrer {
			references = append(references, referrer.References()...)
		}
	}
	return references
}

func (h *Inbound) connHandler(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	request, err := ReadRequest(conn)
	if err != nil {
		return err
	}
	requestUUID := request.UUID
	h.mtx.Lock(requestUUID)
	var ratioConns map[uint8]*ratioConn
	ratioConns, ok := h.conns.Get(requestUUID)
	if !ok {
		ratioConns = make(map[uint8]*ratioConn, request.Count)
		h.conns.SetDefault(requestUUID, ratioConns)
	}
	ratioConns[request.Index] = &ratioConn{
		conn:          conn,
		downloadRatio: request.DownloadRatio,
		uploadRatio:   request.UploadRatio,
	}
	if len(ratioConns) == int(request.Count) {
		conns := make([]net.Conn, len(ratioConns))
		downloadRatios := make([]uint8, len(ratioConns))
		uploadRatios := make([]uint8, len(ratioConns))
		var totalDownloadRatio, totalUploadRatio uint8
		for index, ratioConn := range ratioConns {
			conns[index] = ratioConn.conn
			downloadRatios[index] = ratioConn.downloadRatio
			uploadRatios[index] = ratioConn.uploadRatio
			totalDownloadRatio += ratioConn.downloadRatio
			totalUploadRatio += ratioConn.uploadRatio
			delete(ratioConns, index)
		}
		if totalDownloadRatio != 100 || totalUploadRatio != 100 {
			for _, conn := range conns {
				conn.Close()
			}
			h.mtx.Unlock(requestUUID)
			return E.New("invalid ratios")
		}
		conn = NewBondedConn(conns, downloadRatios, uploadRatios)
		metadata.Inbound = h.Tag()
		metadata.InboundType = C.TypeBond
		metadata.Destination = request.Destination
		h.mtx.Unlock(requestUUID)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return nil
	}
	h.mtx.Unlock(requestUUID)
	return nil
}

type ratioConn struct {
	conn          net.Conn
	downloadRatio uint8
	uploadRatio   uint8
}
