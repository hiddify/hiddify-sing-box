package failover

import (
	"context"
	"net"
	"sync"

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
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.FailoverInboundOptions](registry, C.TypeFailover, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	logger   logger.ContextLogger
	router   adapter.ConnectionRouterEx
	inbounds []adapter.Inbound
	conns    map[uuid.UUID]*failoverConn

	sessionMtx *kmutex.Kmutex[uuid.UUID]
	mtx        sync.RWMutex
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FailoverInboundOptions) (adapter.Inbound, error) {
	if len(options.Inbounds) == 0 {
		return nil, E.New("missing inbounds")
	}
	inbound := &Inbound{
		Adapter:    inbound.NewAdapter(C.TypeFailover, tag),
		logger:     logger,
		router:     uot.NewRouter(router, logger),
		conns:      make(map[uuid.UUID]*failoverConn),
		sessionMtx: kmutex.New[uuid.UUID](),
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
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	for _, inbound := range h.inbounds {
		err := scope.Start("inbound/"+inbound.Type()+"["+inbound.Tag()+"]", inbound, stage)
		if err != nil {
			return err
		}
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
	if metadata.Destination != Destination {
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return nil
	}
	request, err := ReadRequest(conn)
	if err != nil {
		return err
	}
	sessionUUID := request.UUID
	h.sessionMtx.Lock(sessionUUID)
	if request.Command == CommandTCP {
		failoverConn := NewFailoverConn(ctx, conn, nil, func() {
			h.sessionMtx.Lock(sessionUUID)
			h.mtx.Lock()
			delete(h.conns, sessionUUID)
			h.sessionMtx.Unlock(sessionUUID)
			h.mtx.Unlock()
		})
		h.mtx.Lock()
		h.conns[sessionUUID] = failoverConn
		h.mtx.Unlock()
		metadata.Inbound = h.Tag()
		metadata.InboundType = C.TypeFailover
		metadata.Destination = request.Destination
		h.sessionMtx.Unlock(sessionUUID)
		h.router.RouteConnectionEx(ctx, failoverConn, metadata, onClose)
		return nil
	}
	if request.Command == CommandReconnect {
		h.mtx.RLock()
		serverConn, ok := h.conns[sessionUUID]
		h.mtx.RUnlock()
		if !ok {
			h.sessionMtx.Unlock(sessionUUID)
			_, err := conn.Write([]byte{StatusSessionNotFound})
			if err != nil {
				return err
			}
			return SessionNotFound
		}
		_, err = conn.Write([]byte{StatusOK})
		if err != nil {
			return err
		}
		err := serverConn.RestoreConn(conn)
		h.sessionMtx.Unlock(sessionUUID)
		return err
	}
	return E.New("command ", request.Command, " not found")
}
