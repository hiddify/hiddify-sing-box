//go:build with_bond

package bond

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/gofrs/uuid/v5"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.BondInboundOptions](registry, C.TypeBond, NewInbound)
}

// Inbound runs its inbounds and joins the legs of each bonded connection that arrive through
// them, then routes the joined connection.
type Inbound struct {
	inbound.Adapter
	logger   logger.ContextLogger
	router   adapter.ConnectionRouterEx
	inbounds []adapter.Inbound

	access  sync.Mutex
	pending map[uuid.UUID]*pendingBond
}

type leg struct {
	conn          net.Conn
	downloadRatio uint8
	uploadRatio   uint8
	onClose       N.CloseHandlerFunc
}

type pendingBond struct {
	legs  map[uint8]leg
	timer *time.Timer
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BondInboundOptions) (adapter.Inbound, error) {
	if len(options.Inbounds) == 0 {
		return nil, E.New("bond: missing inbounds")
	}
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	if inboundRegistry == nil {
		return nil, E.New("missing inbound registry")
	}
	bond := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeBond, tag),
		logger:  logger,
		router:  uot.NewRouter(router, logger),
		pending: make(map[uuid.UUID]*pendingBond),
	}
	legRouter := NewRouter(router, logger, bond.connHandler)
	for _, inboundOptions := range options.Inbounds {
		legInbound, err := inboundRegistry.Create(ctx, legRouter, logger, inboundOptions.Tag, inboundOptions.Type, inboundOptions.Options)
		if err != nil {
			return nil, E.Cause(err, "bond inbound ", inboundOptions.Type)
		}
		bond.inbounds = append(bond.inbounds, legInbound)
	}
	return bond, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	for _, legInbound := range h.inbounds {
		if err := scope.Start("inbound/"+legInbound.Type()+"["+legInbound.Tag()+"]", legInbound, stage); err != nil {
			return err
		}
	}
	if stage == adapter.StartStateInitialize {
		scope.Add(h.closePending)
	}
	return nil
}

func (h *Inbound) closePending() error {
	h.access.Lock()
	pending := h.pending
	h.pending = make(map[uuid.UUID]*pendingBond)
	h.access.Unlock()
	for _, bond := range pending {
		bond.timer.Stop()
		closeLegs(bond.legs, net.ErrClosed)
	}
	return nil
}

func closeLegs(legs map[uint8]leg, err error) {
	for _, leg := range legs {
		leg.conn.Close()
		if leg.onClose != nil {
			leg.onClose(err)
		}
	}
}

// connHandler takes one leg. The legs of a connection wait for each other up to the connect
// timeout; the last one to arrive routes the joined connection.
func (h *Inbound) connHandler(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	request, err := ReadRequest(conn)
	if err != nil {
		return err
	}
	if request.Count == 0 || request.Index >= request.Count {
		return E.New("bond: leg ", request.Index, " of ", request.Count)
	}
	h.access.Lock()
	bond, loaded := h.pending[request.UUID]
	if !loaded {
		id := request.UUID
		bond = &pendingBond{legs: make(map[uint8]leg, request.Count)}
		bond.timer = time.AfterFunc(C.TCPConnectTimeout, func() {
			h.access.Lock()
			expired, stillPending := h.pending[id]
			delete(h.pending, id)
			h.access.Unlock()
			if stillPending {
				h.logger.Debug("bond: legs of ", id, " did not all arrive")
				closeLegs(expired.legs, os.ErrDeadlineExceeded)
			}
		})
		h.pending[id] = bond
	}
	if _, duplicate := bond.legs[request.Index]; duplicate {
		h.access.Unlock()
		return E.New("bond: leg ", request.Index, " arrived twice")
	}
	bond.legs[request.Index] = leg{conn: conn, downloadRatio: request.DownloadRatio, uploadRatio: request.UploadRatio, onClose: onClose}
	if len(bond.legs) < int(request.Count) {
		h.access.Unlock()
		return nil
	}
	delete(h.pending, request.UUID)
	h.access.Unlock()
	bond.timer.Stop()

	conns := make([]net.Conn, request.Count)
	downloadRatios := make([]uint8, request.Count)
	uploadRatios := make([]uint8, request.Count)
	for index, leg := range bond.legs {
		conns[index] = leg.conn
		downloadRatios[index] = leg.downloadRatio
		uploadRatios[index] = leg.uploadRatio
	}
	if err = checkRatios("download", downloadRatios); err == nil {
		err = checkRatios("upload", uploadRatios)
	}
	if err != nil {
		closeLegs(bond.legs, err)
		return nil
	}
	joined := newBondedConn(conns, downloadRatios, uploadRatios, nil)
	metadata.Inbound = h.Tag()
	metadata.InboundType = C.TypeBond
	metadata.Destination = request.Destination
	h.router.RouteConnectionEx(ctx, joined, metadata, func(err error) {
		for _, leg := range bond.legs {
			if leg.onClose != nil {
				leg.onClose(err)
			}
		}
	})
	return nil
}
