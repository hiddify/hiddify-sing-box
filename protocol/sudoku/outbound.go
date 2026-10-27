package sudoku

import (
	"context"
	"net"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/sudoku"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SudokuOutboundOptions](registry, C.TypeSudoku, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger    logger.ContextLogger
	client    *sudoku.Client
	tlsConfig tls.Config
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SudokuOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	defaultConf := sudoku.DefaultConfig()
	tableType, err := sudoku.NormalizeTableType(options.TableType)
	if err != nil {
		return nil, err
	}
	paddingMin, paddingMax := sudoku.ResolvePadding(options.PaddingMin, options.PaddingMax, defaultConf.PaddingMin, defaultConf.PaddingMax)
	enablePureDownlink := sudoku.DerefBool(options.EnablePureDownlink, defaultConf.EnablePureDownlink)

	serverAddr := options.ServerOptions.Build()

	disableHTTPMask := defaultConf.DisableHTTPMask
	httpMaskMode := defaultConf.HTTPMaskMode
	var httpMaskHost string
	var pathRoot string
	multiplex := defaultConf.Multiplex
	if mode := strings.TrimSpace(options.Multiplex); mode != "" {
		multiplex = mode
	}

	if hm := options.HTTPMask; hm != nil {
		disableHTTPMask = !hm.Enabled
		if hm.Mode != "" {
			httpMaskMode = hm.Mode
		}
		httpMaskHost = hm.Host
		pathRoot = strings.TrimSpace(hm.PathRoot)
		if mode := strings.TrimSpace(hm.Multiplex); mode != "" {
			multiplex = mode
		}
	}

	baseConf := sudoku.ProtocolConfig{
		ServerAddress:           serverAddr.String(),
		Key:                     options.Key,
		AEADMethod:              defaultConf.AEADMethod,
		PaddingMin:              paddingMin,
		PaddingMax:              paddingMax,
		EnablePureDownlink:      enablePureDownlink,
		HandshakeTimeoutSeconds: defaultConf.HandshakeTimeoutSeconds,
		DisableHTTPMask:         disableHTTPMask,
		HTTPMaskMode:            httpMaskMode,
		HTTPMaskHost:            httpMaskHost,
		HTTPMaskPathRoot:        pathRoot,
		Multiplex:               multiplex,
	}
	if options.AEADMethod != "" {
		baseConf.AEADMethod = options.AEADMethod
	}

	tables, err := sudoku.NewClientTablesWithCustomPatterns(sudoku.ClientAEADSeed(options.Key), tableType, options.CustomTable, options.CustomTables)
	if err != nil {
		return nil, E.Cause(err, "build table(s)")
	}
	if len(tables) == 1 {
		baseConf.Table = tables[0]
	} else {
		baseConf.Tables = tables
	}
	if err = baseConf.Validate(); err != nil {
		return nil, err
	}

	var tlsConfig tls.Config
	if hm := options.HTTPMask; !disableHTTPMask && hm != nil && hm.TLS != nil && hm.TLS.Enabled {
		tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
			Context:       ctx,
			Logger:        logger,
			ServerAddress: options.Server,
			Options:       *hm.TLS,
		})
		if err != nil {
			return nil, err
		}
	}

	client, err := sudoku.NewClient(sudoku.ClientOptions{
		Dialer:    outboundDialer,
		TLSConfig: tlsConfig,
		Config:    baseConf,
	})
	if err != nil {
		return nil, err
	}

	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeSudoku, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:    logger,
		client:    client,
		tlsConfig: tlsConfig,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	return h.client.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	conn, err := h.client.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return bufio.NewBindPacketConn(sudoku.NewUoTPacketConn(conn), destination), nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(func() error {
		h.client.Close()
		return common.Close(h.tlsConfig)
	})
	return nil
}

func (h *Outbound) InterfaceUpdated() {
	err := h.client.ResetConnections()
	if err != nil {
		h.logger.Error(E.Cause(err, "reset connections"))
	}
}
