package sudoku

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/transport/sudoku/obfs/httpmask"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ClientOptions struct {
	Dialer    N.Dialer
	TLSConfig tls.Config
	Config    ProtocolConfig
}

type Client struct {
	dialer    N.Dialer
	tlsConfig tls.Config
	baseConf  ProtocolConfig

	muxDialer atomic.Pointer[MultiplexDialer]

	httpMaskMu     sync.Mutex
	httpMaskClient *httpmask.TunnelClient
	httpMaskKey    string
}

func NewClient(options ClientOptions) (*Client, error) {
	client := &Client{
		dialer:    options.Dialer,
		tlsConfig: options.TLSConfig,
		baseConf:  options.Config,
	}
	if client.baseConf.SessionMuxEnabled() {
		muxDialer, err := NewMultiplexDialer(client.dialMultiplexBase)
		if err != nil {
			return nil, err
		}
		client.muxDialer.Store(muxDialer)
	}
	return client, nil
}

func (c *Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	cfg := c.baseConf
	cfg.TargetAddress = destination.String()

	if cfg.SessionMuxEnabled() && N.NetworkName(network) != N.NetworkUDP {
		muxDialer := c.muxDialer.Load()
		if muxDialer == nil {
			return nil, E.New("multiplex dialer is unavailable")
		}
		return muxDialer.Dial(ctx, cfg.TargetAddress)
	}

	conn, err := c.dialAndHandshake(ctx, &cfg)
	if err != nil {
		return nil, err
	}

	switch N.NetworkName(network) {
	case N.NetworkUDP:
		if err = WriteKIPMessage(conn, KIPTypeStartUoT, nil); err != nil {
			conn.Close()
			return nil, E.Cause(err, "start uot")
		}
		return conn, nil
	default:
		addrBuf, err := EncodeAddress(cfg.TargetAddress)
		if err != nil {
			conn.Close()
			return nil, E.Cause(err, "encode target address")
		}
		if err = WriteKIPMessage(conn, KIPTypeOpenTCP, addrBuf); err != nil {
			conn.Close()
			return nil, E.Cause(err, "send target address")
		}
		return conn, nil
	}
}

func (c *Client) Close() {
	if muxDialer := c.muxDialer.Swap(nil); muxDialer != nil {
		muxDialer.Close()
	}
	c.resetHTTPMaskClient()
}

func (c *Client) ResetConnections() error {
	if c.baseConf.SessionMuxEnabled() {
		muxDialer, err := NewMultiplexDialer(c.dialMultiplexBase)
		if err != nil {
			return err
		}
		if previous := c.muxDialer.Swap(muxDialer); previous != nil {
			previous.Close()
		}
	}
	c.resetHTTPMaskClient()
	return nil
}

func (c *Client) dialAndHandshake(ctx context.Context, cfg *ProtocolConfig) (net.Conn, error) {
	handshakeCfg := *cfg
	if !handshakeCfg.DisableHTTPMask && httpTunnelModeEnabled(handshakeCfg.HTTPMaskMode) {
		handshakeCfg.DisableHTTPMask = true
	}

	upgrade := func(raw net.Conn) (net.Conn, error) {
		return ClientHandshake(raw, &handshakeCfg)
	}

	var conn net.Conn
	var err error
	var handshakeDone bool

	if !cfg.DisableHTTPMask && httpTunnelModeEnabled(cfg.HTTPMaskMode) {
		muxMode := cfg.MultiplexMode()
		if muxMode == "auto" && strings.ToLower(strings.TrimSpace(cfg.HTTPMaskMode)) != "ws" {
			if client, cerr := c.getOrCreateHTTPMaskClient(cfg); cerr == nil && client != nil {
				conn, err = client.DialTunnel(ctx, httpmask.TunnelDialOptions{
					Mode:         cfg.HTTPMaskMode,
					TLSConfig:    c.httpMaskTLSConfig(),
					HostOverride: cfg.HTTPMaskHost,
					PathRoot:     cfg.HTTPMaskPathRoot,
					AuthKey:      ClientAEADSeed(cfg.Key),
					Upgrade:      upgrade,
					DialContext:  c.dialRaw,
				})
				if err != nil {
					c.resetHTTPMaskClient()
				}
			}
		}
		if conn == nil && err == nil {
			conn, err = c.dialHTTPMaskTunnel(ctx, cfg, upgrade)
		}
		if err == nil && conn != nil {
			handshakeDone = true
		}
	}
	if conn == nil && err == nil {
		conn, err = c.dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(cfg.ServerAddress))
	}
	if err != nil {
		return nil, E.Cause(err, "connect to ", cfg.ServerAddress)
	}

	if !handshakeDone {
		conn, err = ClientHandshake(conn, &handshakeCfg)
		if err != nil {
			common.Close(conn)
			return nil, err
		}
	}

	return conn, nil
}

func (c *Client) dialMultiplexBase(ctx context.Context) (net.Conn, error) {
	cfg := c.baseConf
	return c.dialAndHandshake(ctx, &cfg)
}

func (c *Client) dialRaw(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
}

func (c *Client) dialHTTPMaskTunnel(ctx context.Context, cfg *ProtocolConfig, upgrade func(net.Conn) (net.Conn, error)) (net.Conn, error) {
	var earlyHandshake *httpmask.ClientEarlyHandshake
	var err error
	if upgrade != nil {
		earlyHandshake, err = newClientHTTPMaskEarlyHandshake(cfg)
		if err != nil {
			return nil, err
		}
	}
	return httpmask.DialTunnel(ctx, cfg.ServerAddress, httpmask.TunnelDialOptions{
		Mode:           cfg.HTTPMaskMode,
		TLSConfig:      c.httpMaskTLSConfig(),
		HostOverride:   cfg.HTTPMaskHost,
		PathRoot:       cfg.HTTPMaskPathRoot,
		AuthKey:        ClientAEADSeed(cfg.Key),
		EarlyHandshake: earlyHandshake,
		Upgrade:        upgrade,
		DialContext:    c.dialRaw,
	})
}

func (c *Client) httpMaskTLSConfig() tls.Config {
	if c.tlsConfig == nil {
		return nil
	}
	return c.tlsConfig
}

func (c *Client) getOrCreateHTTPMaskClient(cfg *ProtocolConfig) (*httpmask.TunnelClient, error) {
	key := cfg.ServerAddress + "|" + fmt.Sprint(c.tlsConfig != nil) + "|" + strings.TrimSpace(cfg.HTTPMaskHost)

	c.httpMaskMu.Lock()
	if c.httpMaskClient != nil && c.httpMaskKey == key {
		client := c.httpMaskClient
		c.httpMaskMu.Unlock()
		return client, nil
	}
	c.httpMaskMu.Unlock()

	client, err := httpmask.NewTunnelClient(cfg.ServerAddress, httpmask.TunnelClientOptions{
		TLSConfig:    c.httpMaskTLSConfig(),
		HostOverride: cfg.HTTPMaskHost,
		DialContext:  c.dialRaw,
		MaxIdleConns: 32,
	})
	if err != nil {
		return nil, err
	}

	c.httpMaskMu.Lock()
	defer c.httpMaskMu.Unlock()
	if c.httpMaskClient != nil && c.httpMaskKey == key {
		client.CloseIdleConnections()
		return c.httpMaskClient, nil
	}
	if c.httpMaskClient != nil {
		c.httpMaskClient.CloseIdleConnections()
	}
	c.httpMaskClient = client
	c.httpMaskKey = key
	return client, nil
}

func (c *Client) resetHTTPMaskClient() {
	c.httpMaskMu.Lock()
	defer c.httpMaskMu.Unlock()
	if c.httpMaskClient != nil {
		c.httpMaskClient.CloseIdleConnections()
		c.httpMaskClient = nil
		c.httpMaskKey = ""
	}
}

func httpTunnelModeEnabled(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "stream", "poll", "auto", "ws":
		return true
	default:
		return false
	}
}
