package ssh

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/ssh"
)

// RegisterInbound registers SSH inbound type
func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SSHInboundOptions](registry, C.TypeSSH, NewInbound)
}

// Inbound represents SSH inbound
type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	users    map[string]option.SSHUser
	config   *ssh.ServerConfig
}

// NewInbound creates new SSH inbound
func NewInbound(
	ctx context.Context,
	router adapter.Router,
	logger log.ContextLogger,
	tag string,
	options option.SSHInboundOptions,
) (adapter.Inbound, error) {

	users := map[string]option.SSHUser{}
	for _, u := range options.Users {
		users[u.User] = u
	}

	serverConfig := &ssh.ServerConfig{}

	// Password auth
	serverConfig.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		u, ok := users[c.User()]
		logger.Debug("checking user pass ", c.User())
		if !ok || u.Password == "" {
			return nil, fmt.Errorf("invalid user")
		}
		if u.Password != string(pass) {
			return nil, fmt.Errorf("invalid password")
		}
		return &ssh.Permissions{}, nil
	}

	// PublicKey auth
	serverConfig.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		u, ok := users[c.User()]
		logger.Debug("checking user pub ", c.User())
		if !ok || u.PublicKey == "" {
			return nil, fmt.Errorf("invalid user")
		}

		parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(u.PublicKey))
		if err != nil {
			return nil, err
		}

		// Compare by Marshal (KeysEqual may not exist)
		if string(parsedKey.Marshal()) == string(key.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, fmt.Errorf("invalid key")
	}

	// HostKeys
	for _, key := range options.HostKey {
		privBytes := []byte(key)
		priv, err := ssh.ParsePrivateKey(privBytes)
		if err != nil {
			return nil, err
		}
		serverConfig.AddHostKey(priv)
	}

	in := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeSSH, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger), // UDP over TCP
		logger:  logger,

		users:  users,
		config: serverConfig,
	}
	in.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Listen:            options.ListenOptions,
		Network:           []string{"tcp"},
		ConnectionHandler: in,
	},
	)

	return in, nil
}

// Start listener
func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	if err := h.listener.Start(); err != nil {
		return err
	}

	return nil
}

//nolint:staticcheck
func (h *Inbound) NewConnection(ctx context.Context, rawConn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	h.logger.Debug("getting connection", fmt.Sprint(metadata))
	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, h.config)
	if err != nil {
		h.logger.Debug("error connection", err)
		rawConn.Close()
		return
	}
	defer sshConn.Close()
	h.logger.Debug("user:", sshConn.User())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		h.logger.Debug("channel connection", fmt.Sprintf("%+v", newChannel))
		if newChannel.ChannelType() != "direct-tcpip" {
			h.logger.Debug("not direct-tcpip connection", fmt.Sprintf("%+v", newChannel.ChannelType()))
			newChannel.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		forward := forwardData{}
		if err := ssh.Unmarshal(newChannel.ExtraData(), &forward); err != nil {
			newChannel.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
			return
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(requests)

		h.logger.Debug("Forwarding to ", forward.DestAddr, ":", forward.DestPort)

		go h.routeChannel(ctx, channel, forward, sshConn.User())
	}
}

type forwardData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

// Close listener
func (h *Inbound) Close() error {
	return h.listener.Close()
}

// routeChannel routes channel to router
func (h *Inbound) routeChannel(ctx context.Context, channel ssh.Channel, d forwardData, user string) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User = user
	metadata.Destination = M.Socksaddr{
		Port: uint16(d.DestPort),
	}
	if ip, err := netip.ParseAddr(d.DestAddr); err == nil {
		metadata.Destination.Addr = ip
	} else {
		metadata.Destination.Fqdn = d.DestAddr
	}

	h.logger.InfoContext(ctx, "[", user, "] SSH inbound connection")
	// Wrap channel to net.Conn
	con := &channelConn{Channel: channel} // localAddr:  &net.TCPAddr{IP: net.ParseIP(d.OriginAddr), Port: int(d.OriginPort)},
	// remoteAddr: &net.TCPAddr{IP: net.ParseIP(d.DestAddr), Port: int(d.DestPort)},

	h.router.RouteConnectionEx(ctx, con, metadata, func(it error) {
		channel.Close()
	})
}

// ----------------- helper: wrap ssh.Channel to net.Conn -----------------
type channelConn struct {
	ssh.Channel
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *channelConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *channelConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *channelConn) SetDeadline(t time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(t time.Time) error { return nil }
