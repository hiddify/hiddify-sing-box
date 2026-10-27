package ssh

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
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
	if options.ServerVersion != "" {
		// the identification string must start with SSH-2.0-, so a bare name such as OpenSSH_9.6 gets it
		serverConfig.ServerVersion = options.ServerVersion
		if !strings.HasPrefix(serverConfig.ServerVersion, "SSH-2.0-") {
			serverConfig.ServerVersion = "SSH-2.0-" + serverConfig.ServerVersion
		}
	}

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
	var hostKeys int
	for _, key := range options.HostKey {
		privBytes := []byte(key)
		priv, err := ssh.ParsePrivateKey(privBytes)
		if err != nil {
			return nil, err
		}
		signer, err := restrictHostKey(priv, options.HostKeyAlgorithms)
		if err != nil {
			return nil, err
		}
		if signer == nil {
			continue
		}
		hostKeys++
		serverConfig.AddHostKey(signer)
	}
	if len(options.HostKeyAlgorithms) > 0 && hostKeys == 0 {
		return nil, E.New("ssh: no host key has an algorithm in host_key_algorithms")
	}
	connectionRouter := adapter.ConnectionRouterEx(uot.NewRouter(router, logger)) // UDP over TCP
	if len(options.Network) > 0 && !common.Contains(options.Network.Build(), N.NetworkUDP) {
		connectionRouter = router // network without udp: no UDP over TCP
	}

	in := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeSSH, tag),
		ctx:     ctx,
		router:  connectionRouter,
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
func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(h.Close) // H: closed with the box
	}
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
			continue // only this channel is refused, not the whole connection
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
	con := deadline.NewConn(&channelConn{Channel: channel}) // the channel has no deadlines of its own // localAddr:  &net.TCPAddr{IP: net.ParseIP(d.OriginAddr), Port: int(d.OriginPort)},
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

// restrictHostKey limits a host key to the algorithms in algorithms: an RSA key signs only with
// the listed rsa-sha2-* or ssh-rsa, another key is kept only if its type is listed. nil means
// the key has none of them; no algorithms keeps the key as it is.
func restrictHostKey(signer ssh.Signer, algorithms []string) (ssh.Signer, error) {
	if len(algorithms) == 0 {
		return signer, nil
	}
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		var allowed []string
		for _, algorithm := range algorithms {
			switch algorithm {
			case ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA:
				allowed = append(allowed, algorithm)
			}
		}
		if len(allowed) == 0 {
			return nil, nil
		}
		algorithmSigner, isAlgorithmSigner := signer.(ssh.AlgorithmSigner)
		if !isAlgorithmSigner {
			return nil, E.New("ssh: RSA host key cannot restrict its algorithms")
		}
		return ssh.NewSignerWithAlgorithms(algorithmSigner, allowed)
	}
	if common.Contains(algorithms, signer.PublicKey().Type()) {
		return signer, nil
	}
	return nil, nil
}
