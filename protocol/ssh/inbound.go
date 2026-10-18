package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/ssh"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SSHInboundOptions](registry, C.TypeSSH, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	logger       logger.ContextLogger
	listener     *listener.Listener
	serverConfig *ssh.ServerConfig
	service      Service
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SSHInboundOptions) (adapter.Inbound, error) {
	if len(options.Users) == 0 && options.Fallback == nil {
		return nil, E.New("missing users")
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeSSH, tag),
		logger:  logger,
	}
	defaultService := newService(router, logger, options.Users)
	if options.Fallback != nil {
		fallback, err := NewFallback(ctx, logger, defaultService, options.Fallback)
		if err != nil {
			return nil, err
		}
		inbound.service = fallback
	} else {
		inbound.service = defaultService
	}
	serverVersion := options.ServerVersion
	if serverVersion == "" {
		serverVersion = "SSH-2.0-OpenSSH_9.6"
	}
	serverConfig := &ssh.ServerConfig{
		ServerVersion:     serverVersion,
		MaxAuthTries:      options.MaxAuthTries,
		PasswordCallback:  inbound.service.PasswordCallback,
		PublicKeyCallback: inbound.service.PublicKeyCallback,
	}
	var hostKeys []ssh.Signer
	for _, hostKey := range options.HostKey {
		signer, err := ssh.ParsePrivateKey([]byte(hostKey))
		if err != nil {
			return nil, E.Cause(err, "parse host key")
		}
		hostKeys = append(hostKeys, signer)
	}
	for _, hostKeyPath := range options.HostKeyPath {
		content, err := os.ReadFile(os.ExpandEnv(hostKeyPath))
		if err != nil {
			return nil, E.Cause(err, "read host key ", hostKeyPath)
		}
		signer, err := ssh.ParsePrivateKey(content)
		if err != nil {
			return nil, E.Cause(err, "parse host key ", hostKeyPath)
		}
		hostKeys = append(hostKeys, signer)
	}
	if len(hostKeys) == 0 {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, E.Cause(err, "generate host key")
		}
		signer, err := ssh.NewSignerFromSigner(privateKey)
		if err != nil {
			return nil, E.Cause(err, "generate host key")
		}
		hostKeys = append(hostKeys, signer)
	}
	for _, hostKey := range hostKeys {
		serverConfig.AddHostKey(hostKey)
	}
	inbound.serverConfig = serverConfig
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(h.service.Close)
	err := h.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *Inbound) UpdateUsers(users []option.SSHUser) {
	h.service.UpdateUsers(users)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	serverConn, channels, requests, err := ssh.NewServerConn(conn, h.serverConfig)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.DebugContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
		return
	}
	var user string
	if serverConn.Permissions != nil {
		user = serverConn.Permissions.Extensions["user"]
	}
	if user == "" {
		user = serverConn.User()
	}
	if user != "" {
		metadata.User = user
	}
	go func() {
		serverConn.Wait()
		conn.Close()
	}()
	h.service.Handle(ctx, serverConn, channels, requests, metadata, user)
}
