package ssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service/filemanager"

	"golang.org/x/crypto/ssh"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SSHOutboundOptions](registry, C.TypeSSH, NewOutbound)
}

var (
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	ctx               context.Context
	logger            logger.ContextLogger
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	user              string
	hostKey           []ssh.PublicKey
	hostKeyAlgorithms []string
	cipher            []string
	mac               []string
	kexAlgorithm      []string
	clientVersion     string
	authMethod        []ssh.AuthMethod
	clientAccess      sync.Mutex
	clientConn        net.Conn
	client            *ssh.Client
	streams           int
	closeIdle         bool
	uotClient         *uot.Client
	// H: connection state shown in the UI and used by monitoring
	ready         atomic.Bool
	connectionErr common.TypedValue[string]
	disconnected  chan struct{}
	done          chan struct{}
	closeOnce     sync.Once
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SSHOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	outbound := &Outbound{
		Adapter:           outbound.NewAdapterWithDialerOptions(C.TypeSSH, tag, options.Network.Build(), options.DialerOptions),
		ctx:               ctx,
		logger:            logger,
		dialer:            outboundDialer,
		serverAddr:        options.ServerOptions.Build(),
		user:              options.User,
		hostKeyAlgorithms: options.HostKeyAlgorithms,
		cipher:            options.Cipher,
		mac:               options.MAC,
		kexAlgorithm:      options.KexAlgorithm,
		clientVersion:     options.ClientVersion,
		disconnected:      make(chan struct{}, 1),
		done:              make(chan struct{}),
	}
	outbound.ready.Store(false)
	if outbound.serverAddr.Port == 0 {
		outbound.serverAddr.Port = 22
	}
	if outbound.user == "" {
		outbound.user = "root"
	}
	if outbound.clientVersion == "" {
		outbound.clientVersion = randomVersion()
	}
	if options.Password != "" {
		outbound.authMethod = append(outbound.authMethod, ssh.Password(options.Password))
	}
	if len(options.PrivateKey) > 0 || options.PrivateKeyPath != "" {
		var privateKey []byte
		if len(options.PrivateKey) > 0 {
			privateKey = []byte(strings.Join(options.PrivateKey, "\n"))
		} else {
			var err error
			privateKey, err = filemanager.ReadFile(ctx, os.ExpandEnv(options.PrivateKeyPath))
			if err != nil {
				return nil, E.Cause(err, "read private key")
			}
		}
		var signer ssh.Signer
		var err error
		if options.PrivateKeyPassphrase == "" {
			signer, err = ssh.ParsePrivateKey(privateKey)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(options.PrivateKeyPassphrase))
		}
		if err != nil {
			return nil, E.Cause(err, "parse private key")
		}
		outbound.authMethod = append(outbound.authMethod, ssh.PublicKeys(signer))
	}
	if len(options.HostKey) > 0 {
		for _, hostKey := range options.HostKey {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
			if err != nil {
				return nil, E.Cause(err, "parse host key: ", hostKey)
			}
			outbound.hostKey = append(outbound.hostKey, key)
		}
	}
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		outbound.uotClient = &uot.Client{
			Dialer:  outbound,
			Version: uotOptions.Version,
		}
	}
	return outbound, nil
}

func randomVersion() string {
	version := "SSH-2.0-OpenSSH_"
	if rand.Intn(2) == 0 {
		version += "7." + strconv.Itoa(rand.Intn(10))
	} else {
		version += "8." + strconv.Itoa(rand.Intn(9))
	}
	return version
}

func (s *Outbound) connect(ctx context.Context) (client *ssh.Client, err error) {
	s.clientAccess.Lock()
	defer s.clientAccess.Unlock()

	if s.client != nil {
		return s.client, nil
	}

	defer func() { // H: the result is shown in the UI
		if err != nil {
			s.connectionErr.Store(err.Error())
		} else {
			s.connectionErr.Store("")
		}
	}()

	conn, err := s.dialer.DialContext(ctx, N.NetworkTCP, s.serverAddr)
	if err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		handshakeConn := conn
		stopContext := context.AfterFunc(ctx, func() {
			_ = handshakeConn.Close()
		})
		defer func() {
			if !stopContext() {
				s.client = nil
				s.clientConn = nil
				client = nil
				err = ctx.Err()
			}
		}()
	}
	config := &ssh.ClientConfig{
		User:              s.user,
		Auth:              s.authMethod,
		ClientVersion:     s.clientVersion,
		HostKeyAlgorithms: s.hostKeyAlgorithms,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(s.hostKey) == 0 {
				return nil
			}
			serverKey := key.Marshal()
			for _, hostKey := range s.hostKey {
				if bytes.Equal(serverKey, hostKey.Marshal()) {
					return nil
				}
			}

			return E.New("host key mismatch, server send ", key.Type(), " ", base64.StdEncoding.EncodeToString(serverKey))
		},
	}
	if len(s.cipher) > 0 {
		config.Ciphers = s.cipher
	}
	if len(s.mac) > 0 {
		config.MACs = s.mac
	}
	if len(s.kexAlgorithm) > 0 {
		config.KeyExchanges = s.kexAlgorithm
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, s.serverAddr.Addr.String(), config)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "connect to ssh server")
	}

	client = ssh.NewClient(clientConn, chans, reqs)

	s.clientConn = conn
	s.client = client
	s.streams = 0
	s.logger.InfoContext(ctx, "connected to ssh server ", s.serverAddr)
	s.ready.Store(true)

	go func() {
		client.Wait()
		conn.Close()
		s.clientAccess.Lock()
		if s.client == client {
			s.client = nil
			s.clientConn = nil
			s.ready.Store(false)
		}
		s.clientAccess.Unlock()
		select { // H: reconnect in the background
		case s.disconnected <- struct{}{}:
		default:
		}
	}()

	return client, nil
}

func (s *Outbound) PostStart() error {
	go s.keepConnected()
	return nil
}

// keepConnected connects in the background and reconnects after the connection drops, retrying
// with a growing delay, so the outbound becomes ready (and gets tested) without waiting for
// traffic; monitoring skips it while it is not ready.
//
// An idle close is not a drop. The URL test opens two channels and the second one does not
// keep the session, so releaseStream closes an unreferenced connection. Reconnecting here
// would test again and close again, which is a loop of SSH handshakes and probes. //H
func (s *Outbound) keepConnected() {
	const (
		minRetryDelay = time.Second
		maxRetryDelay = time.Minute
	)
	delay := minRetryDelay
	for {
		if !s.holdingConnection() && !s.IsReady() {
			if !s.waitSignal(0) {
				return
			}
			continue
		}
		if !s.IsReady() {
			if _, err := s.connect(s.ctx); err != nil {
				s.logger.Debug("connect to ssh server: ", err, ", retry in ", delay)
				if !s.waitSignal(delay) {
					return
				}
				delay = min(delay*2, maxRetryDelay)
				continue
			}
			delay = minRetryDelay
			if !s.holdingConnection() {
				s.CloseIdleConnections()
				continue
			}
			if monitor := monitoring.Get(s.ctx); monitor != nil {
				monitor.TestNow(s.Tag())
			}
		}
		if !s.waitSignal(0) {
			return
		}
	}
}

// holdingConnection reports whether this outbound should keep its SSH session open.
func (s *Outbound) holdingConnection() bool {
	s.clientAccess.Lock()
	hold := !s.closeIdle
	s.clientAccess.Unlock()
	return hold
}

// waitSignal waits for the session to drop, for idle-keeping to change, or for shutdown.
// A positive delay also returns when that time elapses. false means the outbound is closing.
func (s *Outbound) waitSignal(delay time.Duration) bool {
	var timer <-chan time.Time
	if delay > 0 {
		timer = time.After(delay)
	}
	select {
	case <-timer:
		return true
	case <-s.disconnected:
		return true
	case <-s.done:
		return false
	case <-s.ctx.Done():
		return false
	}
}

func (s *Outbound) InterfaceUpdated(ctx context.Context) {
	s.clientAccess.Lock()
	clientConn := s.clientConn
	s.clientAccess.Unlock()
	common.Close(clientConn) // the background loop reconnects
}

func (s *Outbound) MultiplexEnabled() bool {
	return true
}

func (s *Outbound) SetKeepIdleConnections(keep bool) {
	s.clientAccess.Lock()
	s.closeIdle = !keep
	s.clientAccess.Unlock()
	if !keep {
		s.CloseIdleConnections()
	}
	select { // wake keepConnected so it connects again, or stops retrying
	case s.disconnected <- struct{}{}:
	default:
	}
}

func (s *Outbound) CloseIdleConnections() {
	s.clientAccess.Lock()
	if s.client == nil || s.streams > 0 {
		s.clientAccess.Unlock()
		return
	}
	clientConn := s.clientConn
	s.clientAccess.Unlock()
	common.Close(clientConn)
}

func (s *Outbound) releaseStream(client *ssh.Client, keepSession bool) {
	s.clientAccess.Lock()
	if s.client != client {
		s.clientAccess.Unlock()
		return
	}
	s.streams--
	if !s.closeIdle || keepSession || s.streams > 0 {
		s.clientAccess.Unlock()
		return
	}
	clientConn := s.clientConn
	s.clientAccess.Unlock()
	common.Close(clientConn)
}

func (s *Outbound) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	s.clientAccess.Lock()
	clientConn := s.clientConn
	s.clientAccess.Unlock()
	return common.Close(clientConn)
}

func (s *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = s.Tag()
	metadata.Destination = destination
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	s.clientAccess.Lock()
	if s.client == client {
		s.streams++
	}
	s.clientAccess.Unlock()

	switch N.NetworkName(network) {

	case N.NetworkTCP:
		s.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		if s.uotClient != nil {
			s.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
			return s.uotClient.DialContext(ctx, network, destination)
		} else {
			s.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
	}
	conn, err := client.Dial(network, destination.String())
	if err != nil {
		s.releaseStream(client, false)
		return nil, err
	}
	keepSession := adapter.KeepSessionFromContext(ctx)
	return &chanConnWrapper{Conn: conn, onClose: func() { s.releaseStream(client, keepSession) }}, nil
}

func (s *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = s.Tag()
	metadata.Destination = destination
	if s.uotClient != nil {
		s.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return s.uotClient.ListenPacket(ctx, destination)
	} else {
		s.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}

	return nil, os.ErrInvalid
}

type chanConnWrapper struct {
	net.Conn
	closeOnce sync.Once
	onClose   func()
}

func (c *chanConnWrapper) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(c.onClose)
	return err
}

func (c *chanConnWrapper) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *chanConnWrapper) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *chanConnWrapper) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (s *Outbound) IsReady() bool {
	return s.ready.Load()
}

// ProxyDisplayName is the protocol name, with the connection state while not connected.
func (s *Outbound) DisplayType() string {
	name := C.ProxyDisplayName(s.Type())
	if s.IsReady() {
		return name
	}
	if connectionErr := s.connectionErr.Load(); connectionErr != "" {
		return name + " ❌ " + connectionErr
	}
	return name + " ⚠️ Connecting..."
}
