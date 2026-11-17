package call

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/bitrix"
	"github.com/sagernet/sing-box/transport/call/dion"
	"github.com/sagernet/sing-box/transport/call/telemost"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing-box/transport/call/vk"
	"github.com/sagernet/sing-box/transport/call/wbstream"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type Role int

const (
	RoleCreator Role = iota
	RoleJoiner
)

type Config struct {
	Platform     string
	Mode         string
	JoinLink     string
	Cookies      string
	CookieString string
	Email        string
	Password     string
	ReadBuffer   int
	Role         Role
	// Accept takes the connections that arrive through the call. A creator needs both.
	Accept    tunnel.AcceptHandlers
	Dialer    N.Dialer
	DNSRouter adapter.DNSRouter
	Logger    logger.ContextLogger
}

// Connect joins the call and returns the bridge, which owns the session: closing it leaves the
// call. A creator's bridge is returned once its session is up, whether a peer has joined yet or
// not; a joiner's once its tunnel to the creator is.
func Connect(ctx context.Context, cfg Config) (*Bridge, error) {
	if cfg.Role == RoleCreator && (cfg.Accept.TCP == nil || cfg.Accept.UDP == nil) {
		// Hiddify: checked here, as a creator's bridge refuses what it has no handler for
		return nil, E.New("call: a creator needs accept handlers")
	}
	readBuf := cfg.ReadBuffer
	if readBuf <= 0 {
		readBuf = 32768
	}
	log := cfg.Logger
	if log == nil {
		log = logger.NOP()
	}
	cookieStr := cfg.CookieString
	if cookieStr == "" {
		cookieStr = cfg.Cookies
	}
	switch cfg.Platform {
	case "telemost":
		switch cfg.Role {
		case RoleCreator:
			leave, joinLink, err := telemost.ConnectCreator(ctx, cookieStr, cfg.JoinLink, readBuf, cfg.Dialer, cfg.Accept, log)
			if err != nil {
				return nil, err
			}
			log.Info(fmt.Sprintf("call[telemost]: join_link=%s", joinLink))
			return &Bridge{leave: leave}, nil
		case RoleJoiner:
			relay, leave, err := telemost.ConnectJoiner(ctx, cfg.JoinLink, "", readBuf, cfg.Dialer, cfg.DNSRouter, log)
			if err != nil {
				return nil, err
			}
			return &Bridge{relay: relay, leave: leave}, nil
		}
	case "wbstream":
		if err := CheckMode(cfg.Platform, cfg.Mode); err != nil { // Hiddify: an unknown mode never connected
			return nil, err
		}
		switch cfg.Role {
		case RoleCreator:
			leave, joinLink, err := wbstream.ConnectCreator(ctx, cookieStr, cfg.JoinLink, cfg.Mode, readBuf, cfg.Dialer, cfg.Accept, log)
			if err != nil {
				return nil, err
			}
			log.Info(fmt.Sprintf("call[wbstream]: join_link=%s", joinLink))
			return &Bridge{leave: leave}, nil
		case RoleJoiner:
			relay, leave, err := wbstream.ConnectJoiner(ctx, cfg.JoinLink, "", cfg.Mode, readBuf, cfg.Dialer, cfg.DNSRouter, log)
			if err != nil {
				return nil, err
			}
			return &Bridge{relay: relay, leave: leave}, nil
		}
	case "vk":
		switch cfg.Role {
		case RoleCreator:
			leave, joinLink, err := vk.ConnectCreator(ctx, cookieStr, cfg.JoinLink, readBuf, cfg.Dialer, cfg.DNSRouter, cfg.Accept, log)
			if err != nil {
				return nil, err
			}
			log.Info(fmt.Sprintf("call[vk]: join_link=%s", joinLink))
			return &Bridge{leave: leave}, nil
		case RoleJoiner:
			relay, leave, err := vk.ConnectJoiner(ctx, cfg.JoinLink, "", readBuf, cfg.Dialer, cfg.DNSRouter, log)
			if err != nil {
				return nil, err
			}
			return &Bridge{relay: relay, leave: leave}, nil
		}
	case "bitrix":
		switch cfg.Role {
		case RoleJoiner:
			relay, leave, err := bitrix.ConnectJoiner(ctx, cfg.JoinLink, "", cfg.Mode, readBuf, cfg.Dialer, log)
			if err != nil {
				return nil, err
			}
			return &Bridge{relay: relay, leave: leave}, nil
		}
	case "dion":
		switch cfg.Role {
		case RoleCreator:
			leave, joinLink, err := dion.ConnectCreator(ctx, cookieStr, cfg.JoinLink, cfg.Email, cfg.Password, readBuf, cfg.Dialer, cfg.DNSRouter, cfg.Accept, log)
			if err != nil {
				return nil, err
			}
			log.Info(fmt.Sprintf("call[dion]: join_link=%s", joinLink))
			return &Bridge{leave: leave}, nil
		case RoleJoiner:
			relay, leave, err := dion.ConnectJoiner(ctx, cfg.JoinLink, "", readBuf, cfg.Dialer, cfg.DNSRouter, log)
			if err != nil {
				return nil, err
			}
			return &Bridge{relay: relay, leave: leave}, nil
		}
	}
	return nil, E.New("call: unsupported platform ", cfg.Platform)
}

// Bridge is one side's part in a call. Hiddify: it owns the session. Close left only the first
// relay bridge: the call session, its reconnect loop and every bridge made after a reconnect
// went on until the process ended.
type Bridge struct {
	relay     *tunnel.RelayBridge // a joiner's tunnel to dial through; nil for a creator, whose connections go to Config.Accept
	leave     func()              // leaves the call and ends what was started for it
	closeOnce sync.Once
}

// NewBridge is a bridge over relay, of a session that leave ends.
func NewBridge(relay *tunnel.RelayBridge, leave func()) *Bridge {
	return &Bridge{relay: relay, leave: leave}
}

// Close leaves the call. It may be called more than once.
func (b *Bridge) Close() error {
	b.closeOnce.Do(func() {
		if b.relay != nil {
			b.relay.Close()
		}
		if b.leave != nil {
			b.leave()
		}
	})
	return nil
}

func (b *Bridge) DialContext(ctx context.Context, destination string) (net.Conn, error) {
	if b.relay == nil {
		return nil, E.New("call: a creator does not dial")
	}
	return b.relay.DialContext(ctx, destination)
}

func (b *Bridge) ListenPacket(ctx context.Context, destination string) (net.Conn, error) {
	if b.relay == nil {
		return nil, E.New("call: a creator does not dial")
	}
	return b.relay.ListenPacket(ctx, destination)
}

// CheckMode refuses a mode the platform does not have; only wbstream has modes.
func CheckMode(platform string, mode string) error {
	if platform != "wbstream" {
		return nil
	}
	switch mode {
	case "", wbstream.TunnelModeDC, wbstream.TunnelModeVideo:
		return nil
	}
	return E.New("call: unknown wbstream mode ", mode, ", use dc or video")
}
