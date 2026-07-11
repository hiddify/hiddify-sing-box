//go:build darwin

package libbox

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/bridge"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewBridgeService(options *adapter.BridgeOptions) (adapter.BridgeSession, error) {
	if options == nil {
		return nil, E.New("missing bridge options")
	}
	service, err := bridge.NewService(bridge.ServiceOptions{
		MTU:       int(options.MTU),
		Interface: options.Interface,
		Inet4Port: options.Inet4Port,
		Inet6Port: options.Inet6Port,
	})
	if err != nil {
		return nil, err
	}
	return &bridgeServiceSession{service}, nil
}

type bridgeServiceSession struct {
	service *bridge.Service
}

func (s *bridgeServiceSession) FileDescriptor() int {
	return s.service.FileDescriptor()
}

func (s *bridgeServiceSession) Name() string {
	return s.service.Name()
}

func (s *bridgeServiceSession) Inet6Active() bool {
	return s.service.Inet6Active()
}

func (s *bridgeServiceSession) SetEgress(interfaceName string) error {
	return s.service.SetEgress(interfaceName)
}

func (s *bridgeServiceSession) Close() error {
	return s.service.Close()
}
