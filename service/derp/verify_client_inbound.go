//go:build with_tailscale && with_tailcat

package derp

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	boxScale "github.com/sagernet/sing-box/protocol/tailscale"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/tailscale/types/key"
)

func resolveTailcatVerifyKeys(ctx context.Context, inboundTags []string) ([]key.NodePublic, error) {
	var verifyClientKeys []key.NodePublic
	inboundManager := service.FromContext[adapter.InboundManager](ctx)
	for _, inboundTag := range inboundTags {
		inbound, loaded := inboundManager.Get(inboundTag)
		if !loaded {
			return nil, E.New("verify_client_inbound: inbound not found: ", inboundTag)
		}
		tailcatInbound, isTailcat := inbound.(*boxScale.TailcatInbound)
		if !isTailcat {
			return nil, E.New("verify_client_inbound: inbound is not Tailcat: ", inboundTag)
		}
		userKeys := tailcatInbound.UserPublicKeys()
		if len(userKeys) == 0 {
			return nil, E.New("verify_client_inbound: inbound has no users: ", inboundTag)
		}
		verifyClientKeys = append(verifyClientKeys, tailcatInbound.PublicKey())
		verifyClientKeys = append(verifyClientKeys, userKeys...)
	}
	return verifyClientKeys, nil
}
