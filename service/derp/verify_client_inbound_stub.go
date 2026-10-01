//go:build with_tailscale && !with_tailcat

package derp

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/tailscale/types/key"
)

func resolveTailcatVerifyKeys(ctx context.Context, inboundTags []string) ([]key.NodePublic, error) {
	return nil, E.New("verify_client_inbound requires Tailcat, rebuild with -tags with_tailcat")
}
