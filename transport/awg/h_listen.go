package awg

import (
	"context"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	N "github.com/sagernet/sing/common/network"
)

// newDeviceBind is the bind of a device. A server (opts.ListenPort) has the standard bind, which
// listens on its port: the bind of the outbound's dialer handed the port to the dialer as a
// destination, and the dialer listens on a port of its own, so no peer reached the server. Any
// other device dials through the dialer, the endpoint's detour among them.
func newDeviceBind(ctx context.Context, dial N.Dialer, opts DeviceOpts) conn.Bind {
	if opts.ListenPort != 0 {
		return conn.NewStdNetBind()
	}
	bind := newBind(ctx, dial, opts.Peer, opts.Reserved).(*bind_adapter)
	bind.pending = opts.PeerPending && !opts.Peer.IsValid()
	return bind
}
