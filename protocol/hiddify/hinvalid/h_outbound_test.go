package hinvalid

import (
	"context"
	"errors"
	"syscall"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func newTestOutbound(t *testing.T, tag string, err error) *Outbound {
	out, e := New(context.Background(), nil, log.NewNOPFactory().Logger(), tag, option.HInvalidOptions{
		InvalidConfig: map[string]any{"type": "vmess"},
		Err:           err,
	})
	require.NoError(t, e)
	return out.(*Outbound)
}

func TestH_HInvalidBlocksEverything(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, "broken", errors.New("bad uuid"))
	require.Equal(t, C.TypeHInvalidConfig, out.Type())
	require.Equal(t, "broken", out.Tag())
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, out.Network())
	require.Equal(t, map[string]any{"type": "vmess"}, out.InvalidOptions.InvalidConfig)

	conn, err := out.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:443"))
	require.Nil(t, conn)
	require.ErrorIs(t, err, syscall.EPERM)

	conn, err = out.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("example.com:53"))
	require.Nil(t, conn)
	require.ErrorIs(t, err, syscall.EPERM)

	pc, err := out.ListenPacket(context.Background(), M.ParseSocksaddr("8.8.8.8:53"))
	require.Nil(t, pc)
	require.ErrorIs(t, err, syscall.EPERM)
}

func TestH_HInvalidDisplayTypeIncludesError(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, "broken", errors.New("bad uuid"))
	require.Contains(t, out.DisplayType(), "bad uuid")
}

func TestH_HInvalidDisplayTypeName(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, "broken", errors.New("bad uuid"))
	require.Equal(t, "Invalid bad uuid", out.DisplayType())
}

func TestH_HInvalidDisplayTypeNilError(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, "broken", nil)
	require.NotPanics(t, func() { _ = out.DisplayType() })
}
