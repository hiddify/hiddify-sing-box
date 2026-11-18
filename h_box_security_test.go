package box_test

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// The outbound manager tells why each outbound or endpoint is not secure, from its options.
func TestH_BoxInsecureReason(t *testing.T) {
	ctx := include.Context(context.Background())
	server := option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080}
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Outbounds: []option.Outbound{
				{Type: C.TypeSOCKS, Tag: "socks", Options: &option.SOCKSOutboundOptions{ServerOptions: server}},
				{Type: C.TypeShadowsocks, Tag: "ss", Options: &option.ShadowsocksOutboundOptions{ServerOptions: server, Method: "aes-128-gcm", Password: "p"}},
				{Type: C.TypeSelector, Tag: "select", Options: &option.SelectorOutboundOptions{Outbounds: []string{"socks", "ss"}}},
			},
		},
	})
	require.NoError(t, err)
	defer instance.Close()
	require.Equal(t, C.InsecurePlaintext, adapter.InsecureReason(instance.Outbound(), "socks"))
	require.Equal(t, "", adapter.InsecureReason(instance.Outbound(), "ss"))
	require.Equal(t, "", adapter.InsecureReason(instance.Outbound(), "select"))
	require.Equal(t, "", adapter.InsecureReason(instance.Outbound(), "missing"))
}
