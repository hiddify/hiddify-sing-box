package box_test

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func brokenVLESSOutbound(tag string) option.Outbound {
	return option.Outbound{
		Type: C.TypeVLESS,
		Tag:  tag,
		Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
			UUID:          "b831381d-6324-4d53-ad4f-8cda48b30811",
			Flow:          "xtls-rprx-vision-udp443",
		},
	}
}

func TestHInvalidOutboundDoesNotBlock(t *testing.T) {
	ctx := include.Context(context.Background())
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Outbounds: []option.Outbound{
				brokenVLESSOutbound("broken"),
				{
					Type:    C.TypeSOCKS,
					Tag:     "good",
					Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080}},
				},
			},
		},
	})
	require.NoError(t, err)
	defer instance.Close()
	broken, loaded := instance.Outbound().Outbound("broken")
	require.True(t, loaded)
	require.Equal(t, C.TypeHInvalidConfig, broken.Type())
	good, loaded := instance.Outbound().Outbound("good")
	require.True(t, loaded)
	require.Equal(t, C.TypeSOCKS, good.Type())
}

func TestHInvalidOutboundAllInvalidFailsWithTag(t *testing.T) {
	ctx := include.Context(context.Background())
	_, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Outbounds: []option.Outbound{brokenVLESSOutbound("my-vless")},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "outbound/vless[my-vless]")
	require.Contains(t, err.Error(), "unsupported flow")
}

func TestHInvalidOutboundOnlyGroupsLeftFails(t *testing.T) {
	ctx := include.Context(context.Background())
	_, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Outbounds: []option.Outbound{
				brokenVLESSOutbound("my-vless"),
				{Type: C.TypeDirect, Tag: "direct"},
				{Type: C.TypeBlock, Tag: "block"},
				{Type: C.TypeSelector, Tag: "select", Options: &option.SelectorOutboundOptions{Outbounds: []string{"my-vless", "direct"}}},
			},
		},
	})
	require.ErrorContains(t, err, "outbound/vless[my-vless]")
}
