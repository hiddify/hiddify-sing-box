//go:build with_kcp

package v2raykcp

import "github.com/sagernet/sing-box/transport/v2ray"

func init() {
	v2ray.RegisterKCPConstructor(NewServer, NewClient)
}
