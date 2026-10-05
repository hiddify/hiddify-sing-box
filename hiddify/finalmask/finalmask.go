// Package finalmask applies Xray-core finalmask masks (fragment, noise, header-custom, sudoku,
// salamander, xdns, ...) to the connections a sing-box dialer opens. The masks themselves are
// Xray-core's; this package parses the Xray JSON form and wraps the dialer.
package finalmask

import (
	"encoding/json"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	xfinalmask "github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

// Masks holds the built client-side masks of one dialer; a nil manager means no mask of that kind.
type Masks struct {
	TCP *xfinalmask.TcpmaskManager
	UDP *xfinalmask.UdpmaskManager
}

// Build parses and validates options; it returns nil when there is nothing to apply.
func Build(options *option.FinalMaskOptions) (*Masks, error) {
	if options.IsEmpty() {
		return nil, nil
	}
	masks := &Masks{}
	if len(options.TCP) > 0 {
		tcpmasks := make([]xfinalmask.Tcpmask, 0, len(options.TCP))
		for i, item := range options.TCP {
			config, err := buildMask(item, true)
			if err != nil {
				return nil, E.Cause(err, "final_mask.tcp[", i, "] ", item.Type)
			}
			mask, ok := config.(xfinalmask.Tcpmask)
			if !ok {
				return nil, E.New("final_mask.tcp[", i, "]: ", item.Type, " is not a tcp mask")
			}
			tcpmasks = append(tcpmasks, mask)
		}
		masks.TCP = xfinalmask.NewTcpmaskManager(tcpmasks)
	}
	if len(options.UDP) > 0 {
		udpmasks := make([]xfinalmask.Udpmask, 0, len(options.UDP))
		for i, item := range options.UDP {
			config, err := buildMask(item, false)
			if err != nil {
				return nil, E.Cause(err, "final_mask.udp[", i, "] ", item.Type)
			}
			mask, ok := config.(xfinalmask.Udpmask)
			if !ok {
				return nil, E.New("final_mask.udp[", i, "]: ", item.Type, " is not a udp mask")
			}
			udpmasks = append(udpmasks, mask)
		}
		masks.UDP = xfinalmask.NewUdpmaskManager(udpmasks)
	}
	return masks, nil
}

type buildable interface {
	Build() (proto.Message, error)
}

// newMaskConfig mirrors Xray's tcpmaskLoader / udpmaskLoader.
func newMaskConfig(maskType string, tcp bool) buildable {
	if tcp {
		switch maskType {
		case "header-custom":
			return new(HeaderCustomTCP)
		case "fragment":
			return new(FragmentMask)
		case "sudoku":
			return new(Sudoku)
		case "xmc":
			return new(XMC)
		}
		return nil
	}
	switch maskType {
	case "header-custom":
		return new(HeaderCustomUDP)
	case "mkcp-legacy":
		return new(MkcpLegacy)
	case "noise":
		return new(NoiseMask)
	case "salamander":
		return new(Salamander)
	case "sudoku":
		return new(Sudoku)
	case "xdns":
		return new(Xdns)
	case "xicmp":
		return new(Xicmp)
	case "realm":
		return new(Realm)
	}
	return nil
}

func buildMask(item option.FinalMaskItem, tcp bool) (proto.Message, error) {
	config := newMaskConfig(strings.ToLower(item.Type), tcp)
	if config == nil {
		return nil, E.New("unknown mask type")
	}
	settings := []byte(item.Settings)
	if len(settings) == 0 || string(settings) == "null" {
		settings = []byte("{}")
	}
	if err := json.Unmarshal(settings, config); err != nil {
		return nil, E.Cause(err, "parse settings")
	}
	return config.Build()
}

// realmTLSConfig is the part of Xray's tlsSettings that realm's HTTP client uses.
type realmTLSConfig struct {
	ServerName        string   `json:"serverName"`
	ALPN              []string `json:"alpn"`
	MinVersion        string   `json:"minVersion"`
	MaxVersion        string   `json:"maxVersion"`
	DisableSystemRoot bool     `json:"disableSystemRoot"`
}

func (c *realmTLSConfig) Build() *tls.Config {
	return &tls.Config{
		ServerName:        c.ServerName,
		NextProtocol:      c.ALPN,
		MinVersion:        c.MinVersion,
		MaxVersion:        c.MaxVersion,
		DisableSystemRoot: c.DisableSystemRoot,
	}
}
