package option

import "github.com/sagernet/sing/common/json"

// H: FinalMaskOptions is an Xray-style finalmask ({"tcp":[...],"udp":[...]}), applied to every
// connection the dialer opens; see hiddify/finalmask for the supported mask types.
type FinalMaskOptions struct {
	TCP []FinalMaskItem `json:"tcp,omitempty"`
	UDP []FinalMaskItem `json:"udp,omitempty"`
	// QuicParams is accepted so Xray configs load unchanged; it is not used (QUIC protocols
	// have their own options in sing-box).
	QuicParams json.RawMessage `json:"quicParams,omitempty"`
}

type FinalMaskItem struct {
	Type     string          `json:"type"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

func (o *FinalMaskOptions) IsEmpty() bool {
	return o == nil || len(o.TCP) == 0 && len(o.UDP) == 0
}
