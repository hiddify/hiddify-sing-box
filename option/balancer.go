package option

import "github.com/sagernet/sing/common/json/badoption"

type BalancerOutboundOptions struct {
	Outbounds                 []string           `json:"outbounds"`
	Tolerance                 uint16             `json:"tolerance,omitempty"` //not implemented yet
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
	Strategy                  string             `json:"strategy,omitempty"`
	DelayAcceptableRatio      float64            `json:"delay_acceptable_ratio,omitempty"`
	TTL                       badoption.Duration `json:"ttl,omitempty"`
	MaxRetry                  int                `json:"max_retry,omitempty"` //not implemented yet
}
