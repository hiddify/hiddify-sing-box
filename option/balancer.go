package option

import "github.com/sagernet/sing/common/json/badoption"

type BalancerOutboundOptions struct {
	Outbounds                 []string           `json:"outbounds"`
	Tolerance                 uint16             `json:"tolerance,omitempty"` // accepted, not used: delay_acceptable_ratio sets what is close enough
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
	Strategy                  string             `json:"strategy,omitempty"`
	DelayAcceptableRatio      float64            `json:"delay_acceptable_ratio,omitempty"` // members within this times the fastest delay are used; 0 is 2
	TTL                       badoption.Duration `json:"ttl,omitempty"`
	MaxRetry                  int                `json:"max_retry,omitempty"` // consistent-hashing and sticky-sessions: other buckets to try before a full search
	// pool strategy (as lx's round_robin): the number of slots, 3 when 0; how much faster, in ms,
	// a member outside must be to take a slot (0 keeps the first working members); and what a
	// connection sticks to its slot by: process, domain, source_ip, dest_ip, dest_port, or none.
	Pool          int                        `json:"pool,omitempty"`           //H
	PoolTolerance uint16                     `json:"pool_tolerance,omitempty"` //H
	StickyHash    badoption.Listable[string] `json:"sticky_hash,omitempty"`    //H
}
