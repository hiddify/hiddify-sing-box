package option

import "github.com/sagernet/sing/common/json/badoption"

type BalancerOutboundOptions struct {
	Outbounds                 []string           `json:"outbounds"`
	Tolerance                 uint16             `json:"tolerance,omitempty"`       // lowest-delay: a member takes the selection when faster by more than this many ms (0 is 50) ...
	ToleranceRatio            float64            `json:"tolerance_ratio,omitempty"` // ... and by more than this share of the selected member's delay (0 is 0.1), whichever is larger
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
	Strategy                  string             `json:"strategy,omitempty"`
	DelayAcceptableRatio      float64            `json:"delay_acceptable_ratio,omitempty"` // members within this times the fastest delay are used; 0 is 2
	TTL                       badoption.Duration `json:"ttl,omitempty"`
	MaxRetry                  int                `json:"max_retry,omitempty"` // consistent-hashing and sticky-sessions: other buckets to try before a full search
	// pool strategy (as lx's round_robin): the number of slots, 3 when 0. A member outside the
	// pool takes a slot when faster by more than tolerance and tolerance_ratio, as for
	// lowest-delay; with tolerance unset the slots keep the first working members.
	Pool int `json:"pool,omitempty"` //H
	// pool and sticky-sessions: what a connection sticks by: process, domain, source_ip, dest_ip,
	// dest_port, or none. The pool's default is process and domain, sticky-sessions' source_ip
	// and domain.
	StickyHash badoption.Listable[string] `json:"sticky_hash,omitempty"` //H
}
