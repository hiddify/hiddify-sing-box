package scanner

var defaultPortLanes = map[int][]Protocol{
	9050: {ProtoSOCKS5},
	9051: {ProtoSOCKS5},

	8000: {ProtoHTTP},
	8123: {ProtoHTTP},
}

func lanesForPort(cfg Config, port int) (lanes []Protocol, needFingerprint bool) {
	if cfg.PortLanes != nil {
		if v, ok := cfg.PortLanes[port]; ok && len(v) > 0 {
			return v, false
		}
	}
	if v, ok := defaultPortLanes[port]; ok {
		return v, false
	}
	return nil, true
}
