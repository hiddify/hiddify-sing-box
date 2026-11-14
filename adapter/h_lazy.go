package adapter

import E "github.com/sagernet/sing/common/exceptions"

// LazyOutbound is an outbound that keeps only its options until something needs it: the real
// outbound is created at the first connection or test, and closed again once nothing uses it.
// A profile of hundreds of proxies then costs the memory of the few in use. //H
type LazyOutbound interface {
	Outbound
	// Loaded reports whether the real outbound exists now.
	Loaded() bool
	// Acquire keeps the real outbound, once created, until the returned function is called: for
	// work of several connections, such as a URL test and the IP lookup after it. It creates
	// nothing by itself.
	Acquire() func()
	// Unload closes the real outbound now unless a connection is open through it, without
	// waiting for it to be idle for a while; a dial or a test still under way does not hold it.
	Unload()
}

// AcquireOutbound is LazyOutbound.Acquire for any outbound: nothing for one that is not lazy.
func AcquireOutbound(outbound Outbound) func() {
	if lazy, isLazy := outbound.(LazyOutbound); isLazy {
		return lazy.Acquire()
	}
	return func() {}
}

// HeldLazy is a lazy outbound or endpoint that something can hold: Hold creates the real one now,
// if it is not there, and keeps it until release, never unloaded meanwhile. For what needs the real
// one itself, as a DNS server needs its endpoint. Held while anything holds it.
type HeldLazy interface {
	LazyOutbound
	Hold() (Outbound, func(), error)
	Held() bool
}

// HoldEndpoint is the real endpoint behind endpoint, held until release: endpoint itself, with a
// release that does nothing, when it is not lazy.
func HoldEndpoint(endpoint Endpoint) (Endpoint, func(), error) {
	lazy, isLazy := endpoint.(HeldLazy)
	if !isLazy {
		return endpoint, func() {}, nil
	}
	inner, release, err := lazy.Hold()
	if err != nil {
		return nil, nil, err
	}
	real, isEndpoint := inner.(Endpoint)
	if !isEndpoint {
		release()
		return nil, nil, E.New("lazy ", endpoint.Tag(), " is not an endpoint")
	}
	return real, release, nil
}
