package adapter

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
