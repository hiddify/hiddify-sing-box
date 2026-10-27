package option

// MigrateTLSFragment moves a tls_fragment written inside an outbound's tls block, as old editor
// templates do, to its dialer options, where it takes effect; the dialer's own tls_fragment wins.
func MigrateTLSFragment(options any) {
	tlsWrapper, hasTLS := options.(OutboundTLSOptionsWrapper)
	dialerWrapper, hasDialer := options.(DialerOptionsWrapper)
	if !hasTLS || !hasDialer {
		return
	}
	tlsOptions := tlsWrapper.TakeOutboundTLSOptions()
	if tlsOptions == nil || tlsOptions.TLSFragment == nil || !tlsOptions.TLSFragment.Enabled {
		return
	}
	dialerOptions := dialerWrapper.TakeDialerOptions()
	if dialerOptions.TLSFragment.Enabled {
		return
	}
	dialerOptions.TLSFragment = *tlsOptions.TLSFragment
	dialerWrapper.ReplaceDialerOptions(dialerOptions)
}
