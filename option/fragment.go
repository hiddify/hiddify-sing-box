package option

// H: TLSFragmentOptions is the dialer's tls_fragment, applied as a finalmask fragment mask.
type TLSFragmentOptions struct {
	Enabled bool   `json:"enabled,omitempty"`
	Size    string `json:"size,omitempty"`   // Fragment size in Bytes
	Sleep   string `json:"sleep,omitempty"`  // Time to sleep between sending the fragments in milliseconds
	Method  string `json:"method,omitempty"` // Whether to fragment only the ClientHello or a range of packets: "tlsHello" (default) or "range"
	Range   string `json:"range,omitempty"`  // Packets to fragment with the range method, such as "1-3"
}
