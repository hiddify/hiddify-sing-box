package option

// HLazyOptions are the options of the outbound that stands for a lazy one (an outbound with
// "lazy": true): the type and options the real outbound is created from when a connection or a
// test first needs it. They are never written in a config; the box builds them.
type HLazyOptions struct {
	// Type is the type of the real outbound.
	Type string `json:"-"`
	// Options are the options of the real outbound.
	Options any `json:"-"`
	// Dependencies are the tags the real outbound dials through (its detours).
	Dependencies []string `json:"-"`
}
