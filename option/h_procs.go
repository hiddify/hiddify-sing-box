package option

// HProcsOptions lets the number of Go processors (GOMAXPROCS) follow the load instead of being
// the number of CPU cores: one while the proxy has little to do, more while it is busy. See
// docs/hiddify/features/adaptive-processors.en.md.
type HProcsOptions struct {
	// Enabled turns it on.
	Enabled bool `json:"enabled,omitempty"`
	// Min is the least number of processors, 1 when it is 0.
	Min int `json:"min,omitempty"`
	// Max is the most, the number the runtime starts with (the CPU cores) when it is 0.
	Max int `json:"max,omitempty"`
}
