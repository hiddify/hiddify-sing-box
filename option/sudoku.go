package option

type SudokuOutboundOptions struct {
	DialerOptions
	ServerOptions
	Key                string          `json:"key"`
	AEADMethod         string          `json:"aead_method,omitempty"`
	PaddingMin         *int            `json:"padding_min,omitempty"`
	PaddingMax         *int            `json:"padding_max,omitempty"`
	TableType          string          `json:"table_type,omitempty"`
	EnablePureDownlink *bool           `json:"enable_pure_downlink,omitempty"`
	CustomTable        string          `json:"custom_table,omitempty"`
	CustomTables       []string        `json:"custom_tables,omitempty"`
	Multiplex          string          `json:"multiplex,omitempty"`
	HTTPMask           *SudokuHTTPMask `json:"http_mask,omitempty"`
}

type SudokuHTTPMask struct {
	Enabled   bool   `json:"enabled,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Host      string `json:"host,omitempty"`
	PathRoot  string `json:"path_root,omitempty"`
	Multiplex string `json:"multiplex,omitempty"`
	OutboundTLSOptionsContainer
}

type SudokuInboundOptions struct {
	ListenOptions
	Key                string   `json:"key"`
	AEADMethod         string   `json:"aead_method,omitempty"`
	PaddingMin         *int     `json:"padding_min,omitempty"`
	PaddingMax         *int     `json:"padding_max,omitempty"`
	TableType          string   `json:"table_type,omitempty"`
	HandshakeTimeout   *int     `json:"handshake_timeout,omitempty"`
	EnablePureDownlink *bool    `json:"enable_pure_downlink,omitempty"`
	CustomTable        string   `json:"custom_table,omitempty"`
	CustomTables       []string `json:"custom_tables,omitempty"`
	DisableHTTPMask    bool     `json:"disable_http_mask,omitempty"`
	HTTPMaskMode       string   `json:"http_mask_mode,omitempty"`
	PathRoot           string   `json:"path_root,omitempty"`
	Fallback           string   `json:"fallback,omitempty"`
}
