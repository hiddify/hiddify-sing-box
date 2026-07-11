package option

type TLSTricksOptions struct {
	MixedCaseSNI bool   `json:"mixedcase_sni,omitempty"`
	PaddingMode  string `json:"padding_mode,omitempty"`
	PaddingSize  string `json:"padding_size,omitempty"`
	PaddingSNI   string `json:"padding_sni,omitempty"`
}
