package option

type BondInboundOptions struct {
	Inbounds []Inbound `json:"inbounds"`
}

type BondOutboundOptions struct {
	Outbounds []BondOutbound `json:"outbounds"`
}

type BondOutbound struct {
	Outbound      Outbound `json:"outbound"`
	DownloadRatio uint8    `json:"download_ratio"`
	UploadRatio   uint8    `json:"upload_ratio"`
	Count         uint8    `json:"count"`
}
