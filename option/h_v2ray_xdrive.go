package option

import (
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// V2RayXDriveOptions configures the "xdrive" V2Ray transport, Xray-core's XDRIVE: the connection
// is carried in files of a storage service (Google Drive, S3, a "template" of HTTP requests, or a
// local folder) that the client and the server both reach, so no packet goes to the server. The
// fields are those of Xray's xdriveSettings.
type V2RayXDriveOptions struct {
	Service           string                     `json:"service,omitempty"` // google-drive, s3, template or local
	RemoteFolder      string                     `json:"remote_folder,omitempty"`
	Secrets           badoption.Listable[string] `json:"secrets,omitempty"`
	SegmentBytes      uint32                     `json:"segment_bytes,omitempty"`
	FlushIntervalMs   uint32                     `json:"flush_interval_ms,omitempty"`
	PollIntervalMs    uint32                     `json:"poll_interval_ms,omitempty"`
	MaxPollIntervalMs uint32                     `json:"max_poll_interval_ms,omitempty"`
	SessionTTLSeconds uint32                     `json:"session_ttl_seconds,omitempty"`
	Concurrency       uint32                     `json:"concurrency,omitempty"`
	EagerWindowMs     uint32                     `json:"eager_window_ms,omitempty"`
	HoleTimeoutMs     uint32                     `json:"hole_timeout_ms,omitempty"`
	Template          json.RawMessage            `json:"template,omitempty"`
	S3                *V2RayXDriveS3Options      `json:"s3,omitempty"`
	Xmux              *V2RayXHTTPXmuxOptions     `json:"xmux,omitempty"`
	// FrontingAddress and FrontingPort, when set, are dialed for every host of the service
	// instead of its own address, with the TLS server name still that host (Xray's
	// streamSettings "address" and "port").
	FrontingAddress string `json:"fronting_address,omitempty"`
	FrontingPort    uint16 `json:"fronting_port,omitempty"`
}

type V2RayXDriveS3Options struct {
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	PathStyle *bool  `json:"path_style,omitempty"`
}
