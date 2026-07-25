package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

type MasterDnsOptions struct {
	DialerOptions

	// ProtocolType is the local proxy protocol MasterDnsVPN's client
	// listener speaks, e.g. "socks5". Defaults to "socks5" when empty.
	ProtocolType string `json:"protocol_type,omitempty"`

	Domains   []string `json:"domains,omitempty"`
	Resolvers []string `json:"resolvers,omitempty"`

	SOCKS5Auth bool   `json:"socks5_auth,omitempty"`
	SOCKS5User string `json:"socks5_user,omitempty"`
	SOCKS5Pass string `json:"socks5_pass,omitempty"`

	EncryptionKey         string `json:"encryption_key,omitempty"`
	DataEncryptionMethod  *int   `json:"data_encryption_method,omitempty"`
	UploadCompressionType *int   `json:"upload_compression_type,omitempty"`

	PacketDuplicationCount *int `json:"packet_duplication_count,omitempty"`
	MinUploadMTU           *int `json:"min_upload_mtu,omitempty"`
	MaxUploadMTU           *int `json:"max_upload_mtu,omitempty"`

	ConnectTimeout *badoption.Duration `json:"connect_timeout,omitempty"`
}
