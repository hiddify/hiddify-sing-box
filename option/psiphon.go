package option

import "github.com/sagernet/sing/common/json/badoption"

type PsiphonOutboundOptions struct {
	Network NetworkList `json:"network,omitempty"`
	DialerOptions

	DataDirectory                           string             `json:"data_directory,omitempty"`
	EgressRegion                            string             `json:"egress_region,omitempty"`
	PropagationChannelID                    string             `json:"propagation_channel_id,omitempty"`
	SponsorID                               string             `json:"sponsor_id,omitempty"`
	NetworkID                               string             `json:"network_id,omitempty"`
	ClientPlatform                          string             `json:"client_platform,omitempty"`
	ClientVersion                           string             `json:"client_version,omitempty"`
	RemoteServerListURL                     string             `json:"remote_server_list_url,omitempty"`
	RemoteServerListDownloadFilename        string             `json:"remote_server_list_download_filename,omitempty"`
	RemoteServerListSignaturePublicKey      string             `json:"remote_server_list_signature_public_key,omitempty"`
	UpstreamProxyURL                        string             `json:"upstream_proxy_url,omitempty"`
	AllowDefaultDNSResolverWithBindToDevice *bool              `json:"allow_default_dns_resolver_with_bind_to_device,omitempty"`
	EstablishTunnelTimeout                  badoption.Duration `json:"establish_tunnel_timeout,omitempty"`
}
