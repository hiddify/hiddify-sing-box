// Package v2rayxdrive is the "xdrive" V2Ray transport: Xray-core's XDRIVE, which carries a
// connection in files of a storage service that the client and the server both reach. The
// transport is Xray's own; this package builds its settings from sing-box options and makes it
// dial through the sing-box dialer.
package v2rayxdrive

import (
	"maps"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	utls "github.com/refraction-networking/utls"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/xdrive"
)

// buildConfig mirrors Xray's XDriveConfig.Build (infra/conf/transport_method.go, Xray-core
// v26.10.31, Mozilla Public License 2.0); h3 is whether the TLS ALPN is ["h3"] alone.
func buildConfig(options option.V2RayXDriveOptions, h3 bool) (*xdrive.Config, error) {
	service := options.Service
	switch service {
	case "local":
	case "Google Drive":
		service = "google-drive"
		fallthrough
	case "google-drive":
		if len(options.Secrets) != 3 {
			return nil, E.New("xdrive: google-drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken")
		}
	case "template":
		if len(options.Template) == 0 {
			return nil, E.New(`xdrive: service "template" needs a "template" object`)
		}
	case "s3":
		if options.S3 == nil {
			return nil, E.New(`xdrive: service "s3" needs an "s3" object`)
		}
	case "":
		return nil, E.New(`xdrive: missing "service", use "google-drive", "template", "s3" or "local"`)
	default:
		return nil, E.New(`xdrive: unknown "service": "`, service, `", use "google-drive", "template", "s3" or "local"`)
	}
	xmux := &splithttp.XmuxConfig{}
	if options.Xmux != nil {
		if options.Xmux.MaxConnections.To > 0 && options.Xmux.MaxConcurrency.To > 0 {
			return nil, E.New("xdrive: max_connections cannot be specified together with max_concurrency")
		}
		xmux.MaxConcurrency = rangeConfig(options.Xmux.MaxConcurrency.From, options.Xmux.MaxConcurrency.To)
		xmux.MaxConnections = rangeConfig(options.Xmux.MaxConnections.From, options.Xmux.MaxConnections.To)
		xmux.CMaxReuseTimes = rangeConfig(options.Xmux.CMaxReuseTimes.From, options.Xmux.CMaxReuseTimes.To)
		xmux.HMaxRequestTimes = rangeConfig(options.Xmux.HMaxRequestTimes.From, options.Xmux.HMaxRequestTimes.To)
		xmux.HMaxReusableSecs = rangeConfig(options.Xmux.HMaxReusableSecs.From, options.Xmux.HMaxReusableSecs.To)
		xmux.HKeepAlivePeriod = options.Xmux.HKeepAlivePeriod
	} else {
		connections := int32(1)
		if service == "google-drive" && !h3 {
			// Google gives an h2 connection 1 MiB of window, which a few sessions on a long rtt
			// would share; an h3 connection has no such limit
			connections = 4
		}
		xmux.MaxConnections = rangeConfig(connections, connections)
		xmux.HMaxReusableSecs = rangeConfig(1800, 3000)
	}
	config := &xdrive.Config{
		RemoteFolder:      options.RemoteFolder,
		Service:           service,
		Secrets:           options.Secrets,
		SegmentBytes:      options.SegmentBytes,
		FlushIntervalMs:   options.FlushIntervalMs,
		PollIntervalMs:    options.PollIntervalMs,
		MaxPollIntervalMs: options.MaxPollIntervalMs,
		SessionTtlSeconds: options.SessionTTLSeconds,
		Concurrency:       options.Concurrency,
		EagerWindowMs:     options.EagerWindowMs,
		HoleTimeoutMs:     options.HoleTimeoutMs,
		Template:          string(options.Template),
		Xmux:              xmux,
	}
	if service == "s3" {
		config.S3 = &xdrive.S3Config{
			Endpoint:  options.S3.Endpoint,
			Region:    options.S3.Region,
			Bucket:    options.S3.Bucket,
			PathStyle: options.S3.PathStyle == nil || *options.S3.PathStyle,
		}
		if err := xdrive.ValidateS3Config(config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func rangeConfig(from, to int32) *splithttp.RangeConfig {
	return &splithttp.RangeConfig{From: from, To: to}
}

// xrayTLSConfig is the TLS of the requests to the storage service, from the outbound's TLS
// options: its server name, ALPN and uTLS fingerprint. Without TLS options, or without uTLS,
// Xray's defaults apply: the host of each request as server name and a Chrome fingerprint.
// The server name sing-box fills in from the outbound's own address is not used, as XDRIVE
// never connects to that address.
func xrayTLSConfig(tlsConfig tls.Config, serverAddr M.Socksaddr) *xtls.Config {
	config := &xtls.Config{}
	if tlsConfig == nil {
		return config
	}
	if serverName := tlsConfig.ServerName(); serverName != "" && serverName != serverAddr.AddrString() {
		config.ServerName = serverName
	}
	config.NextProtocol = tlsConfig.NextProtos()
	if client, version, ok := tls.UTLSHelloID(tlsConfig); ok {
		config.Fingerprint = xrayFingerprintName(client, version)
	}
	return config
}

// xrayFingerprintName finds the Xray name of a uTLS fingerprint; "" (Chrome) when Xray has none.
// The random presets are skipped, and names are tried in order so the result is stable.
func xrayFingerprintName(client, version string) string {
	for _, table := range []map[string]*utls.ClientHelloID{xtls.PresetFingerprints, xtls.ModernFingerprints, xtls.OtherFingerprints} {
		for _, name := range slices.Sorted(maps.Keys(table)) {
			if strings.HasPrefix(name, "random") {
				continue
			}
			if id := table[name]; id.Client == client && id.Version == version {
				return name
			}
		}
	}
	return ""
}

func frontingDestination(options option.V2RayXDriveOptions) *xnet.Destination {
	if options.FrontingAddress == "" {
		return nil
	}
	return &xnet.Destination{
		Network: xnet.Network_TCP,
		Address: xnet.ParseAddress(options.FrontingAddress),
		Port:    xnet.Port(options.FrontingPort),
	}
}
