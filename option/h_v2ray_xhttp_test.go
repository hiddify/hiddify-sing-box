package option

import (
	"context"
	"testing"

	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func hUnmarshalTransport(t *testing.T, content string) (V2RayTransportOptions, error) {
	t.Helper()
	var options V2RayTransportOptions
	err := json.UnmarshalContext(context.Background(), []byte(content), &options)
	return options, err
}

func TestH_V2RayTransportXHTTPDefaults(t *testing.T) {
	t.Parallel()
	options, err := hUnmarshalTransport(t, `{"type":"xhttp","host":"example.com","path":"/p","x_padding_bytes":"100-1000"}`)
	require.NoError(t, err)
	require.Equal(t, C.V2RayTransportTypeXHTTP, options.Type)
	xhttp := options.XHTTPOptions
	require.Equal(t, "auto", xhttp.Mode)
	require.Equal(t, "example.com", xhttp.Host)
	require.Equal(t, Xbadoption.Range{From: 100, To: 1000}, xhttp.XPaddingBytes)
	require.Equal(t, "x_padding", xhttp.XPaddingKey)
	require.Equal(t, "X-Padding", xhttp.XPaddingHeader)
	require.Equal(t, PlacementQueryInHeader, xhttp.XPaddingPlacement)
	require.Equal(t, "repeat-x", xhttp.XPaddingMethod)
	require.Equal(t, PlacementBody, xhttp.UplinkDataPlacement)
	require.Equal(t, "POST", xhttp.UplinkHTTPMethod)
	require.Equal(t, PlacementPath, xhttp.SessionPlacement)
	require.Equal(t, PlacementPath, xhttp.SeqPlacement)
	require.Empty(t, xhttp.SessionKey)
	require.Empty(t, xhttp.SeqKey)
	require.Empty(t, xhttp.UplinkDataKey)
	require.Zero(t, xhttp.UplinkChunkSize)
	require.NotNil(t, xhttp.Xmux)
	require.Equal(t, Xbadoption.Range{From: 1, To: 1}, xhttp.Xmux.MaxConcurrency)
	require.Equal(t, Xbadoption.Range{From: 600, To: 900}, xhttp.Xmux.HMaxRequestTimes)
	require.Equal(t, Xbadoption.Range{From: 1800, To: 3000}, xhttp.Xmux.HMaxReusableSecs)
	require.Nil(t, xhttp.Download)
}

func TestH_V2RayTransportXHTTPMissingPadding(t *testing.T) {
	t.Skip("BUG: minimal xhttp transport without x_padding_bytes is rejected ('xPaddingBytes cannot be disabled'); Xray only rejects explicit non-positive values, and GetNormalizedXPaddingBytes' 100-1000 default is unreachable (option/v2ray_transport.go:229)")
	t.Parallel()
	_, err := hUnmarshalTransport(t, `{"type":"xhttp"}`)
	require.NoError(t, err)
}

func TestH_V2RayTransportXHTTPPlacementKeys(t *testing.T) {
	t.Parallel()
	options, err := hUnmarshalTransport(t, `{
		"type":"xhttp","mode":"packet-up","x_padding_bytes":"10-20",
		"session_placement":"header","seq_placement":"query",
		"uplink_data_placement":"cookie","uplink_http_method":"get",
		"x_padding_placement":"cookie","x_padding_method":"tokenish"
	}`)
	require.NoError(t, err)
	xhttp := options.XHTTPOptions
	require.Equal(t, "packet-up", xhttp.Mode)
	require.Equal(t, "GET", xhttp.UplinkHTTPMethod)
	require.Equal(t, "X-Session", xhttp.SessionKey)
	require.Equal(t, "x_seq", xhttp.SeqKey)
	require.Equal(t, "x_data", xhttp.UplinkDataKey)
	require.Equal(t, uint32(3*1024), xhttp.UplinkChunkSize)
	require.Equal(t, "X-Session", xhttp.GetNormalizedSessionKey())
	require.Equal(t, "x_seq", xhttp.GetNormalizedSeqKey())

	options, err = hUnmarshalTransport(t, `{
		"type":"xhttp","mode":"packet-up","x_padding_bytes":5,
		"session_placement":"cookie","seq_placement":"header",
		"uplink_data_placement":"header","uplink_chunk_size":10
	}`)
	require.NoError(t, err)
	xhttp = options.XHTTPOptions
	require.Equal(t, Xbadoption.Range{From: 5, To: 5}, xhttp.XPaddingBytes)
	require.Equal(t, "x_session", xhttp.SessionKey)
	require.Equal(t, "X-Seq", xhttp.SeqKey)
	require.Equal(t, "X-Data", xhttp.UplinkDataKey)
	require.Equal(t, uint32(64), xhttp.UplinkChunkSize)

	options, err = hUnmarshalTransport(t, `{"type":"xhttp","mode":"packet-up","x_padding_bytes":"1-2","uplink_data_placement":"header"}`)
	require.NoError(t, err)
	require.Equal(t, uint32(4*1024), options.XHTTPOptions.UplinkChunkSize)

	options, err = hUnmarshalTransport(t, `{"type":"xhttp","x_padding_bytes":"1-2","session_key":"sid","session_placement":"query"}`)
	require.NoError(t, err)
	require.Equal(t, "sid", options.XHTTPOptions.SessionKey)
}

func TestH_V2RayTransportXHTTPInvalid(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"bad-mode":               `{"type":"xhttp","mode":"bogus","x_padding_bytes":"1-2"}`,
		"padding-zero":           `{"type":"xhttp","x_padding_bytes":"0-10"}`,
		"padding-negative":       `{"type":"xhttp","x_padding_bytes":{"from":-1,"to":5}}`,
		"padding-reversed":       `{"type":"xhttp","x_padding_bytes":"10-1"}`,
		"padding-not-number":     `{"type":"xhttp","x_padding_bytes":"a-b"}`,
		"host-header":            `{"type":"xhttp","x_padding_bytes":"1-2","headers":{"Host":"x"}}`,
		"padding-placement":      `{"type":"xhttp","x_padding_bytes":"1-2","x_padding_placement":"body"}`,
		"padding-method":         `{"type":"xhttp","x_padding_bytes":"1-2","x_padding_method":"zero"}`,
		"uplink-placement":       `{"type":"xhttp","x_padding_bytes":"1-2","uplink_data_placement":"query"}`,
		"uplink-header-not-pkt":  `{"type":"xhttp","mode":"stream-up","x_padding_bytes":"1-2","uplink_data_placement":"header"}`,
		"get-not-packet-up":      `{"type":"xhttp","mode":"stream-one","x_padding_bytes":"1-2","uplink_http_method":"GET"}`,
		"session-placement":      `{"type":"xhttp","x_padding_bytes":"1-2","session_placement":"body"}`,
		"seq-placement":          `{"type":"xhttp","x_padding_bytes":"1-2","seq_placement":"body"}`,
		"seq-with-session-path":  `{"type":"xhttp","x_padding_bytes":"1-2","seq_placement":"header"}`,
		"xmux-conflict":          `{"type":"xhttp","x_padding_bytes":"1-2","xmux":{"max_connections":"1-2","max_concurrency":"1-2"}}`,
		"download-padding":       `{"type":"xhttp","x_padding_bytes":"1-2","download":{"x_padding_bytes":"0"}}`,
		"download-host-header":   `{"type":"xhttp","x_padding_bytes":"1-2","download":{"x_padding_bytes":"1-2","headers":{"host":"x"}}}`,
		"unknown-transport-type": `{"type":"bogus"}`,
	}
	for name, content := range cases {
		_, err := hUnmarshalTransport(t, content)
		require.Error(t, err, name)
	}
}

func TestH_V2RayTransportXHTTPDownload(t *testing.T) {
	t.Parallel()
	options, err := hUnmarshalTransport(t, `{
		"type":"xhttp","mode":"stream-up","x_padding_bytes":"1-2",
		"download":{"x_padding_bytes":"3-4","path":"/down","server":"dl.example.com","server_port":8443,"detour":"direct"}
	}`)
	require.NoError(t, err)
	download := options.XHTTPOptions.Download
	require.NotNil(t, download)
	require.Equal(t, "/down", download.Path)
	require.Equal(t, "dl.example.com", download.Server)
	require.Equal(t, uint16(8443), download.ServerPort)
	require.Equal(t, "direct", download.Detour)
	require.Equal(t, Xbadoption.Range{From: 3, To: 4}, download.XPaddingBytes)
	require.Equal(t, "x_padding", download.XPaddingKey)
	require.NotNil(t, download.Xmux)
}

func TestH_V2RayTransportXHTTPRoundTrip(t *testing.T) {
	t.Parallel()
	options, err := hUnmarshalTransport(t, `{"type":"xhttp","mode":"stream-one","path":"/a?b=c","x_padding_bytes":"7-9","sc_max_each_post_bytes":"100-200"}`)
	require.NoError(t, err)
	content, err := json.Marshal(options)
	require.NoError(t, err)
	decoded, err := hUnmarshalTransport(t, string(content))
	require.NoError(t, err)
	require.Equal(t, options, decoded)
	require.Contains(t, string(content), `"type":"xhttp"`)
	require.Contains(t, string(content), `"x_padding_bytes":"7-9"`)
}

func TestH_V2RayXHTTPNormalizers(t *testing.T) {
	t.Parallel()
	var empty V2RayXHTTPBaseOptions
	require.Equal(t, "/", empty.GetNormalizedPath())
	require.Equal(t, "", empty.GetNormalizedQuery())
	require.Equal(t, Xbadoption.Range{From: 100, To: 1000}, empty.GetNormalizedXPaddingBytes())
	require.Equal(t, "POST", empty.GetNormalizedUplinkHTTPMethod())
	require.Equal(t, Xbadoption.Range{From: 1000000, To: 1000000}, empty.GetNormalizedScMaxEachPostBytes())
	require.Equal(t, Xbadoption.Range{From: 30, To: 30}, empty.GetNormalizedScMinPostsIntervalMs())
	require.Equal(t, 30, empty.GetNormalizedScMaxBufferedPosts())
	require.Equal(t, Xbadoption.Range{From: 20, To: 80}, empty.GetNormalizedScStreamUpServerSecs())
	require.Equal(t, PlacementPath, empty.GetNormalizedSessionPlacement())
	require.Equal(t, PlacementPath, empty.GetNormalizedSeqPlacement())
	require.Equal(t, PlacementBody, empty.GetNormalizedUplinkDataPlacement())
	require.Empty(t, empty.GetNormalizedSessionKey())
	require.Empty(t, empty.GetNormalizedSeqKey())
	require.NotEmpty(t, empty.GetRequestHeader().Get("User-Agent"))

	custom := V2RayXHTTPBaseOptions{
		Path:                 "api/v1?token=abc&x=1",
		Headers:              map[string]string{"User-Agent": "custom", "X-Test": "1"},
		XPaddingBytes:        Xbadoption.Range{From: 1, To: 2},
		UplinkHTTPMethod:     "PUT",
		ScMaxEachPostBytes:   Xbadoption.Range{From: 3, To: 4},
		ScMinPostsIntervalMs: Xbadoption.Range{From: 5, To: 6},
		ScMaxBufferedPosts:   7,
		ScStreamUpServerSecs: Xbadoption.Range{From: 8, To: 9},
		SessionPlacement:     PlacementCookie,
		SeqPlacement:         PlacementHeader,
		UplinkDataPlacement:  PlacementHeader,
	}
	require.Equal(t, "/api/v1/", custom.GetNormalizedPath())
	require.Equal(t, "token=abc&x=1", custom.GetNormalizedQuery())
	require.Equal(t, Xbadoption.Range{From: 1, To: 2}, custom.GetNormalizedXPaddingBytes())
	require.Equal(t, "PUT", custom.GetNormalizedUplinkHTTPMethod())
	require.Equal(t, Xbadoption.Range{From: 3, To: 4}, custom.GetNormalizedScMaxEachPostBytes())
	require.Equal(t, Xbadoption.Range{From: 5, To: 6}, custom.GetNormalizedScMinPostsIntervalMs())
	require.Equal(t, 7, custom.GetNormalizedScMaxBufferedPosts())
	require.Equal(t, Xbadoption.Range{From: 8, To: 9}, custom.GetNormalizedScStreamUpServerSecs())
	require.Equal(t, "x_session", custom.GetNormalizedSessionKey())
	require.Equal(t, "X-Seq", custom.GetNormalizedSeqKey())
	require.Equal(t, PlacementHeader, custom.GetNormalizedUplinkDataPlacement())
	header := custom.GetRequestHeader()
	require.Equal(t, "custom", header.Get("User-Agent"))
	require.Equal(t, "1", header.Get("X-Test"))

	require.Equal(t, "/already/", (&V2RayXHTTPBaseOptions{Path: "/already/"}).GetNormalizedPath())
	require.Equal(t, "X-Session", (&V2RayXHTTPBaseOptions{SessionPlacement: PlacementHeader}).GetNormalizedSessionKey())
	require.Equal(t, "x_seq", (&V2RayXHTTPBaseOptions{SeqPlacement: PlacementQuery}).GetNormalizedSeqKey())
	require.Equal(t, "k", (&V2RayXHTTPBaseOptions{SeqKey: "k"}).GetNormalizedSeqKey())

	xmux := &V2RayXHTTPXmuxOptions{
		MaxConcurrency:   Xbadoption.Range{From: 1, To: 2},
		MaxConnections:   Xbadoption.Range{From: 3, To: 4},
		CMaxReuseTimes:   Xbadoption.Range{From: 5, To: 6},
		HMaxRequestTimes: Xbadoption.Range{From: 7, To: 8},
		HMaxReusableSecs: Xbadoption.Range{From: 9, To: 10},
	}
	require.Equal(t, xmux.MaxConcurrency, xmux.GetNormalizedMaxConcurrency())
	require.Equal(t, xmux.MaxConnections, xmux.GetNormalizedMaxConnections())
	require.Equal(t, xmux.CMaxReuseTimes, xmux.GetNormalizedCMaxReuseTimes())
	require.Equal(t, xmux.HMaxRequestTimes, xmux.GetNormalizedHMaxRequestTimes())
	require.Equal(t, xmux.HMaxReusableSecs, xmux.GetNormalizedHMaxReusableSecs())
}

func TestH_V2RayTransportRawAndHTTPVersion(t *testing.T) {
	t.Parallel()
	options, err := hUnmarshalTransport(t, `{"type":"raw"}`)
	require.NoError(t, err)
	require.Equal(t, C.V2RayTransportTypeRaw, options.Type)
	content, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, `{"type":"raw"}`, string(content))
	_, err = hUnmarshalTransport(t, `{"type":"raw","path":"/x"}`)
	require.Error(t, err)

	options, err = hUnmarshalTransport(t, `{"type":"http","host":"a.example","version":1}`)
	require.NoError(t, err)
	require.Equal(t, 1, options.HTTPOptions.Version)
	content, err = json.Marshal(options)
	require.NoError(t, err)
	require.Contains(t, string(content), `"version":1`)

	_, err = json.Marshal(V2RayTransportOptions{})
	require.ErrorContains(t, err, "missing transport type")
	_, err = json.Marshal(V2RayTransportOptions{Type: "bogus"})
	require.ErrorContains(t, err, "unknown transport type")
}
