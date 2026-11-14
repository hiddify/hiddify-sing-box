package xhttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/buf"
	Xbadoption "github.com/sagernet/sing-box/common/xray/json/badoption"
	"github.com/sagernet/sing-box/common/xray/net"
	"github.com/sagernet/sing-box/common/xray/pipe"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	"github.com/sagernet/sing-box/common/xray/uuid"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/http2"
)

type Client struct {
	ctx             context.Context
	options         *option.V2RayXHTTPOptions
	baseRequestURL  url.URL
	baseRequestURL2 url.URL
	getHTTPClient   func() (DialerClient, *XmuxClient)
	getHTTPClient2  func() (DialerClient, *XmuxClient)
	xmuxManagers    []*XmuxManager //H: closed with the client
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if options.Mode == "" || options.Mode == "auto" {
		options.Mode = autoMode(tls.IsReality(tlsConfig), options.Download != nil)
	}
	tlsConfig = hDefaultALPN(tlsConfig) //H
	dest := serverAddr
	baseRequestURL, err := getBaseRequestURL(&options.V2RayXHTTPBaseOptions, dest, tlsConfig)
	if err != nil {
		return nil, err
	}
	var xmuxOptions option.V2RayXHTTPXmuxOptions
	if options.Xmux != nil {
		xmuxOptions = *options.Xmux
	}
	xmuxManager := NewXmuxManager(xmuxOptions, func() XmuxConn {
		return createHTTPClient(dest, dialer, &options.V2RayXHTTPBaseOptions, tlsConfig)
	})
	getHTTPClient := func() (DialerClient, *XmuxClient) {
		xmuxClient := xmuxManager.GetXmuxClient(ctx)
		return xmuxClient.XmuxConn.(DialerClient), xmuxClient
	}
	baseRequestURL2 := baseRequestURL
	getHTTPClient2 := getHTTPClient
	xmuxManagers := []*XmuxManager{xmuxManager} //H
	if options.Download != nil {
		options2 := options.Download
		dialer2 := dialer
		if options2.Detour != "" {
			var ok bool
			dialer2, ok = service.FromContext[adapter.OutboundManager](ctx).Outbound(options2.Detour)
			if !ok {
				return nil, E.New("outbound detour not found: ", options2.Detour)
			}
		}
		dest2 := options2.ServerOptions.Build()
		var tlsConfig2 tls.Config
		if options2.TLS != nil {
			tlsConfig2, err = tls.NewClient(ctx, logger.NOP(), options2.Server, common.PtrValueOrDefault(options2.TLS))
			if err != nil {
				return nil, err
			}
			tlsConfig2 = hDefaultALPN(tlsConfig2) //H
		}
		baseRequestURL2, err = getBaseRequestURL(&options2.V2RayXHTTPBaseOptions, dest2, tlsConfig2)
		if err != nil {
			return nil, err
		}
		var xmuxOptions2 option.V2RayXHTTPXmuxOptions
		if options2.Xmux != nil {
			xmuxOptions2 = *options2.Xmux
		}
		xmuxManager2 := NewXmuxManager(xmuxOptions2, func() XmuxConn {
			return createHTTPClient(dest2, dialer2, &options2.V2RayXHTTPBaseOptions, tlsConfig2)
		})
		getHTTPClient2 = func() (DialerClient, *XmuxClient) {
			xmuxClient2 := xmuxManager2.GetXmuxClient(ctx)
			return xmuxClient2.XmuxConn.(DialerClient), xmuxClient2
		}
		xmuxManagers = append(xmuxManagers, xmuxManager2) //H
	}
	return &Client{
		ctx:             ctx,
		options:         &options,
		getHTTPClient:   getHTTPClient,
		getHTTPClient2:  getHTTPClient2,
		baseRequestURL:  baseRequestURL,
		baseRequestURL2: baseRequestURL2,
		xmuxManagers:    xmuxManagers, //H
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	options := c.options
	mode := c.options.Mode
	sessionId := ""
	if c.options.Mode != "stream-one" {
		sessionIdUuid := uuid.New()
		sessionId = sessionIdUuid.String()
	}
	requestURL := c.baseRequestURL
	requestURL2 := c.baseRequestURL2
	httpClient, xmuxClient := c.getHTTPClient()
	httpClient2, xmuxClient2 := c.getHTTPClient2()
	if xmuxClient != nil {
		xmuxClient.AddRunning()
	}
	if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
		xmuxClient2.AddRunning()
	}
	var closed atomic.Int32
	reader, writer := io.Pipe()
	conn := splitConn{
		writer: writer,
		onClose: func() {
			if closed.Add(1) > 1 {
				return
			}
			if xmuxClient != nil {
				xmuxClient.DoneRunning()
			}
			if xmuxClient2 != nil && xmuxClient2 != xmuxClient {
				xmuxClient2.DoneRunning()
			}
		},
	}
	fail := func(err error) (net.Conn, error) { //H: a failed dial releases what it took
		conn.Close()    //H
		return nil, err //H
	} //H
	var err error
	if mode == "stream-one" {
		requestURL.Path = options.GetNormalizedPath()
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient.OpenStream(ctx, requestURL.String(), sessionId, reader, false)
		if err != nil { // browser dialer only
			return fail(err) //H
		}
		return &conn, nil
	} else { // stream-down
		if mode == "packet-up" { //H: the first upload's connection is dialled while the download's is
			hWarmUpload(ctx, httpClient) //H
		} //H
		if xmuxClient2 != nil {
			xmuxClient2.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient2.OpenStream(ctx, requestURL2.String(), sessionId, nil, false)
		if err != nil { // browser dialer only
			return fail(err) //H
		}
	}
	if mode == "stream-up" {
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		_, _, _, err = httpClient.OpenStream(ctx, requestURL.String(), sessionId, reader, true)
		if err != nil { // browser dialer only
			return fail(err) //H
		}
		return &conn, nil
	}
	scMaxEachPostBytes := hMinScMaxEachPostBytes(options.GetNormalizedScMaxEachPostBytes()) //H: was a panic that took the whole app down
	scMinPostsIntervalMs := options.GetNormalizedScMinPostsIntervalMs()
	maxUploadSize := scMaxEachPostBytes.Rand()
	// WithSizeLimit(0) will still allow single bytes to pass, and a lot of
	// code relies on this behavior. Subtract 1 so that together with
	// uploadWriter wrapper, exact size limits can be enforced
	// uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - 1))
	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - buf.Size))
	conn.writer = uploadWriter{
		uploadPipeWriter,
		maxUploadSize,
	}
	ctx = context.WithoutCancel(ctx) //H: the uploads belong to the conn, which outlives the dial context
	go func() {
		var seq int64
		var lastWrite time.Time
		// the client the uploads go to: the conn's own until its requests are used up, then others,
		// which are not the conn's to release when it closes
		dynamicHTTPClient := httpClient
		dynamicXmuxClient := xmuxClient
		defer func() { //H: a client taken for the uploads is given back when they end
			if dynamicXmuxClient != nil && dynamicXmuxClient != xmuxClient {
				dynamicXmuxClient.DoneRunning()
			}
		}()
		for {
			wroteRequest := done.New()
			ctx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				WroteRequest: func(httptrace.WroteRequestInfo) {
					wroteRequest.Close()
				},
			})
			// this intentionally makes a shallow-copy of the struct so we
			// can reassign Path (potentially concurrently)
			url := requestURL
			seqStr := strconv.FormatInt(seq, 10)
			seq += 1
			if scMinPostsIntervalMs.From > 0 {
				time.Sleep(time.Duration(scMinPostsIntervalMs.Rand())*time.Millisecond - time.Since(lastWrite))
			}
			// by offloading the uploads into a buffered pipe, multiple conn.Write
			// calls get automatically batched together into larger POST requests.
			// without batching, bandwidth is extremely limited.
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}
			lastWrite = time.Now()
			if dynamicXmuxClient != nil && (dynamicXmuxClient.LeftRequests.Add(-1) <= 0 ||
				(dynamicXmuxClient.UnreusableAt != time.Time{} && lastWrite.After(dynamicXmuxClient.UnreusableAt))) {
				previous := dynamicXmuxClient //H
				dynamicHTTPClient, dynamicXmuxClient = c.getHTTPClient()
				dynamicXmuxClient.AddRunning() //H: in use until the uploads end or move on
				if previous != xmuxClient {    //H
					previous.DoneRunning() //H
				} //H
			}
			go func(httpClient DialerClient) {
				err := httpClient.PostPacket(
					ctx,
					url.String(),
					sessionId,
					seqStr,
					&buf.MultiBufferContainer{MultiBuffer: chunk},
					int64(chunk.Len()),
				)
				wroteRequest.Close()
				if err != nil {
					uploadPipeReader.Interrupt()
				}
			}(dynamicHTTPClient)
			if _, ok := dynamicHTTPClient.(*DefaultDialerClient); ok {
				select {
				case <-ctx.Done():
				case <-wroteRequest.Wait():
				}

			}
		}
	}()
	return &conn, nil
}

// Close closes the connections to the server. The client can be used again, as it is after the
// network changed: the next connection makes new ones. //H
func (c *Client) Close() error {
	for _, xmuxManager := range c.xmuxManagers {
		xmuxManager.Close()
	}
	return nil
}

// CloseIdleConnections closes the connections to the server that nothing runs on. //H
func (c *Client) CloseIdleConnections() {
	for _, xmuxManager := range c.xmuxManagers {
		xmuxManager.CloseIdleConnections()
	}
}

func decideHTTPVersion(tlsConfig tls.Config) string {
	if tlsConfig == nil || len(tlsConfig.NextProtos()) == 0 || tlsConfig.NextProtos()[0] == "http/1.1" {
		return "1.1"
	}
	if tlsConfig.NextProtos()[0] == "h3" {
		return "3"
	}
	return "2"
}

func getBaseRequestURL(options *option.V2RayXHTTPBaseOptions, dest M.Socksaddr, tlsConfig tls.Config) (url.URL, error) {
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = options.Host
	if requestURL.Host == "" && tlsConfig != nil {
		requestURL.Host = tlsConfig.ServerName()
	}
	if requestURL.Host == "" {
		requestURL.Host = dest.AddrString()
	}
	requestURL.Host = hURLHost(requestURL.Host) //H: a bare IPv6 host made an unparsable URL and a nil request that took the whole app down
	requestURL.Path = options.Path
	if err := sHTTP.URLSetPath(&requestURL, options.Path); err != nil {
		return requestURL, E.New(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	requestURL.Path = options.GetNormalizedPath()
	requestURL.RawQuery = options.GetNormalizedQuery()
	if _, err := url.Parse(requestURL.String()); err != nil { //H: refused when the outbound is made, not on every dial
		return requestURL, E.Cause(err, "xhttp request url") //H
	} //H
	return requestURL, nil
}

func createHTTPClient(dest M.Socksaddr, dialer N.Dialer, options *option.V2RayXHTTPBaseOptions, tlsConfig tls.Config) DialerClient {
	httpVersion := decideHTTPVersion(tlsConfig)
	var trackConn func(net.Conn) net.Conn //H: set below, once the client exists
	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := dialer.DialContext(ctxInner, "tcp", dest)
		if err != nil {
			return nil, err
		}
		if httpVersion != "3" && tlsConfig != nil {
			tlsConn, err := tls.ClientHandshake(ctxInner, conn, tlsConfig) //H
			if err != nil {                                                //H
				conn.Close()    //H: a failed handshake left the TCP connection open
				return nil, err //H
			} //H
			return trackConn(tlsConn), nil //H
		}
		return trackConn(conn), nil //H
	}
	var keepAlivePeriod time.Duration
	if options.Xmux != nil {
		keepAlivePeriod = time.Duration(options.Xmux.HKeepAlivePeriod) * time.Second
	}
	var transport http.RoundTripper
	switch httpVersion {
	case "3":
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.QuicgoH3KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		quicConfig := &quic.Config{
			MaxIdleTimeout: net.ConnIdleTimeout,
			// these two are defaults of quic-go/http3. the default of quic-go (no
			// http3) is different, so it is hardcoded here for clarity.
			// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
			MaxIncomingStreams: -1,
			KeepAlivePeriod:    keepAlivePeriod,
		}
		transport = &http3.Transport{
			QUICConfig: quicConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udpConn, dErr := dialer.DialContext(ctx, N.NetworkUDP, dest)
				if dErr != nil {
					return nil, dErr
				}
				quicConn, dErr := qtls.DialEarly(ctx, udpConn, tlsConfig, cfg) //H
				if dErr != nil {                                               //H
					udpConn.Close()  //H
					return nil, dErr //H
				} //H
				// quic-go does not close a socket it was given: it stayed open after the connection ended
				context.AfterFunc(quicConn.Context(), func() { udpConn.Close() }) //H
				return quicConn, nil                                              //H
			},
		}
	case "2":
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.ChromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		transport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	default:
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}
		transport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: net.ConnIdleTimeout,
			// chunked transfer download with KeepAlives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
	}
	client := &DefaultDialerClient{
		options: options,
		client: &http.Client{
			Transport: transport,
		},
		httpVersion:    httpVersion,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}
	trackConn = client.hTrack //H
	return client
}

// autoMode picks the mode for auto as Xray's client does: stream-one over REALITY, or
// stream-up when the download goes elsewhere, and packet-up otherwise.
func autoMode(reality bool, splitDownload bool) string {
	if !reality {
		return "packet-up"
	}
	if splitDownload {
		return "stream-up"
	}
	return "stream-one"
}

// hMinScMaxEachPostBytes raises an sc_max_each_post_bytes too small to hold one buffer, which
// packet-up cannot split into posts. Xray panics on it at the first dial, and a subscription
// carrying such a server ("4096-4096", "1536-6144") crashed the app as soon as it was tested.
// The posts get a little bigger than the link asks for; a server takes up to 1 MB by default.
func hMinScMaxEachPostBytes(value Xbadoption.Range) Xbadoption.Range {
	if value.From <= buf.Size {
		value.From = buf.Size + 1
	}
	if value.To < value.From {
		value.To = value.From
	}
	return value
}

// hURLHost brackets a bare IPv6 address, which a URL host needs: "2001:db8::1" -> "[2001:db8::1]".
func hURLHost(host string) string {
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is6() {
		return host
	}
	return "[" + strings.ReplaceAll(addr.String(), "%", "%25") + "]"
}
