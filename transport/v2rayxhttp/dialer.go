package xhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"

	common "github.com/sagernet/sing-box/common/xray"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool

	// ctx, url, sessionId, body, uploadOnly
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, sessionId, seqStr, body, contentLength
	PostPacket(context.Context, string, string, string, io.Reader, int64) error
}

// implements xhttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	options     *option.V2RayXHTTPBaseOptions
	client      *http.Client
	closed      atomic.Bool //H: set by stream goroutines, read by IsClosed
	httpVersion string
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load() //H
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	gotConn := done.New()
	// the trace runs on the transport's goroutine, possibly after this function returned on ctx,
	// so the addresses go through an atomic, not the named results
	var connAddrs atomic.Pointer[[2]net.Addr]
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			connAddrs.CompareAndSwap(nil, &[2]net.Addr{connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()})
			gotConn.Close()
		},
	})
	method := "GET" // stream-down
	if body != nil {
		method = c.options.GetNormalizedUplinkHTTPMethod() // stream-up/one
	}
	req, _ := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, body)
	req.Header = c.options.GetRequestHeader()
	length := int(c.options.GetNormalizedXPaddingBytes().Rand())
	config := XPaddingConfig{Length: length}
	if c.options.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.options.XPaddingPlacement,
			Key:       c.options.XPaddingKey,
			Header:    c.options.XPaddingHeader,
			RawURL:    url,
		}
		config.Method = PaddingMethod(c.options.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: option.PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    url,
		}
	}
	ApplyXPaddingToRequest(req, config)
	ApplyMetaToRequest(c.options, req, sessionId, "")
	if method == c.options.GetNormalizedUplinkHTTPMethod() && !c.options.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}
	reader := &WaitReadCloser{ctx: ctx, Wait: make(chan struct{})} //H: the goroutine keeps its own reference, wrc is a result
	wrc = reader                                                   //H
	var doErr atomic.Pointer[error]                                //H: a request that fails before connecting is returned, not hidden in a dead reader
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly { // stream-down is enough
				c.closed.Store(true) //H
			}
			doErr.Store(&err) //H: published before gotConn is closed
			gotConn.Close()
			reader.Close() //H
			return
		}
		if resp.StatusCode != 200 || uploadOnly { // stream-up
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close() // if it is called immediately, the upload will be interrupted also
			reader.Close()    //H
			return
		}
		reader.Set(resp.Body) //H
	}()
	select {
	case <-gotConn.Wait():
	case <-ctx.Done():
	}
	if failure := doErr.Load(); failure != nil { //H
		return nil, nil, nil, *failure //H
	} //H
	if addrs := connAddrs.Load(); addrs != nil {
		remoteAddr, localAddr = addrs[0], addrs[1]
	}
	return
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, body io.Reader, contentLength int64) error {
	var encodedData string
	dataPlacement := c.options.GetNormalizedUplinkDataPlacement()
	if dataPlacement != option.PlacementBody {
		data, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		encodedData = base64.RawURLEncoding.EncodeToString(data)
		body = nil
		contentLength = 0
	}
	method := c.options.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, body)
	if err != nil {
		return err
	}
	req.ContentLength = contentLength
	req.Header = c.options.GetRequestHeader()
	if dataPlacement != option.PlacementBody {
		key := c.options.UplinkDataKey
		chunkSize := int(c.options.UplinkChunkSize)
		switch dataPlacement {
		case option.PlacementHeader:
			for i := 0; i < len(encodedData); i += chunkSize {
				end := i + chunkSize
				if end > len(encodedData) {
					end = len(encodedData)
				}
				chunk := encodedData[i:end]
				headerKey := fmt.Sprintf("%s-%d", key, i/chunkSize)
				req.Header.Set(headerKey, chunk)
			}

			req.Header.Set(key+"-Length", fmt.Sprintf("%d", len(encodedData)))
			req.Header.Set(key+"-Upstream", "1")
		case option.PlacementCookie:
			for i := 0; i < len(encodedData); i += chunkSize {
				end := i + chunkSize
				if end > len(encodedData) {
					end = len(encodedData)
				}
				chunk := encodedData[i:end]
				cookieName := fmt.Sprintf("%s_%d", key, i/chunkSize)
				req.AddCookie(&http.Cookie{Name: cookieName, Value: chunk})
			}

			req.AddCookie(&http.Cookie{Name: key + "_upstream", Value: "1"})
		}
	}
	length := int(c.options.GetNormalizedXPaddingBytes().Rand())
	config := XPaddingConfig{Length: length}
	if c.options.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.options.XPaddingPlacement,
			Key:       c.options.XPaddingKey,
			Header:    c.options.XPaddingHeader,
			RawURL:    url,
		}
		config.Method = PaddingMethod(c.options.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: option.PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    url,
		}
	}
	ApplyXPaddingToRequest(req, config)
	ApplyMetaToRequest(c.options, req, sessionId, seqStr)
	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed.Store(true) //H
			return err
		}
		io.Copy(io.Discard, resp.Body)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK { //H: as in Xray, a rejected upload is an error
			return E.New("bad status code: ", resp.Status) //H
		} //H
	} else {
		// stringify the entire HTTP/1.1 request so it can be
		// safely retried. if instead req.Write is called multiple
		// times, the body is already drained after the first
		// request
		requestBuff := new(bytes.Buffer)
		common.Must(req.Write(requestBuff))
		var uploadConn any
		var h1UploadConn *H1Conn
		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				newConn, err := c.dialUploadConn(context.WithoutCancel(ctx))
				if err != nil {
					return err
				}
				h1UploadConn = NewH1Conn(newConn)
				uploadConn = h1UploadConn
			} else {
				h1UploadConn = uploadConn.(*H1Conn)

				// TODO: Replace 0 here with a config value later
				// Or add some other condition for optimization purposes
				if h1UploadConn.UnreadedResponsesCount > 0 {
					resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
					if err != nil {
						c.closed.Store(true) //H
						return fmt.Errorf("error while reading response: %s", err.Error())
					}
					io.Copy(io.Discard, resp.Body)
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
					}
				}
			}
			_, err := h1UploadConn.Write(requestBuff.Bytes())
			// if the write failed, we try another connection from
			// the pool, until the write on a new connection fails.
			// failed writes to a pooled connection are normal when
			// the connection has been closed in the meantime.
			if err == nil {
				break
			} else if newConnection {
				return err
			}
		}
		c.uploadRawPool.Put(uploadConn)
	}
	return nil
}

// WaitReadCloser is the download stream of OpenStream: reads wait until the response arrives
// (Set) or the stream is closed. Set runs on the request goroutine, so the reader is guarded.
type WaitReadCloser struct {
	ctx    context.Context
	Wait   chan struct{}
	access sync.Mutex
	reader io.ReadCloser
	closed bool
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.access.Lock()
	if w.closed {
		w.access.Unlock()
		rc.Close()
		return
	}
	w.reader = rc
	close(w.Wait)
	w.access.Unlock()
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	select {
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	case <-w.Wait:
	}
	w.access.Lock()
	reader := w.reader
	w.access.Unlock()
	if reader == nil {
		return 0, io.ErrClosedPipe
	}
	return reader.Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.access.Lock()
	if w.closed {
		w.access.Unlock()
		return nil
	}
	w.closed = true
	reader := w.reader
	if reader == nil {
		close(w.Wait)
	}
	w.access.Unlock()
	if reader != nil {
		return reader.Close()
	}
	return nil
}

func ApplyMetaToRequest(options *option.V2RayXHTTPBaseOptions, req *http.Request, sessionId string, seqStr string) {
	sessionPlacement := options.GetNormalizedSessionPlacement()
	seqPlacement := options.GetNormalizedSeqPlacement()
	sessionKey := options.GetNormalizedSessionKey()
	seqKey := options.GetNormalizedSeqKey()
	if sessionId != "" {
		switch sessionPlacement {
		case option.PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, sessionId)
		case option.PlacementQuery:
			q := req.URL.Query()
			q.Set(sessionKey, sessionId)
			req.URL.RawQuery = q.Encode()
		case option.PlacementHeader:
			req.Header.Set(sessionKey, sessionId)
		case option.PlacementCookie:
			req.AddCookie(&http.Cookie{Name: sessionKey, Value: sessionId})
		}
	}
	if seqStr != "" {
		switch seqPlacement {
		case option.PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, seqStr)
		case option.PlacementQuery:
			q := req.URL.Query()
			q.Set(seqKey, seqStr)
			req.URL.RawQuery = q.Encode()
		case option.PlacementHeader:
			req.Header.Set(seqKey, seqStr)
		case option.PlacementCookie:
			req.AddCookie(&http.Cookie{Name: seqKey, Value: seqStr})
		}
	}
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}
