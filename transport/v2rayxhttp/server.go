package xhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/kmutex"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

type Server struct {
	ctx         context.Context
	logger      logger.ContextLogger
	tlsConfig   tls.ServerConfig
	quicConfig  *quic.Config
	handler     adapter.V2RayServerTransportHandler
	httpServer  *http.Server
	http3Server *http3.Server
	localAddr   net.Addr
	options     *option.V2RayXHTTPOptions
	host        string
	path        string
	sessionMu   *kmutex.Kmutex[string]
	sessions    sync.Map
}

func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayXHTTPOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	server := &Server{
		ctx:       ctx,
		logger:    logger,
		tlsConfig: tlsConfig,
		handler:   handler,
		options:   &options,
		host:      options.Host,
		path:      options.GetNormalizedPath(),
		sessionMu: kmutex.New[string](),
	}
	if server.network() == N.NetworkTCP {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		server.httpServer = &http.Server{
			Handler:           server,
			ReadHeaderTimeout: time.Second * 4,
			MaxHeaderBytes:    options.GetNormalizedServerMaxHeaderBytes(),
			Protocols:         protocols,
			BaseContext: func(net.Listener) context.Context {
				return ctx
			},
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return log.ContextWithNewID(ctx)
			},
		}
	} else {
		congestionControlFactory, err := congestion.NewCongestionControl(options.CongestionController, options.CWND, ntp.TimeFuncFromContext(ctx))
		if err != nil {
			return nil, err
		}
		server.quicConfig = &quic.Config{
			DisablePathMTUDiscovery: !C.IsLinux && !C.IsWindows,
		}
		server.http3Server = &http3.Server{
			Handler: server,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				if congestionControlFactory != nil {
					conn.SetCongestionControl(congestionControlFactory(conn))
				}
				return log.ContextWithNewID(ctx)
			},
		}
	}
	return server, nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if len(s.host) > 0 && !isValidHTTPHost(request.Host, s.host) {
		s.logger.ErrorContext(request.Context(), "failed to validate host, request:", request.Host, ", config:", s.host)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if !strings.HasPrefix(request.URL.Path, s.path) {
		s.logger.ErrorContext(request.Context(), "failed to validate path, request:", request.URL.Path, ", config:", s.path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	WriteResponseHeader(writer, request.Method, request.Header, s.options)
	length := s.options.GetNormalizedXPaddingBytes().Rand()
	config := XPaddingConfig{Length: length}
	if s.options.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: s.options.XPaddingPlacement,
			Key:       s.options.XPaddingKey,
			Header:    s.options.XPaddingHeader,
		}
		config.Method = PaddingMethod(s.options.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: option.PlacementHeader,
			Header:    "X-Padding",
		}
	}
	ApplyXPaddingToResponse(writer, config)
	if request.Method == "OPTIONS" {
		writer.WriteHeader(http.StatusOK)
		return
	}
	validRange := s.options.GetNormalizedXPaddingBytes()
	paddingValue, paddingPlacement := ExtractXPaddingFromRequest(&s.options.V2RayXHTTPBaseOptions, request, s.options.XPaddingObfsMode)
	if !IsPaddingValid(&s.options.V2RayXHTTPBaseOptions, paddingValue, validRange.From, validRange.To, PaddingMethod(s.options.XPaddingMethod)) {
		s.logger.ErrorContext(request.Context(), "invalid padding ("+paddingPlacement+") length:", len(paddingValue))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	obfsPaddingAccepted := s.options.XPaddingObfsMode && paddingValue != ""
	sessionId, seqStr := ExtractMetaFromRequest(s.options, request, s.path)
	if s.options.Mode != "" && s.options.Mode != "auto" {
		if sessionId == "" {
			if s.options.Mode != "stream-one" && s.options.Mode != "stream-up" {
				s.logger.ErrorContext(request.Context(), "stream-one mode is not allowed")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		} else {
			if s.options.Mode == "stream-one" {
				s.logger.ErrorContext(request.Context(), "session is not allowed in stream-one mode")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}
	}
	var remoteAddr net.Addr
	var err error
	remoteAddr, err = net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil {
		remoteAddr = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}
	if request.ProtoMajor == 3 {
		remoteAddr = &net.UDPAddr{
			IP:   remoteAddr.(*net.TCPAddr).IP,
			Port: remoteAddr.(*net.TCPAddr).Port,
		}
	}
	if forwardedFor := request.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		if slices.ContainsFunc(s.options.TrustedXForwardedFor, func(key string) bool {
			return len(request.Header.Values(key)) > 0
		}) {
			if forwardedAddress := parseXForwardedFor(request.Header)[0]; forwardedAddress.Family().IsIP() {
				remoteAddr = &net.TCPAddr{
					IP:   forwardedAddress.IP(),
					Port: 0,
				}
			}
		} else if len(s.options.TrustedXForwardedFor) == 0 {
			s.logger.WarnContext(request.Context(), "received \"X-Forwarded-For\" from ", remoteAddr, " but \"trusted_x_forwarded_for\" is not configured; ignoring it and using the real remote address")
		} else {
			s.logger.ErrorContext(request.Context(), "ignored potentially forged \"X-Forwarded-For\" from ", remoteAddr, ": ", forwardedFor)
		}
	}
	var currentSession *httpSession
	if sessionId != "" {
		currentSession = s.upsertSession(sessionId)
	}
	scMaxEachPostBytes := s.options.GetNormalizedScMaxEachPostBytes().To
	uplinkDataPlacement := s.options.GetNormalizedUplinkDataPlacement()
	uplinkDataKey := s.options.UplinkDataKey
	isUplinkRequest := false
	switch request.Method {
	case "GET":
		isUplinkRequest = seqStr != ""
	default:
		isUplinkRequest = true
	}
	if isUplinkRequest && sessionId != "" { // stream-up, packet-up
		if seqStr == "" {
			if s.options.Mode != "" && s.options.Mode != "auto" && s.options.Mode != "stream-up" {
				s.logger.ErrorContext(request.Context(), "stream-up mode is not allowed")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			httpSC := &httpServerConn{
				Instance:       done.New(),
				Reader:         request.Body,
				ResponseWriter: writer,
			}
			err = currentSession.uploadQueue.Push(Packet{
				Reader: httpSC,
			})
			if err != nil {
				s.logger.DebugContext(request.Context(), err, "failed to upload (PushReader)")
				writer.WriteHeader(http.StatusConflict)
			} else {
				writer.Header().Set("X-Accel-Buffering", "no")
				writer.Header().Set("Cache-Control", "no-store")
				writer.WriteHeader(http.StatusOK)
				scStreamUpServerSecs := s.options.GetNormalizedScStreamUpServerSecs()
				if (request.Header.Get("Referer") != "" || obfsPaddingAccepted) && scStreamUpServerSecs.To > 0 {
					go func() {
						timer := time.NewTimer(0)
						if !timer.Stop() {
							<-timer.C
						}
						defer timer.Stop()
						for {
							_, err := httpSC.Write(bytes.Repeat([]byte{'X'}, s.options.GetNormalizedXPaddingBytes().Rand()))
							if err != nil {
								return
							}
							timer.Reset(time.Duration(scStreamUpServerSecs.Rand()) * time.Second)
							select {
							case <-timer.C:
							case <-httpSC.Wait():
								return
							}
						}
					}()
				}
				select {
				case <-request.Context().Done():
				case <-httpSC.Wait():
				}
			}
			httpSC.Close()
			return
		}
		if s.options.Mode != "" && s.options.Mode != "auto" && s.options.Mode != "packet-up" {
			s.logger.ErrorContext(request.Context(), "packet-up mode is not allowed")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var headerPayload []byte
		if uplinkDataPlacement == option.PlacementAuto || uplinkDataPlacement == option.PlacementHeader {
			var headerPayloadChunks []string
			for i := 0; true; i++ {
				chunk := request.Header.Get(fmt.Sprintf("%s-%d", uplinkDataKey, i))
				if chunk == "" {
					break
				}
				headerPayloadChunks = append(headerPayloadChunks, chunk)
			}
			headerPayloadEncoded := strings.Join(headerPayloadChunks, "")
			headerPayload, err = base64.RawURLEncoding.DecodeString(headerPayloadEncoded)
			if err != nil {
				s.logger.DebugContext(request.Context(), err, "Invalid base64 in header's payload")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		var cookiePayload []byte
		if uplinkDataPlacement == option.PlacementAuto || uplinkDataPlacement == option.PlacementCookie {
			var cookiePayloadChunks []string
			for i := 0; true; i++ {
				cookieName := fmt.Sprintf("%s_%d", uplinkDataKey, i)
				if c, _ := request.Cookie(cookieName); c != nil {
					cookiePayloadChunks = append(cookiePayloadChunks, c.Value)
				} else {
					break
				}
			}
			cookiePayloadEncoded := strings.Join(cookiePayloadChunks, "")
			cookiePayload, err = base64.RawURLEncoding.DecodeString(cookiePayloadEncoded)
			if err != nil {
				s.logger.DebugContext(request.Context(), err, "Invalid base64 in cookies' payload")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		var bodyPayload []byte
		if uplinkDataPlacement == option.PlacementAuto || uplinkDataPlacement == option.PlacementBody {
			var readErr error
			if request.ContentLength > int64(scMaxEachPostBytes) {
				s.logger.ErrorContext(request.Context(), "Too large upload. scMaxEachPostBytes is set to ", scMaxEachPostBytes, "but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.")
				writer.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			if request.ContentLength > 0 {
				bodyPayload = make([]byte, request.ContentLength)
				_, readErr = io.ReadFull(request.Body, bodyPayload)
			} else {
				bodyPayload, readErr = buf.ReadAllToBytes(io.LimitReader(request.Body, int64(scMaxEachPostBytes)+1))
			}
			if readErr != nil {
				s.logger.DebugContext(request.Context(), readErr, "failed to read body payload")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		var payload []byte
		switch uplinkDataPlacement {
		case option.PlacementHeader:
			payload = headerPayload
		case option.PlacementCookie:
			payload = cookiePayload
		case option.PlacementBody:
			payload = bodyPayload
		case option.PlacementAuto:
			payload = slices.Concat(headerPayload, cookiePayload, bodyPayload)
		}
		if len(payload) > scMaxEachPostBytes {
			s.logger.ErrorContext(request.Context(), "Too large upload. scMaxEachPostBytes is set to ", scMaxEachPostBytes, "but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.")
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			s.logger.DebugContext(request.Context(), err, "failed to upload (ParseUint)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = currentSession.uploadQueue.Push(Packet{
			Payload: payload,
			Seq:     seq,
		})
		if err != nil {
			s.logger.DebugContext(request.Context(), err, "failed to upload (PushPayload)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if len(bodyPayload) == 0 {
			// Methods without a body are usually cached by default.
			writer.Header().Set("Cache-Control", "no-store")
		}
		writer.WriteHeader(http.StatusOK)
	} else if request.Method == "GET" || sessionId == "" { // stream-down, stream-one
		if sessionId != "" {
			// after GET is done, the connection is finished. disable automatic
			// session reaping, and handle it in defer
			currentSession.isFullyConnected.Close()
			defer func() {
				s.sessionMu.Lock(sessionId)
				defer s.sessionMu.Unlock(sessionId)
				s.sessions.Delete(sessionId)
			}()
		}
		// magic header instructs nginx + apache to not buffer response body
		writer.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		writer.Header().Set("Cache-Control", "no-store")
		if !s.options.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			writer.Header().Set("Content-Type", "text/event-stream")
		}
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		httpSC := &httpServerConn{
			Instance:       done.New(),
			Reader:         request.Body,
			ResponseWriter: writer,
		}
		localAddress := s.localAddr
		if requestLocalAddress, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && requestLocalAddress != nil {
			localAddress = requestLocalAddress
		}
		conn := splitConn{
			writer:     httpSC,
			reader:     httpSC,
			remoteAddr: remoteAddr,
			localAddr:  localAddress,
		}
		if sessionId != "" { // if not stream-one
			conn.reader = currentSession.uploadQueue
		}
		s.handler.NewConnectionEx(v2rayhttp.HWIDContext(request.Context(), request.Header), &conn, M.SocksaddrFromNet(remoteAddr).Unwrap(), M.Socksaddr{}, func(it error) {})
		// "A ResponseWriter may not be used after [Handler.ServeHTTP] has returned."
		select {
		case <-request.Context().Done():
		case <-httpSC.Wait():
		}
		conn.Close()
	} else {
		s.logger.ErrorContext(request.Context(), "unsupported method: ", request.Method)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) Network() []string {
	return []string{s.network()}
}

func (s *Server) Serve(listener net.Listener) error {
	if s.network() == N.NetworkTCP {
		if s.tlsConfig != nil {
			listener = aTLS.NewListener(listener, s.tlsConfig)
		}
		s.localAddr = listener.Addr()
		return s.httpServer.Serve(listener)
	}
	return os.ErrInvalid
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	if s.network() == N.NetworkUDP {
		quicListener, err := qtls.ListenEarly(listener, s.tlsConfig, s.quicConfig)
		if err != nil {
			return err
		}
		s.localAddr = quicListener.Addr()
		return s.http3Server.ServeListener(quicListener)
	}
	return os.ErrInvalid
}

func (s *Server) Close() error {
	if s.network() == N.NetworkTCP {
		return common.Close(s.httpServer)
	}
	return common.Close(s.http3Server)
}

func (s *Server) network() string {
	if s.tlsConfig != nil && len(s.tlsConfig.NextProtos()) == 1 && s.tlsConfig.NextProtos()[0] == "h3" {
		return N.NetworkUDP
	}
	return N.NetworkTCP
}

func (s *Server) upsertSession(sessionId string) *httpSession {
	s.sessionMu.Lock(sessionId)
	defer s.sessionMu.Unlock(sessionId)
	currentSessionAny, ok := s.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}
	session := &httpSession{
		uploadQueue:      NewUploadQueue(s.options.GetNormalizedScMaxBufferedPosts()),
		isFullyConnected: done.New(),
	}
	s.sessions.Store(sessionId, session)
	go func() {
		reapTimer := time.NewTimer(30 * time.Second)
		defer reapTimer.Stop()
		select {
		case <-reapTimer.C:
			s.sessionMu.Lock(sessionId)
			if current, ok := s.sessions.Load(sessionId); ok && current.(*httpSession) == session {
				s.sessions.Delete(sessionId)
			}
			s.sessionMu.Unlock(sessionId)
			session.uploadQueue.Close()
		case <-session.isFullyConnected.Wait():
		}
	}()
	return session
}

func ExtractMetaFromRequest(options *option.V2RayXHTTPOptions, req *http.Request, path string) (sessionId string, seqStr string) {
	sessionPlacement := options.GetNormalizedSessionPlacement()
	seqPlacement := options.GetNormalizedSeqPlacement()
	sessionKey := options.GetNormalizedSessionKey()
	seqKey := options.GetNormalizedSeqKey()
	var subpath []string
	pathPart := 0
	if sessionPlacement == option.PlacementPath || seqPlacement == option.PlacementPath {
		subpath = strings.Split(req.URL.Path[len(path):], "/")
	}
	switch sessionPlacement {
	case option.PlacementPath:
		if len(subpath) > pathPart {
			sessionId = subpath[pathPart]
			pathPart += 1
		}
	case option.PlacementQuery:
		sessionId = req.URL.Query().Get(sessionKey)
	case option.PlacementHeader:
		sessionId = req.Header.Get(sessionKey)
	case option.PlacementCookie:
		if cookie, e := req.Cookie(sessionKey); e == nil {
			sessionId = cookie.Value
		}
	}
	switch seqPlacement {
	case option.PlacementPath:
		if len(subpath) > pathPart {
			seqStr = subpath[pathPart]
			pathPart += 1
		}
	case option.PlacementQuery:
		seqStr = req.URL.Query().Get(seqKey)
	case option.PlacementHeader:
		seqStr = req.Header.Get(seqKey)
	case option.PlacementCookie:
		if cookie, e := req.Cookie(seqKey); e == nil {
			seqStr = cookie.Value
		}
	}
	return sessionId, seqStr
}
