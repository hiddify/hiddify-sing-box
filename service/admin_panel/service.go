//go:build with_admin_panel

package admin_panel

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHTTP "github.com/sagernet/sing/protocol/http"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/http2"
)

// distFS holds the SPA bytes produced by `npm run build` (Vite) and then
// post-processed by `cmd/internal/admin_panel_pack`. The directory
// is checked into the repo so a plain `go build -tags with_admin_panel`
// produces a self-contained binary — no Node.js required at compile time.
//
// The post-processor:
//   - deletes the legacy *.woff fonts (every browser since 2014 reads
//     WOFF2 natively) and removes their references from the bundled CSS;
//   - drops a gzip-compressed `*.gz` companion next to every compressible
//     text asset (.html, .css, .js, …) using BestCompression. We pass
//     those bytes through verbatim with Content-Encoding: gzip when the
//     client advertises gzip, and fall back to the raw file otherwise.
//
//go:embed dist
var distFS embed.FS

// distRoot is the embed.FS rooted at `dist/`, so handlers can use plain
// "index.html" / "assets/..." keys instead of the "dist/..." prefix.
var distRoot = func() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// Cannot happen unless the //go:embed pattern above and the
		// fs.Sub argument disagree; bail loudly so the mismatch is
		// caught at startup.
		panic(err)
	}
	return sub
}()

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.AdminPanelServiceOptions](registry, C.TypeAdminPanel, NewService)
}

type Service struct {
	boxService.Adapter
	ctx        context.Context
	logger     log.ContextLogger
	listener   *listener.Listener
	tlsConfig  tls.ServerConfig
	httpServer *http.Server
	options    option.AdminPanelServiceOptions
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.AdminPanelServiceOptions) (adapter.Service, error) {
	return &Service{
		Adapter: boxService.NewAdapter(C.TypeAdminPanel, tag),
		ctx:     ctx,
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: []string{N.NetworkTCP},
			Listen:  options.ListenOptions,
		}),
		options: options,
	}, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	chiRouter := chi.NewRouter()
	s.Route(chiRouter)
	if s.options.TLS != nil {
		tlsConfig, err := tls.NewServer(s.ctx, s.logger, common.PtrValueOrDefault(s.options.TLS))
		if err != nil {
			return err
		}
		s.tlsConfig = tlsConfig
	}
	if s.tlsConfig != nil {
		err := s.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(s.tlsConfig.Close)
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(s.listener.Close)
	if s.tlsConfig != nil {
		if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{"h2"}, s.tlsConfig.NextProtos()...))
		}
		tcpListener = aTLS.NewListener(tcpListener, s.tlsConfig)
	}
	s.httpServer = &http.Server{
		Handler:           chiRouter,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	scope.Add(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(ctx)
		return nil
	})
	go func() {
		err := s.httpServer.Serve(tcpListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("serve error: ", err)
		}
	}()
	return nil
}

func (s *Service) Route(r chi.Router) {
	r.Use(func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			s.logger.Debug(request.Method, " ", request.RequestURI, " ", sHTTP.SourceAddress(request))
			handler.ServeHTTP(writer, request)
		})
	})
	r.Get("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version": C.Version,
		})
	})
	handler := newSPAHandler()
	r.Method(http.MethodGet, "/*", handler)
	r.Method(http.MethodHead, "/*", handler)
}

func newSPAHandler() http.Handler {
	_, hasIndex := readFile("index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if reqPath != "" && reqPath != "index.html" {
			if data, ok := readFile(reqPath); ok {
				serveAsset(w, r, reqPath, data)
				return
			}
		}
		if !hasIndex {
			http.Error(w, "admin panel not built", http.StatusInternalServerError)
			return
		}
		serveIndex(w, r)
	})
}

func readFile(name string) ([]byte, bool) {
	data, err := fs.ReadFile(distRoot, name)
	if err != nil {
		return nil, false
	}
	return data, true
}

func gzipCompanion(name string) ([]byte, bool) {
	return readFile(name + ".gz")
}

func serveAsset(w http.ResponseWriter, r *http.Request, name string, raw []byte) {
	if ctype := contentType(name); ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	if isHashedAsset(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	}
	writeBody(w, r, name, raw)
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	raw, _ := readFile("index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	writeBody(w, r, "index.html", raw)
}

func writeBody(w http.ResponseWriter, r *http.Request, name string, raw []byte) {
	header := w.Header()
	if gz, ok := gzipCompanion(name); ok {
		// Even when we end up serving the raw bytes (because the client
		// declined gzip), let any shared cache know the response varies
		// by Accept-Encoding so it doesn't hand a gzipped payload to a
		// non-gzip client.
		header.Add("Vary", "Accept-Encoding")
		if acceptsGzip(r) {
			header.Set("Content-Encoding", "gzip")
			header.Set("Content-Length", strconv.Itoa(len(gz)))
			if r.Method == http.MethodHead {
				return
			}
			_, _ = w.Write(gz)
			return
		}
	}
	header.Set("Content-Length", strconv.Itoa(len(raw)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(raw)
}

func acceptsGzip(r *http.Request) bool {
	for _, h := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(h, ",") {
			tok := strings.TrimSpace(part)
			if i := strings.IndexByte(tok, ';'); i >= 0 {
				tok = strings.TrimSpace(tok[:i])
			}
			if strings.EqualFold(tok, "gzip") {
				return true
			}
		}
	}
	return false
}

func isHashedAsset(name string) bool {
	return strings.HasPrefix(name, "assets/")
}

func contentType(name string) string {
	ext := path.Ext(name)
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	switch ext {
	case ".js", ".mjs":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	}
	return ""
}
