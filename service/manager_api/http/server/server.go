package server

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/manager/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"golang.org/x/net/http2"
)

type APIServer struct {
	boxService.Adapter

	ctx        context.Context
	logger     log.ContextLogger
	listener   *listener.Listener
	tlsConfig  tls.ServerConfig
	httpServer *http.Server
	manager    constant.Manager
	options    option.ManagerAPIServerOptions
}

func NewAPIServer(ctx context.Context, logger log.ContextLogger, tag string, options option.ManagerAPIServerOptions) (*APIServer, error) {
	if options.APIKey == "" {
		return nil, E.New("missing api key")
	}
	return &APIServer{
		Adapter: boxService.NewAdapter(C.TypeManagerAPI, tag),
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

func (s *APIServer) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	boxManager := service.FromContext[adapter.ServiceManager](s.ctx)
	managerService, ok := boxManager.Get(s.options.Manager)
	if !ok {
		return E.New("manager ", s.options.Manager, " not found")
	}
	s.manager, ok = managerService.(constant.Manager)
	if !ok {
		return E.New("invalid ", s.options.Manager, " manager")
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
		Handler: chiRouter,
	}
	scope.Add(s.httpServer.Close)
	go func() {
		err = s.httpServer.Serve(tcpListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("serve error: ", err)
		}
	}()
	return nil
}

func (s *APIServer) Route(r chi.Router) {
	r.Route("/manager/v1", func(r chi.Router) {
		r.Use(newCORSMiddleware(s.options.CORS))
		r.Use(func(handler http.Handler) http.Handler {
			return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				s.logger.Debug(request.Method, " ", request.RequestURI, " ", sHTTP.SourceAddress(request))
				handler.ServeHTTP(writer, request)
			})
		})
		r.Group(func(r chi.Router) {
			r.Use(s.requireAPIKey)
			r.Get("/version", func(w http.ResponseWriter, req *http.Request) {
				render.JSON(w, req, render.M{
					"version": C.Version,
				})
			})
			registerIntCRUD(r, "/squads",
				s.manager.GetSquads, s.manager.GetSquadsCount,
				s.manager.GetSquad, s.manager.CreateSquad,
				s.manager.UpdateSquad, s.manager.DeleteSquad)
			registerIntCRUD(r, "/users",
				s.manager.GetUsers, s.manager.GetUsersCount,
				s.manager.GetUser, s.manager.CreateUser,
				s.manager.UpdateUser, s.manager.DeleteUser)
			registerIntCRUD(r, "/bandwidth-limiters",
				s.manager.GetBandwidthLimiters, s.manager.GetBandwidthLimitersCount,
				s.manager.GetBandwidthLimiter, s.manager.CreateBandwidthLimiter,
				s.manager.UpdateBandwidthLimiter, s.manager.DeleteBandwidthLimiter)
			registerIntCRUD(r, "/traffic-limiters",
				s.manager.GetTrafficLimiters, s.manager.GetTrafficLimitersCount,
				s.manager.GetTrafficLimiter, s.manager.CreateTrafficLimiter,
				s.manager.UpdateTrafficLimiter, s.manager.DeleteTrafficLimiter)
			r.Put("/traffic-limiters/{id}/used", s.updateTrafficLimiterUsed)
			registerIntCRUD(r, "/connection-limiters",
				s.manager.GetConnectionLimiters, s.manager.GetConnectionLimitersCount,
				s.manager.GetConnectionLimiter, s.manager.CreateConnectionLimiter,
				s.manager.UpdateConnectionLimiter, s.manager.DeleteConnectionLimiter)
			registerIntCRUD(r, "/rate-limiters",
				s.manager.GetRateLimiters, s.manager.GetRateLimitersCount,
				s.manager.GetRateLimiter, s.manager.CreateRateLimiter,
				s.manager.UpdateRateLimiter, s.manager.DeleteRateLimiter)
			r.Route("/nodes", func(r chi.Router) {
				r.Get("/", listHandler(s.manager.GetNodes))
				r.Post("/", createHandler(s.manager.CreateNode))
				r.Get("/count", countHandler(s.manager.GetNodesCount))
				r.Get("/{uuid}", getByStringIDHandler("uuid", s.manager.GetNode))
				r.Put("/{uuid}", updateByStringIDHandler("uuid", s.manager.UpdateNode))
				r.Delete("/{uuid}", deleteByStringIDHandler("uuid", s.manager.DeleteNode))
				r.Get("/{uuid}/status", func(w http.ResponseWriter, req *http.Request) {
					status, err := s.manager.GetNodeStatus(chi.URLParam(req, "uuid"))
					if err != nil {
						writeError(w, req, err)
						return
					}
					render.JSON(w, req, render.M{"status": status})
				})
			})
		})
		r.Get("/swagger", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, req.URL.Path+"/", http.StatusMovedPermanently)
		})
		r.Get("/swagger/", s.swaggerUI)
		r.Get("/swagger/openapi.yaml", s.swaggerSpec)
	})
}

// updateTrafficLimiterUsed overwrites the running raw_used counter
// of a traffic limiter. Used by the admin panel "reset traffic" button
// (which posts {"used": 0}); also fine for any operator who needs to
// nudge the counter to a specific number.
func (s *APIServer) updateTrafficLimiterUsed(w http.ResponseWriter, req *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(req, "id"))
	if err != nil {
		writeBadRequest(w, req, err)
		return
	}
	var body struct {
		Used uint64 `json:"used"`
	}
	if err := render.DecodeJSON(req.Body, &body); err != nil {
		writeBadRequest(w, req, err)
		return
	}
	item, err := s.manager.UpdateTrafficLimiterUsed(id, body.Used)
	if err != nil {
		writeUpdateError(w, req, err)
		return
	}
	render.JSON(w, req, item)
}

func (s *APIServer) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := request.Header.Get("Authorization")
		if header == "" {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="manager-api"`)
			render.Status(request, http.StatusUnauthorized)
			render.PlainText(writer, request, "missing api key")
			return
		}
		token := strings.TrimPrefix(header, "Bearer ")
		if token == header {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="manager-api"`)
			render.Status(request, http.StatusUnauthorized)
			render.PlainText(writer, request, "invalid api key format")
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.options.APIKey)) == 0 {
			render.Status(request, http.StatusUnauthorized)
			render.PlainText(writer, request, "invalid api key")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func newCORSMiddleware(cfg *option.ManagerAPICORSOptions) func(http.Handler) http.Handler {
	const (
		allowedMethods  = "GET, POST, PUT, DELETE, OPTIONS"
		fallbackHeaders = "Authorization, Content-Type"
	)
	var (
		originSet      map[string]struct{}
		allowAnyOrigin = true
		exposedHeaders string
		maxAge         = "600"
	)
	if cfg != nil {
		hasWildcard := false
		filtered := make([]string, 0, len(cfg.AllowedOrigins))
		for _, o := range cfg.AllowedOrigins {
			if o == "*" {
				hasWildcard = true
				continue
			}
			if o == "" {
				continue
			}
			filtered = append(filtered, o)
		}
		if len(filtered) > 0 && !hasWildcard {
			originSet = make(map[string]struct{}, len(filtered))
			for _, o := range filtered {
				originSet[o] = struct{}{}
			}
			allowAnyOrigin = false
		}
		if len(cfg.ExposedHeaders) > 0 {
			exposedHeaders = strings.Join(cfg.ExposedHeaders, ", ")
		}
		if cfg.MaxAge > 0 {
			maxAge = strconv.Itoa(cfg.MaxAge)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			h := w.Header()
			h.Set("Vary", "Origin")
			emitOrigin := ""
			if !allowAnyOrigin {
				if _, ok := originSet[origin]; ok {
					emitOrigin = origin
				}
			} else if origin != "" {
				emitOrigin = origin
			} else {
				emitOrigin = "*"
			}
			if emitOrigin != "" {
				h.Set("Access-Control-Allow-Origin", emitOrigin)
			}
			h.Set("Access-Control-Allow-Methods", allowedMethods)
			if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
				h.Set("Access-Control-Allow-Headers", reqHeaders)
			} else {
				h.Set("Access-Control-Allow-Headers", fallbackHeaders)
			}
			if exposedHeaders != "" {
				h.Set("Access-Control-Expose-Headers", exposedHeaders)
			}
			h.Set("Access-Control-Max-Age", maxAge)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *APIServer) swaggerUI(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = writer.Write([]byte(swaggerUIHTML))
}

func (s *APIServer) swaggerSpec(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/yaml")
	_, _ = writer.Write(openAPISpec)
}

func registerIntCRUD[T any, CR any, UP any](
	r chi.Router, path string,
	list func(map[string][]string) ([]T, error),
	count func(map[string][]string) (int, error),
	get func(int) (T, error),
	create func(CR) (T, error),
	update func(int, UP) (T, error),
	del func(int) (T, error),
) {
	r.Route(path, func(r chi.Router) {
		r.Get("/", listHandler(list))
		r.Post("/", createHandler(create))
		r.Get("/count", countHandler(count))
		r.Get("/{id}", getByIntIDHandler("id", get))
		r.Put("/{id}", updateByIntIDHandler("id", update))
		r.Delete("/{id}", deleteByIntIDHandler("id", del))
	})
}

func listHandler[T any](fn func(map[string][]string) ([]T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		filters := parseListFilters(req.URL.Query())
		applyDefaultLimit(filters)
		items, err := fn(filters)
		if err != nil {
			writeError(w, req, err)
			return
		}
		if items == nil {
			items = []T{}
		}
		render.JSON(w, req, items)
	}
}

func applyDefaultLimit(filters map[string][]string) {
	if _, ok := filters["limit"]; !ok {
		filters["limit"] = []string{"100"}
	}
}

func countHandler(fn func(map[string][]string) (int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		count, err := fn(parseListFilters(req.URL.Query()))
		if err != nil {
			writeError(w, req, err)
			return
		}
		render.JSON(w, req, render.M{"count": count})
	}
}

func parseListFilters(q url.Values) map[string][]string {
	out := make(map[string][]string, len(q))
	for k, vs := range q {
		if !strings.HasSuffix(k, "_in") {
			out[k] = vs
			continue
		}
		expanded := make([]string, 0, len(vs))
		for _, v := range vs {
			s := strings.TrimSpace(v)
			s = strings.TrimPrefix(s, "[")
			s = strings.TrimSuffix(s, "]")
			for _, p := range strings.Split(s, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					expanded = append(expanded, p)
				}
			}
		}
		if len(expanded) == 0 {
			continue
		}
		out[k] = expanded
	}
	return out
}

func createHandler[T, CR any](fn func(CR) (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var body CR
		if err := render.DecodeJSON(req.Body, &body); err != nil {
			writeBadRequest(w, req, err)
			return
		}
		item, err := fn(body)
		if err != nil {
			writeBadRequest(w, req, err)
			return
		}
		render.Status(req, http.StatusCreated)
		render.JSON(w, req, item)
	}
}

func getByIntIDHandler[T any](idKey string, fn func(int) (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		id, err := strconv.Atoi(chi.URLParam(req, idKey))
		if err != nil {
			writeBadRequest(w, req, err)
			return
		}
		item, err := fn(id)
		if err != nil {
			writeError(w, req, err)
			return
		}
		render.JSON(w, req, item)
	}
}

func getByStringIDHandler[T any](idKey string, fn func(string) (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		item, err := fn(chi.URLParam(req, idKey))
		if err != nil {
			writeError(w, req, err)
			return
		}
		render.JSON(w, req, item)
	}
}

func updateByIntIDHandler[T, UP any](idKey string, fn func(int, UP) (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		id, err := strconv.Atoi(chi.URLParam(req, idKey))
		if err != nil {
			writeBadRequest(w, req, err)
			return
		}
		var body UP
		if err := render.DecodeJSON(req.Body, &body); err != nil {
			writeBadRequest(w, req, err)
			return
		}
		item, err := fn(id, body)
		if err != nil {
			writeUpdateError(w, req, err)
			return
		}
		render.JSON(w, req, item)
	}
}

func updateByStringIDHandler[T, UP any](idKey string, fn func(string, UP) (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var body UP
		if err := render.DecodeJSON(req.Body, &body); err != nil {
			writeBadRequest(w, req, err)
			return
		}
		item, err := fn(chi.URLParam(req, idKey), body)
		if err != nil {
			writeUpdateError(w, req, err)
			return
		}
		render.JSON(w, req, item)
	}
}

func deleteByIntIDHandler[T any](idKey string, fn func(int) (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		id, err := strconv.Atoi(chi.URLParam(req, idKey))
		if err != nil {
			writeBadRequest(w, req, err)
			return
		}
		item, err := fn(id)
		if err != nil {
			writeError(w, req, err)
			return
		}
		render.JSON(w, req, item)
	}
}

func deleteByStringIDHandler[T any](idKey string, fn func(string) (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		item, err := fn(chi.URLParam(req, idKey))
		if err != nil {
			writeError(w, req, err)
			return
		}
		render.JSON(w, req, item)
	}
}

func writeBadRequest(w http.ResponseWriter, req *http.Request, err error) {
	render.Status(req, http.StatusBadRequest)
	render.PlainText(w, req, err.Error())
}

func writeError(w http.ResponseWriter, req *http.Request, err error) {
	if err == constant.ErrNotFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	render.Status(req, http.StatusInternalServerError)
	render.PlainText(w, req, err.Error())
}

func writeUpdateError(w http.ResponseWriter, req *http.Request, err error) {
	if err == constant.ErrNotFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	render.Status(req, http.StatusBadRequest)
	render.PlainText(w, req, err.Error())
}
