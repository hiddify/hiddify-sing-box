package profiler

import (
	"context"
	"net/http"
	"net/http/pprof"
	runtimePprof "runtime/pprof"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"github.com/go-chi/chi/v5"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.ProfilerServiceOptions](registry, C.TypeProfiler, NewService)
}

type Service struct {
	boxService.Adapter
	logger   log.ContextLogger
	listener *listener.Listener
	server   *http.Server
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.ProfilerServiceOptions) (adapter.Service, error) {
	return &Service{
		Adapter: boxService.NewAdapter(C.TypeProfiler, tag),
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: []string{N.NetworkTCP},
			Listen:  options.ListenOptions,
		}),
	}, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	r := chi.NewMux()
	r.Route("/debug/pprof", func(r chi.Router) {
		r.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			if !strings.HasSuffix(req.URL.Path, "/") {
				http.Redirect(w, req, req.URL.Path+"/", http.StatusMovedPermanently)
				return
			}
			pprof.Index(w, req)
		})
		r.HandleFunc("/cmdline", pprof.Cmdline)
		r.HandleFunc("/profile", pprof.Profile)
		r.HandleFunc("/symbol", pprof.Symbol)
		r.HandleFunc("/trace", pprof.Trace)
		for _, p := range runtimePprof.Profiles() {
			name := p.Name()
			r.Handle("/"+name, pprof.Handler(name))
		}
		r.HandleFunc("/*", pprof.Index)
	})

	s.server = &http.Server{
		Handler: r,
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(s.listener.Close)
	scope.Add(s.server.Close)
	s.logger.Info("profiler listening at ", tcpListener.Addr())
	go func() {
		err := s.server.Serve(tcpListener)
		if err != nil && !E.IsClosed(err) {
			s.logger.Error(E.Cause(err, "serve profiler"))
		}
	}()
	return nil
}
