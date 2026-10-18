package adapter

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
)

type SimpleLifecycle interface {
	Start() error
	Close() error
}

type StartStage uint8

const (
	StartStateInitialize StartStage = iota
	StartStateStart
	StartStatePostStart
	StartStateStarted
)

var ListStartStages = []StartStage{
	StartStateInitialize,
	StartStateStart,
	StartStatePostStart,
	StartStateStarted,
}

func (s StartStage) String() string {
	switch s {
	case StartStateInitialize:
		return "initialize"
	case StartStateStart:
		return "start"
	case StartStatePostStart:
		return "post-start"
	case StartStateStarted:
		return "finish-start"
	default:
		panic("unknown stage")
	}
}

type Lifecycle interface {
	Start(stage StartStage, scope *Scope) error
}

type LifecycleService interface {
	Name() string
	Lifecycle
}

type Scope struct {
	ctx      context.Context
	cancel   context.CancelFunc
	logger   log.ContextLogger
	access   sync.Mutex
	cleanups list.List[func() error]
	children map[Lifecycle]*scopeChild
}

type scopeChild struct {
	scope   *Scope
	cleanup *list.Element[func() error]
}

func NewScope(ctx context.Context, logger log.ContextLogger) *Scope {
	ctx, cancel := context.WithCancel(ctx)
	return &Scope{
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		children: make(map[Lifecycle]*scopeChild),
	}
}

func (s *Scope) Context() context.Context {
	return s.ctx
}

func (s *Scope) Add(cleanup func() error) {
	s.access.Lock()
	s.cleanups.PushBack(cleanup)
	s.access.Unlock()
}

func (s *Scope) Start(name string, component Lifecycle, stage StartStage) error {
	s.access.Lock()
	err := s.ctx.Err()
	if err != nil {
		s.access.Unlock()
		return err
	}
	child, loaded := s.children[component]
	if !loaded {
		childScope := NewScope(s.ctx, s.logger)
		child = &scopeChild{scope: childScope}
		child.cleanup = s.cleanups.PushBack(func() error {
			done := LogElapsed(s.logger, "close ", name)
			monitor := taskmonitor.New(s.logger, C.StopTimeout)
			monitor.Start("close ", name)
			closeErr := childScope.Close()
			monitor.Finish()
			done()
			if closeErr != nil {
				return E.Cause(closeErr, "close ", name)
			}
			return nil
		})
		s.children[component] = child
	}
	s.access.Unlock()
	done := LogElapsed(s.logger, stage, " ", name)
	monitor := taskmonitor.New(s.logger, C.StartTimeout)
	monitor.Start(stage, " ", name)
	err = component.Start(stage, child.scope)
	monitor.Finish()
	done()
	if err != nil {
		return E.Cause(err, stage, " ", name)
	}
	return nil
}

func (s *Scope) Remove(component Lifecycle) error {
	s.access.Lock()
	child, loaded := s.children[component]
	if !loaded {
		s.access.Unlock()
		return nil
	}
	delete(s.children, component)
	cleanup := s.cleanups.Remove(child.cleanup)
	s.access.Unlock()
	return cleanup()
}

func (s *Scope) Close() error {
	s.access.Lock()
	s.cancel()
	var cleanups []func() error
	for element := s.cleanups.Back(); element != nil; element = element.Prev() {
		cleanups = append(cleanups, element.Value)
	}
	s.cleanups.Init()
	s.children = nil
	s.access.Unlock()
	var err error
	for _, cleanup := range cleanups {
		err = E.Errors(err, cleanup())
	}
	return err
}

func LogElapsed(logger log.ContextLogger, description ...any) func() {
	prefix := F.ToString(description...)
	startTime := time.Now()
	timer := time.AfterFunc(time.Second, func() {
		logger.Trace(prefix, "...")
	})
	return func() {
		if timer.Stop() {
			return
		}
		logger.Trace(prefix, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
	}
}
