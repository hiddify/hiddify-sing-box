package adapter

import (
	"io"

	"github.com/sagernet/sing/common"
)

// Hot reload creates and removes components after the box has started. The managers start
// such a component in its own child scope, the way the box starts the rest, and close it by
// closing that child scope alone. //H

// AsLifecycle returns how a scope starts and closes a component. Components written for the
// lifecycle before scopes (outbounds may skip Lifecycle) are driven the way the managers used
// to drive them: PreStart at initialize, Start at start, PostStart once started, and Close
// when the scope closes.
func AsLifecycle(component any) (Lifecycle, bool) {
	if lifecycle, isLifecycle := component.(Lifecycle); isLifecycle {
		return lifecycle, true
	}
	switch component.(type) {
	case interface{ PreStart() error }, interface{ Start() error }, interface{ PostStart() error }, io.Closer:
		return legacyLifecycle{component}, true
	}
	return nil, false
}

type legacyLifecycle struct {
	component any
}

func (c legacyLifecycle) Start(stage StartStage, scope *Scope) error {
	switch stage {
	case StartStateInitialize:
		if closer, isCloser := c.component.(io.Closer); isCloser {
			scope.Add(closer.Close)
		}
		if preStarter, isPreStarter := c.component.(interface{ PreStart() error }); isPreStarter {
			return preStarter.PreStart()
		}
	case StartStateStart:
		if starter, isStarter := c.component.(interface{ Start() error }); isStarter {
			return starter.Start()
		}
	case StartStateStarted:
		if postStarter, isPostStarter := c.component.(interface{ PostStart() error }); isPostStarter {
			return postStarter.PostStart()
		}
	}
	return nil
}

// StartLate runs a component created after its manager started through every start stage.
// A component that fails to start is closed again.
func StartLate(scope *Scope, name string, component any) error {
	lifecycle, isLifecycle := AsLifecycle(component)
	if !isLifecycle {
		return nil
	}
	for _, stage := range ListStartStages {
		err := scope.Start(name, lifecycle, stage)
		if err != nil {
			scope.closeChild(lifecycle)
			return err
		}
	}
	return nil
}

// CloseLate closes one component of scope, without touching the others. The cleanup the scope
// keeps for it does nothing when the whole scope closes later, since a scope closes only once.
// A component that was never started in scope is closed directly, if it can be.
func CloseLate(scope *Scope, component any) error {
	if lifecycle, isLifecycle := AsLifecycle(component); isLifecycle && scope != nil {
		if closed, err := scope.closeChild(lifecycle); closed {
			return err
		}
	}
	return common.Close(component)
}

func (s *Scope) closeChild(component Lifecycle) (bool, error) {
	s.access.Lock()
	child, loaded := s.children[component]
	if loaded {
		delete(s.children, component)
	}
	s.access.Unlock()
	if !loaded {
		return false, nil
	}
	return true, child.Close()
}
