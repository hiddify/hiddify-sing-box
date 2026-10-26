// Package htest starts and closes single components in tests, the way a box would:
// each component gets its own scope, which Close closes. //H
package htest

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
)

var scopes sync.Map // component -> *adapter.Scope

// Start runs stage of component in the component's scope, creating the scope on first use.
func Start(component adapter.Lifecycle, stage adapter.StartStage) error {
	scope, _ := scopes.LoadOrStore(component, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger()))
	return scope.(*adapter.Scope).Start("test", component, stage)
}

// StartAll runs every start stage of component.
func StartAll(component adapter.Lifecycle) error {
	for _, stage := range adapter.ListStartStages {
		err := Start(component, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

// Close closes the scope of a component started with Start, or the component itself
// if it was never started that way and can be closed.
func Close(component any) error {
	if scope, loaded := scopes.LoadAndDelete(component); loaded {
		return scope.(*adapter.Scope).Close()
	}
	return common.Close(component)
}
