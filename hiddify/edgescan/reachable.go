package edgescan

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

// A search spends battery and CPU on probes that cannot succeed when the device has no network
// (no Wi-Fi, no mobile data) or the system paused it (a phone asleep): it waits for the network
// instead, and the wait does not count toward its time (see Search).

// reachableRecheck is how often a wait looks again without an event: the events of the network
// monitor are the signal, this is the fallback.
const reachableRecheck = 30 * time.Second

// Reachable reports whether the box has a network to probe through: the device and the network
// are not paused, and there is a default interface, when the box watches it. Without a network
// manager (a test), it is reachable.
func Reachable(ctx context.Context) bool {
	if manager := service.FromContext[pause.Manager](ctx); manager != nil && (manager.IsDevicePaused() || manager.IsNetworkPaused()) {
		return false
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil || networkManager.InterfaceMonitor() == nil {
		return true
	}
	return networkManager.DefaultNetworkInterface() != nil
}

// WaitReachable waits until the box has a network (see Reachable), and returns how long it
// waited; false when ctx ends first. It wakes on the network monitor's and the pause manager's
// events, without polling.
func WaitReachable(ctx context.Context, logger logger.ContextLogger) (time.Duration, bool) {
	if Reachable(ctx) {
		return 0, true
	}
	start := time.Now()
	changed := make(chan struct{}, 1)
	signal := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	if networkManager := service.FromContext[adapter.NetworkManager](ctx); networkManager != nil {
		if monitor := networkManager.InterfaceMonitor(); monitor != nil {
			element := monitor.RegisterCallback(func(*control.Interface, int) { signal() })
			defer monitor.UnregisterCallback(element)
		}
	}
	if manager := service.FromContext[pause.Manager](ctx); manager != nil {
		element := manager.RegisterCallback(func(int) { signal() })
		defer manager.UnregisterCallback(element)
	}
	if logger != nil {
		logger.DebugContext(ctx, "no network: the search waits for one")
	}
	recheck := time.NewTicker(reachableRecheck)
	defer recheck.Stop()
	for !Reachable(ctx) {
		select {
		case <-ctx.Done():
			return time.Since(start), false
		case <-changed:
		case <-recheck.C:
		}
	}
	return time.Since(start), true
}
