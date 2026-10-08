package daemon

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// HotReload applies options to the running instance without restarting it (see box.HotReload).
// The options get the same service additions as at start (TUN overrides, OOM killer), and are
// copied, so the caller's options are not changed. //H
func (s *StartedService) HotReload(ctx context.Context, options *option.Options) (box.HotReloadResult, error) {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	instance, newOptions, err := s.hotReloadOptions(options)
	if err != nil {
		return box.HotReloadResult{}, err
	}
	return instance.Box().HotReloadWithResult(ctx, newOptions)
}

// IsTunChanged reports whether options would change the running TUN inbound (see box.IsTunChanged).
func (s *StartedService) IsTunChanged(ctx context.Context, options *option.Options) (bool, error) {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	instance, newOptions, err := s.hotReloadOptions(options)
	if err != nil {
		return false, err
	}
	return instance.Box().IsTunChanged(ctx, newOptions)
}

// hotReloadOptions copies options and adds what the service added at start.
func (s *StartedService) hotReloadOptions(options *option.Options) (*Instance, *option.Options, error) {
	if options == nil {
		return nil, nil, E.New("missing options")
	}
	instance := s.Instance()
	if instance == nil || instance.Box() == nil {
		return nil, nil, E.New("service is not running")
	}
	instanceCtx := instance.Context()
	content, err := json.MarshalContext(instanceCtx, options)
	if err != nil {
		return nil, nil, E.Cause(err, "encode config")
	}
	newOptions, err := parseConfig(instanceCtx, string(content))
	if err != nil {
		return nil, nil, err
	}
	s.applyServiceOptions(&newOptions, instance.overrideOptions)
	return instance, &newOptions, nil
}
