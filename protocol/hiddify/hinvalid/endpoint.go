package hinvalid

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.HInvalidOptions](registry, C.TypeHInvalidConfig, NewEndpoint)
}

var _ adapter.Endpoint = (*Endpoint)(nil)

// Endpoint is a placeholder for an endpoint whose options could not be parsed or initialized.
// It blocks every connection instead of failing the whole config.
type Endpoint struct {
	*Outbound
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, invalidOptions option.HInvalidOptions) (adapter.Endpoint, error) {
	out, err := New(ctx, router, logger, tag, invalidOptions)
	if err != nil {
		return nil, err
	}
	return &Endpoint{Outbound: out.(*Outbound)}, nil
}

func (h *Endpoint) Start(stage adapter.StartStage) error {
	return nil
}

func (h *Endpoint) Close() error {
	return nil
}
