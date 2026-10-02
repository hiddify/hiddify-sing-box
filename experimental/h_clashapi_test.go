package experimental

import (
	"context"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

type hClashServer struct {
	adapter.ClashServer
	mode string
}

func (s *hClashServer) Mode() string {
	return s.mode
}

func TestH_NewClashServerConstructor(t *testing.T) {
	original := clashServerConstructor
	t.Cleanup(func() { clashServerConstructor = original })

	clashServerConstructor = nil
	server, err := NewClashServer(context.Background(), nil, option.ClashAPIOptions{})
	require.ErrorIs(t, err, os.ErrInvalid)
	require.Nil(t, server)

	var received option.ClashAPIOptions
	RegisterClashServerConstructor(func(ctx context.Context, logFactory log.ObservableFactory, options option.ClashAPIOptions) (adapter.ClashServer, error) {
		received = options
		return &hClashServer{mode: options.DefaultMode}, nil
	})
	server, err = NewClashServer(context.Background(), nil, option.ClashAPIOptions{DefaultMode: "rule", ExternalController: "127.0.0.1:9090"})
	require.NoError(t, err)
	require.Equal(t, "rule", server.Mode())
	require.Equal(t, "127.0.0.1:9090", received.ExternalController)
}
