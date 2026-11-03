package adapter_test

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

func TestH_LastError(t *testing.T) {
	var last adapter.LastError
	require.NoError(t, last.Get())
	last.Set(errors.New("refused"))
	require.EqualError(t, last.Get(), "refused")
	last.Set(nil)
	require.NoError(t, last.Get())
}
