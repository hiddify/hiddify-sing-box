package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type nilUnwrap struct{}

func (nilUnwrap) Error() string { return "nil unwrap" }
func (nilUnwrap) Unwrap() error { return nil }

func TestH_Cause(t *testing.T) {
	t.Parallel()
	require.Nil(t, Cause(nil))
	root := errors.New("root")
	require.Same(t, root, Cause(root))
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("middle: %w", root))
	require.Same(t, root, Cause(wrapped))
	stop := nilUnwrap{}
	require.Equal(t, stop, Cause(fmt.Errorf("x: %w", stop)))
}
