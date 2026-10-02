package common

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type closable struct{ closed int }

func (c *closable) Close() error {
	c.closed++
	return nil
}

type interruptible struct {
	closable
	interrupted bool
}

func (i *interruptible) Interrupt() { i.interrupted = true }

func TestH_MustHelpers(t *testing.T) {
	t.Parallel()
	require.NotPanics(t, func() { Must(nil) })
	require.Panics(t, func() { Must(errors.New("x")) })
	require.Equal(t, 5, Must2(5, nil))
	require.Panics(t, func() { Must2(5, errors.New("x")) })
	expected := errors.New("e")
	require.Same(t, expected, Error2(1, expected))
	require.NoError(t, Error2(1, nil))
}

func TestH_CloseAndInterrupt(t *testing.T) {
	t.Parallel()
	c := &closable{}
	require.NoError(t, Close(c))
	require.Equal(t, 1, c.closed)
	require.NoError(t, Close(42))

	require.NoError(t, CloseIfExists(nil))
	var nilClosable *closable
	require.NoError(t, CloseIfExists(nilClosable))
	require.NoError(t, CloseIfExists(c))
	require.Equal(t, 2, c.closed)

	i := &interruptible{}
	require.NoError(t, Interrupt(i))
	require.True(t, i.interrupted)
	require.Zero(t, i.closed)
	require.NoError(t, Interrupt(c))
	require.Equal(t, 3, c.closed)
}
