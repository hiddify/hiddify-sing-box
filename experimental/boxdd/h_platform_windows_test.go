//go:build windows

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_WindowsPlatformSystemCertificates(t *testing.T) {
	t.Parallel()
	require.Nil(t, (&windowsPlatformInterface{}).SystemCertificates())
}
