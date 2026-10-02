//go:build linux && !android

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_LinuxPlatformSystemCertificates(t *testing.T) {
	t.Parallel()
	require.Nil(t, (&linuxPlatformInterface{}).SystemCertificates())
}
