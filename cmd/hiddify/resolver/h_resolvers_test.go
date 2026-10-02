package main

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestH_EmbeddedResolversAreIPs(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, resolvers)
	var count int
	var invalid []string
	for i, line := range strings.Split(resolvers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		count++
		if net.ParseIP(line) == nil {
			invalid = append(invalid, line)
			if len(invalid) < 10 {
				t.Logf("line %d: %q is not an IP", i+1, line)
			}
		}
	}
	require.Greater(t, count, 0)
	require.Empty(t, invalid, "%d invalid resolver entries", len(invalid))
	require.Contains(t, resolvers, "8.8.8.8")
	require.Contains(t, resolvers, "1.1.1.1")
}
