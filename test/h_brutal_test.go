package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// requireBrutal skips a TCP Brutal test where the kernel has no brutal congestion control: Brutal
// is Linux-only and needs the tcp_brutal module (github.com/apernet/tcp-brutal) loaded.
func requireBrutal(t *testing.T) {
	t.Helper()
	available, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
	if err != nil || !slices.Contains(strings.Fields(string(available)), "brutal") {
		t.Skip("TCP Brutal needs Linux with the tcp_brutal module loaded")
	}
}
