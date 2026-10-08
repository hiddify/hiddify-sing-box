package dnstt

import (
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter/outbound"
)

// registries are built for every new context, possibly at the same time
func TestH_RegisterOutboundConcurrently(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RegisterOutbound(outbound.NewRegistry())
		}()
	}
	wg.Wait()
	if len(resolverCountry) == 0 {
		t.Fatal("resolvers not loaded")
	}
}
