package warpscan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// The score book is kept in the cache file under the client's key plus this suffix.
const storeSuffix = "/warp-scanner"

// Load returns the client's score book, or an empty one.
func Load(cacheFile adapter.CacheFile, key string) *Book {
	book := NewBook()
	if cacheFile == nil {
		return book
	}
	saved := cacheFile.LoadBinary(key + storeSuffix)
	if saved != nil {
		// an unreadable or older format starts over
		_ = json.Unmarshal(saved.Content, book)
	}
	return book
}

func Save(cacheFile adapter.CacheFile, key string, book *Book) error {
	if cacheFile == nil {
		return nil
	}
	content, err := json.Marshal(book)
	if err != nil {
		return err
	}
	return cacheFile.SaveBinary(key+storeSuffix, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content})
}

// Network describes the network the box is on: the default interface's type and the network
// environment (its gateways, and the Wi-Fi name or the gateway's hardware address). It also
// reports which address families the interface has a global address of.
func Network(ctx context.Context) (name string, ipv4 bool, ipv6 bool) {
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return "default", true, true
	}
	defaultInterface := networkManager.DefaultNetworkInterface()
	if defaultInterface == nil {
		return fmt.Sprintf("unknown/%x", networkManager.NetworkEnvironment()), true, true
	}
	for _, prefix := range defaultInterface.Addresses {
		address := prefix.Addr()
		if !address.IsGlobalUnicast() || address.IsPrivate() && address.Is6() {
			continue
		}
		if address.Is4() || address.Is4In6() {
			ipv4 = true
		} else {
			ipv6 = true
		}
	}
	if !ipv4 && !ipv6 {
		// addresses unknown (some platforms): try both
		ipv4, ipv6 = true, true
	}
	return fmt.Sprintf("%s/%x", defaultInterface.Type, networkManager.NetworkEnvironment()), ipv4, ipv6
}

