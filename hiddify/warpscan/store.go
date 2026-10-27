package warpscan

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// The endpoints that answered are kept in the cache file under the client's key plus this
// suffix, and tried first by the next scan.
const storeSuffix = "/warp-scanner"

func Load(cacheFile adapter.CacheFile, key string) []netip.AddrPort {
	if cacheFile == nil {
		return nil
	}
	saved := cacheFile.LoadBinary(key + storeSuffix)
	if saved == nil {
		return nil
	}
	var endpoints []netip.AddrPort
	if json.Unmarshal(saved.Content, &endpoints) != nil {
		return nil
	}
	return endpoints
}

func Save(cacheFile adapter.CacheFile, key string, endpoints []netip.AddrPort) error {
	if cacheFile == nil || len(endpoints) == 0 {
		return nil
	}
	content, err := json.Marshal(endpoints)
	if err != nil {
		return err
	}
	return cacheFile.SaveBinary(key+storeSuffix, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content})
}
