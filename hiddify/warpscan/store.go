package warpscan

import (
	"encoding/json"
	"time"

	"github.com/sagernet/sing-box/adapter"
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
