package edgescan

import (
	"encoding/json"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// Load returns the score book kept in the cache file under key, or an empty one.
func Load(cacheFile adapter.CacheFile, key string) *Book {
	book := NewBook()
	if cacheFile == nil {
		return book
	}
	saved := cacheFile.LoadBinary(key)
	if saved != nil {
		// an unreadable or older format starts over
		_ = json.Unmarshal(saved.Content, book)
	}
	return book
}

// Save keeps book in the cache file under key.
func Save(cacheFile adapter.CacheFile, key string, book *Book) error {
	if cacheFile == nil {
		return nil
	}
	content, err := json.Marshal(book)
	if err != nil {
		return err
	}
	return cacheFile.SaveBinary(key, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content})
}
