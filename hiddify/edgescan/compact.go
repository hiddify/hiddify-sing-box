package edgescan

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"
)

// The book is saved in a compact form, as it grows with every network, target, block and
// method it rates: a record is an array of numbers, a time is in Unix seconds (0 for none), and
// the keys are short.
//
//	{"v":2,"n":{"<network>":{"t":<last seen>,
//	  "r":{"<target>":[score,last success,last failure,rtt ms]},
//	  "m":{"<method>":[score,last success,last failure]},
//	  "b":{"<block>":[score,last success,last failure]},
//	  "w":{"<walk>":"<seed>:<next>:<last used>"}}}}
const compactVersion = 2

var errNotCompact = errors.New("not the compact format")

type compactBook struct {
	Version  int                        `json:"v"`
	Networks map[string]*compactNetwork `json:"n"`
}

type compactNetwork struct {
	LastSeen int64              `json:"t"`
	Records  map[string][]int64 `json:"r,omitempty"`
	Methods  map[string][]int64 `json:"m,omitempty"`
	Blocks   map[string][]int64 `json:"b,omitempty"`
	Walks    map[string]string  `json:"w,omitempty"`
}

func unixOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOf(seconds int64) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

func ratingArray(record rating.Record) []int64 {
	return []int64{int64(record.Score), unixOf(record.LastSuccess), unixOf(record.LastFailure)}
}

func ratingOf(values []int64) (rating.Record, bool) {
	if len(values) < 3 {
		return rating.Record{}, false
	}
	return rating.Record{Score: rating.Clamp(int(values[0])), LastSuccess: timeOf(values[1]), LastFailure: timeOf(values[2])}, true
}

func marshalCompact(networks map[string]*network) ([]byte, error) {
	book := compactBook{Version: compactVersion, Networks: make(map[string]*compactNetwork, len(networks))}
	for name, n := range networks {
		saved := &compactNetwork{LastSeen: unixOf(n.LastSeen)}
		if len(n.Records) > 0 {
			saved.Records = make(map[string][]int64, len(n.Records))
			for key, record := range n.Records {
				saved.Records[key] = append(ratingArray(record.Record), record.RTT.Milliseconds())
			}
		}
		if len(n.Methods) > 0 {
			saved.Methods = make(map[string][]int64, len(n.Methods))
			for key, record := range n.Methods {
				saved.Methods[key] = ratingArray(*record)
			}
		}
		if len(n.Blocks) > 0 {
			saved.Blocks = make(map[string][]int64, len(n.Blocks))
			for key, record := range n.Blocks {
				saved.Blocks[key.String()] = ratingArray(*record)
			}
		}
		if len(n.Walks) > 0 {
			saved.Walks = make(map[string]string, len(n.Walks))
			for key, walk := range n.Walks {
				saved.Walks[key] = strconv.FormatUint(walk.Seed, 36) + ":" + strconv.FormatUint(walk.Next, 36) + ":" + strconv.FormatInt(unixOf(walk.LastUsed), 36)
			}
		}
		book.Networks[name] = saved
	}
	return json.Marshal(book)
}

func unmarshalCompact(content []byte) (map[string]*network, error) {
	var book compactBook
	if err := json.Unmarshal(content, &book); err != nil || book.Version != compactVersion {
		return nil, errNotCompact
	}
	networks := make(map[string]*network, len(book.Networks))
	for name, saved := range book.Networks {
		if saved == nil {
			continue
		}
		n := &network{
			LastSeen: timeOf(saved.LastSeen),
			Records:  make(map[string]*Record, len(saved.Records)),
			Methods:  make(map[string]*rating.Record, len(saved.Methods)),
			Blocks:   make(map[netip.Prefix]*rating.Record, len(saved.Blocks)),
			Walks:    make(map[string]*walk, len(saved.Walks)),
		}
		for key, values := range saved.Records {
			record, ok := ratingOf(values)
			if _, err := ParseTarget(key); !ok || err != nil {
				continue
			}
			var rtt time.Duration
			if len(values) > 3 {
				rtt = time.Duration(values[3]) * time.Millisecond
			}
			n.Records[key] = &Record{Record: record, RTT: rtt}
		}
		for key, values := range saved.Methods {
			if record, ok := ratingOf(values); ok {
				n.Methods[key] = &record
			}
		}
		for key, values := range saved.Blocks {
			prefix, err := netip.ParsePrefix(key)
			if record, ok := ratingOf(values); ok && err == nil {
				n.Blocks[prefix] = &record
			}
		}
		for key, value := range saved.Walks {
			parts := strings.Split(value, ":")
			if len(parts) != 3 {
				continue
			}
			seed, err1 := strconv.ParseUint(parts[0], 36, 64)
			next, err2 := strconv.ParseUint(parts[1], 36, 64)
			used, err3 := strconv.ParseInt(parts[2], 36, 64)
			if err1 == nil && err2 == nil && err3 == nil {
				n.Walks[key] = &walk{Seed: seed, Next: next, LastUsed: timeOf(used)}
			}
		}
		networks[name] = n
	}
	return networks, nil
}
