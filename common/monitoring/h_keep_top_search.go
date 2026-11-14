package monitoring

import (
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// Some lazy outbounds register or search before they work (WARP registers a device and scans
// for an endpoint that answers): their tests fail until they are through, and closing them starts
// it over. Keep top does not put such a one to rest for failing while there is a place for it:
//
//   - One whose real outbound exists (a test created it) and that says it registers or searches
//     (adapter.IsWarming) is a searcher. While fewer answer than are kept (or the pick is under
//     way), it is used beside the kept ones, so it goes on; the lazy outbound does not close it
//     while it is idle either.
//   - Once it is ready it is tested at once. If it answers it takes a free place as any outbound
//     at rest that answers does (keepTopBackLocked), or the pick under way weighs it.
//   - When there is no place for it any more (count answer), it rests, which stops its search.

// keepTopSearchPoll is how often the searchers are looked at: their status changes untold.
var keepTopSearchPoll = 2 * time.Second // a variable for the tests

// keepTopSearchAnswer is how long after a searcher was through its test may take, before it is
// no longer one and the usual rules apply.
const keepTopSearchAnswer = 30 * time.Second

// keepTopSearchRoomLocked reports whether there is a place for a searcher: a pick is under way,
// or fewer are kept than may be.
func (m *OutboundMonitoring) keepTopSearchRoomLocked() bool {
	k := &m.keepTop
	if k.picking {
		return true
	}
	room, _ := m.keepTopRoomLocked()
	return room > 0
}

// keepTopWatchSearchersLocked finds the searchers and follows them: a new one, one through,
// one that failed, one with no place any more. It reports whether what is used must change.
func (m *OutboundMonitoring) keepTopWatchSearchersLocked(now time.Time) bool {
	k := &m.keepTop
	if !k.on {
		return false
	}
	room := m.keepTopSearchRoomLocked()
	changed := false
	drop := func(tag string) {
		if _, was := k.searching[tag]; was {
			delete(k.searching, tag)
			changed = true
		}
	}
	for _, tag := range k.tags {
		lazy, isLazy := k.owners[tag].(adapter.LazyOutbound)
		if !isLazy || !lazy.Loaded() || slices.Contains(k.loaded, tag) {
			drop(tag) // not created, or used by the pick itself
			continue
		}
		status := lazy.Status()
		readyAt, was := k.searching[tag]
		switch {
		case status == adapter.StatusFailed:
			drop(tag)
		case !was && !adapter.IsWarming(status):
			// not a searcher: the usual rules
		case !room:
			drop(tag)
			go lazy.Unload() // at rest, its search stops
			m.logger.Info("KEEP TOP ", tag, " stops searching: enough answer")
		case status == adapter.StatusReady && readyAt.IsZero():
			k.searching[tag] = now
			go m.TestOutbounds([]string{tag}, "keep top: it is through, is it fast")
			m.logger.Info("KEEP TOP ", tag, " is through its search, testing it")
		case status == adapter.StatusReady:
			// through: once its test answered, or had its time, the usual rules
			if ping := k.pings[tag]; (ping != nil && ping.Time >= readyAt.Unix() && pingAlive(ping.Delay)) || now.Sub(readyAt) >= keepTopSearchAnswer {
				drop(tag)
			}
		case !was:
			if k.searching == nil {
				k.searching = make(map[string]time.Time)
			}
			k.searching[tag] = time.Time{}
			changed = true
			m.logger.Info("KEEP TOP ", tag, " ", status, ": it is used while it does, as fewer answer than are kept")
		}
	}
	for tag := range k.searching {
		if _, managed := k.owners[tag]; !managed {
			drop(tag)
		}
	}
	return changed
}

// keepTopWithSearchersLocked is loaded with the searchers beside it, while there is a place for
// them.
func (m *OutboundMonitoring) keepTopWithSearchersLocked(loaded []string) []string {
	k := &m.keepTop
	m.keepTopWatchSearchersLocked(time.Now())
	if len(k.searching) == 0 {
		return loaded
	}
	with := slices.Clone(loaded)
	for tag := range k.searching {
		if !slices.Contains(with, tag) {
			with = append(with, tag)
		}
	}
	slices.Sort(with)
	return with
}
