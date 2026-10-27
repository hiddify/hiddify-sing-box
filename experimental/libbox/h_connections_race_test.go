package libbox

import (
	"strconv"
	"sync"
	"testing"
)

// The platform applies connection events on the command client's thread while the UI
// filters, sorts and iterates on its own; run with -race.
func TestH_ConnectionsConcurrentAccess(t *testing.T) {
	connections := NewConnections()
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for i := range 200 {
			id := strconv.Itoa(i)
			connections.ApplyEvents(&ConnectionEvents{events: []*ConnectionEvent{
				{Type: ConnectionEventNew, ID: id, Connection: &Connection{ID: id, CreatedAt: int64(i)}},
				{Type: ConnectionEventUpdate, ID: id, UplinkDelta: 1},
			}})
		}
	}()
	go func() {
		defer wait.Done()
		for i := range 200 {
			connections.FilterState(int32(i % 3))
			connections.SortByDate()
			connections.SortByTraffic()
			for iterator := connections.Iterator(); iterator.HasNext(); {
				iterator.Next()
			}
		}
	}()
	wait.Wait()
}
