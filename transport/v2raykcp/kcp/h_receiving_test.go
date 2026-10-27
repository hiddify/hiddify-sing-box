package kcp

import (
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// Read keeps what does not fit in leftOver; Release, from Terminate, frees it from another
// goroutine. Run with -race.
func TestH_ReceivingWorkerReadRelease(t *testing.T) {
	worker := &ReceivingWorker{window: NewReceivingWindow()}
	var group sync.WaitGroup
	for range 100 {
		chunk := buf.New()
		chunk.Extend(64)
		worker.Lock()
		worker.leftOver = buf.MultiBuffer{chunk}
		worker.Unlock()
		group.Add(2)
		go func() {
			defer group.Done()
			worker.Read(make([]byte, 16))
		}()
		go func() {
			defer group.Done()
			worker.Release()
		}()
		group.Wait()
	}
}
