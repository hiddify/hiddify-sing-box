package xhttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"container/heap"
	"io"
	"runtime"
	"sync"
	"sync/atomic"

	E "github.com/sagernet/sing/common/exceptions"
)

type Packet struct {
	Reader  io.ReadCloser
	Payload []byte
	Seq     uint64
}

type uploadQueue struct {
	reader          io.ReadCloser
	readerAccess    sync.Mutex // reader is set by Read and by Close's drain
	nomore          bool
	pushedPackets   chan Packet
	writeCloseMutex sync.Mutex
	heap            uploadHeap
	nextSeq         uint64
	closed          atomic.Bool   // read by Read without writeCloseMutex
	closing         chan struct{} // closed by Close before it waits for writeCloseMutex
	closeOnce       sync.Once
	maxPackets      int
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		closing:       make(chan struct{}),
		heap:          uploadHeap{},
		nextSeq:       0,
		maxPackets:    maxPackets,
	}
}

func (h *uploadQueue) Push(p Packet) error {
	h.writeCloseMutex.Lock()
	defer h.writeCloseMutex.Unlock()
	if h.closed.Load() {
		return E.New("packet queue closed")
	}
	if h.nomore {
		return E.New("h.reader already exists")
	}
	// a full queue that nobody reads would hold writeCloseMutex here, and Close with it, forever
	select {
	case h.pushedPackets <- p:
	case <-h.closing:
		return E.New("packet queue closed")
	}
	if p.Reader != nil {
		h.nomore = true
	}
	return nil
}

func (h *uploadQueue) Close() error {
	h.closeOnce.Do(func() { close(h.closing) }) // a blocked Push gives up the mutex
	h.writeCloseMutex.Lock()
	defer h.writeCloseMutex.Unlock()
	if !h.closed.Load() {
		h.closed.Store(true)
		runtime.Gosched() // hope Read() gets the packet
	f:
		for {
			select {
			case p := <-h.pushedPackets:
				if p.Reader != nil {
					h.setReader(p.Reader)
				}
			default:
				break f
			}
		}
		close(h.pushedPackets)
	}
	if reader := h.currentReader(); reader != nil {
		return reader.Close()
	}
	return nil
}

func (h *uploadQueue) currentReader() io.ReadCloser {
	h.readerAccess.Lock()
	defer h.readerAccess.Unlock()
	return h.reader
}

func (h *uploadQueue) setReader(reader io.ReadCloser) {
	h.readerAccess.Lock()
	h.reader = reader
	h.readerAccess.Unlock()
}

func (h *uploadQueue) Read(b []byte) (int, error) {
	if reader := h.currentReader(); reader != nil {
		return reader.Read(b)
	}
	if h.closed.Load() {
		return 0, io.EOF
	}
	if len(h.heap) == 0 {
		packet, more := <-h.pushedPackets
		if !more {
			return 0, io.EOF
		}
		if packet.Reader != nil {
			h.setReader(packet.Reader)
			return packet.Reader.Read(b)
		}
		heap.Push(&h.heap, packet)
	}
	for len(h.heap) > 0 {
		packet := heap.Pop(&h.heap).(Packet)
		n := 0

		if packet.Seq == h.nextSeq {
			copy(b, packet.Payload)
			n = min(len(b), len(packet.Payload))

			if n < len(packet.Payload) {
				// partial read
				packet.Payload = packet.Payload[n:]
				heap.Push(&h.heap, packet)
			} else {
				h.nextSeq = packet.Seq + 1
			}

			return n, nil
		}
		// misordered packet
		if packet.Seq > h.nextSeq {
			if len(h.heap) > h.maxPackets {
				// the "reassembly buffer" is too large, and we want to
				// constrain memory usage somehow. let's tear down the
				// connection, and hope the application retries.
				return 0, E.New("packet queue is too large")
			}
			heap.Push(&h.heap, packet)
			packet2, more := <-h.pushedPackets
			if !more {
				return 0, io.EOF
			}
			heap.Push(&h.heap, packet2)
		}
	}
	return 0, nil
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
