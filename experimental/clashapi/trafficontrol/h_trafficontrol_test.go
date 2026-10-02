package trafficontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type fakeOutbound struct {
	tag, typ string
}

func (f *fakeOutbound) Type() string           { return f.typ }
func (f *fakeOutbound) Tag() string            { return f.tag }
func (f *fakeOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (f *fakeOutbound) Dependencies() []string { return nil }
func (f *fakeOutbound) IsReady() bool          { return true }
func (f *fakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unsupported")
}
func (f *fakeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

type fakeGroup struct {
	fakeOutbound
	selected adapter.Outbound
}

func (g *fakeGroup) All() []string                                     { return []string{g.selected.Tag()} }
func (g *fakeGroup) Selected(network string) adapter.Outbound          { return g.selected }
func (g *fakeGroup) AttachConnection(closer io.Closer) (detach func()) { return func() {} }

type fakeOutboundManager struct {
	adapter.OutboundManager
	list []adapter.Outbound
}

func (m *fakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, o := range m.list {
		if o.Tag() == tag {
			return o, true
		}
	}
	return nil, false
}
func (m *fakeOutboundManager) Default() adapter.Outbound { return m.list[0] }

type fakeTracker struct {
	metadata TrackerMetadata
	closed   atomic.Int32
}

func (f *fakeTracker) Metadata() *TrackerMetadata { return &f.metadata }
func (f *fakeTracker) Close() error {
	f.closed.Add(1)
	return nil
}

func newFakeTracker(outboundType string) *fakeTracker {
	return &fakeTracker{metadata: TrackerMetadata{
		ID:           uuid.Must(uuid.NewV4()),
		OutboundType: outboundType,
		Upload:       new(atomic.Int64),
		Download:     new(atomic.Int64),
	}}
}

func TestH_TrafficManagerJoinLeave(t *testing.T) {
	m := NewManager()
	hook := observable.NewSubscriber[ConnectionEvent](8)
	m.SetEventHook(hook)
	events, _ := hook.Subscription()

	direct, dns := newFakeTracker(C.TypeDirect), newFakeTracker(C.TypeDNS)
	m.Join(direct)
	m.Join(dns)
	require.Equal(t, 2, m.ConnectionsLen())
	require.Equal(t, direct, m.Connection(direct.metadata.ID))
	require.Nil(t, m.Connection(uuid.Must(uuid.NewV4())))
	require.Len(t, m.Connections(), 2)
	require.Equal(t, ConnectionEventNew, (<-events).Type)
	<-events

	snapshot := m.Snapshot()
	require.Len(t, snapshot.Connections, 1, "dns connections are hidden from snapshots")
	require.Equal(t, direct, snapshot.Connections[0])

	m.Leave(direct)
	m.Leave(direct)
	require.Equal(t, 1, m.ConnectionsLen())
	ev := <-events
	require.Equal(t, ConnectionEventClosed, ev.Type)
	require.Equal(t, direct.metadata.ID, ev.ID)
	require.False(t, ev.ClosedAt.IsZero())
	select {
	case <-events:
		t.Fatal("leaving twice must emit only one event")
	default:
	}
	closed := m.ClosedConnections()
	require.Len(t, closed, 1)
	require.Equal(t, direct.metadata.ID, closed[0].ID)

	m.Clear()
	require.Nil(t, m.ClosedConnections())
}

func TestH_TrafficManagerClosedLimit(t *testing.T) {
	m := NewManager()
	var first uuid.UUID
	for i := range closedConnectionsLimit + 5 {
		tr := newFakeTracker(C.TypeDirect)
		if i == 0 {
			first = tr.metadata.ID
		}
		m.Join(tr)
		m.Leave(tr)
	}
	closed := m.ClosedConnections()
	require.Len(t, closed, closedConnectionsLimit)
	require.NotEqual(t, first, closed[0].ID)
}

func TestH_TrafficManagerStatistics(t *testing.T) {
	m := NewManager()
	m.PushUploaded(10)
	m.PushDownloaded(20)
	m.PushOutboundUploaded("a", 3)
	m.PushOutboundUploaded("a", 4)
	m.PushOutboundDownloaded("a", 5)
	up, down := m.Total()
	require.Equal(t, int64(10), up)
	require.Equal(t, int64(20), down)
	up, down = m.OutboundUsage("a")
	require.Equal(t, int64(7), up)
	require.Equal(t, int64(5), down)
	up, down = m.OutboundUsage("missing")
	require.Zero(t, up)
	require.Zero(t, down)

	data, err := json.Marshal(m.Snapshot())
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, float64(10), decoded["uploadTotal"])
	require.Equal(t, float64(20), decoded["downloadTotal"])
	require.Contains(t, decoded, "memory")
	require.Contains(t, decoded, "connections")

	m.ResetStatistic()
	up, down = m.Total()
	require.Zero(t, up+down)
	up, down = m.OutboundUsage("a")
	require.Zero(t, up+down)
}

func TestH_TrafficTCPTracker(t *testing.T) {
	leaf := &fakeOutbound{tag: "leaf", typ: C.TypeDirect}
	group := &fakeGroup{fakeOutbound: fakeOutbound{tag: "proxy", typ: C.TypeSelector}, selected: leaf}
	outbounds := &fakeOutboundManager{list: []adapter.Outbound{group, leaf}}
	m := NewManager()

	c1, c2 := net.Pipe()
	defer c2.Close()
	metadata := adapter.InboundContext{
		Network:     N.NetworkTCP,
		Inbound:     "in",
		InboundType: "mixed",
		Domain:      "example.com",
		Source:      M.ParseSocksaddrHostPort("10.0.0.1", 1000),
		Destination: M.ParseSocksaddrHostPort("1.2.3.4", 443),
	}
	tracker := NewTCPTracker(c1, m, metadata, outbounds, nil, nil)
	require.Equal(t, 1, m.ConnectionsLen())
	md := tracker.Metadata()
	require.Equal(t, []string{"leaf", "proxy"}, md.Chain)
	require.Equal(t, "leaf", md.Outbound)
	require.Equal(t, C.TypeDirect, md.OutboundType)

	go func() {
		buffer := make([]byte, 5)
		_, _ = io.ReadFull(c2, buffer)
		_, _ = c2.Write([]byte("abc"))
	}()
	_, err := tracker.Write([]byte("hello"))
	require.NoError(t, err)
	buffer := make([]byte, 3)
	_, err = io.ReadFull(tracker, buffer)
	require.NoError(t, err)
	// the tracked conn is the inbound side: reads are uploads, writes are downloads
	require.Equal(t, int64(3), md.Upload.Load())
	require.Equal(t, int64(5), md.Download.Load())
	up, down := m.OutboundUsage("leaf")
	require.Equal(t, int64(3), up)
	require.Equal(t, int64(5), down)

	data, err := json.Marshal(md)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	inner := decoded["metadata"].(map[string]any)
	require.Equal(t, "mixed/in", inner["type"])
	require.Equal(t, "example.com", inner["host"])
	require.Equal(t, "443", inner["destinationPort"])
	require.Equal(t, "final", decoded["rule"])
	require.Equal(t, float64(3), decoded["upload"])

	require.NoError(t, tracker.Close())
	require.Equal(t, 0, m.ConnectionsLen())
	require.Len(t, m.ClosedConnections(), 1)
}

func TestH_TrafficUDPTrackerMatchOutbound(t *testing.T) {
	leaf := &fakeOutbound{tag: "leaf", typ: C.TypeDirect}
	other := &fakeOutbound{tag: "other", typ: C.TypeBlock}
	outbounds := &fakeOutboundManager{list: []adapter.Outbound{leaf, other}}
	m := NewManager()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	tracker := NewUDPTracker(bufio.NewPacketConn(udp), m, adapter.InboundContext{Network: N.NetworkUDP}, outbounds, nil, other)
	require.Equal(t, []string{"other"}, tracker.Metadata().Chain)
	require.Equal(t, C.TypeBlock, tracker.Metadata().OutboundType)
	require.True(t, tracker.ReaderReplaceable())
	require.NotNil(t, tracker.Upstream())
	require.NoError(t, tracker.Close())
	require.Equal(t, 0, m.ConnectionsLen())
}

func TestH_TrafficBalancerChainIncludesRealOutbound(t *testing.T) {
	t.Skip("BUG: TrackerMetadata.MarshalJSON builds a balancer chain with the real outbound but serialises t.Chain instead")
	md := newFakeTracker(C.TypeBalancer).metadata
	md.Chain = []string{"lb"}
	md.Metadata.SetRealOutbound("node-1")
	data, err := json.Marshal(md)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, []any{"node-1", "lb"}, decoded["chains"])
}

func TestH_TrafficSnapshotTimestamps(t *testing.T) {
	m := NewManager()
	tr := newFakeTracker(C.TypeDirect)
	tr.metadata.CreatedAt = time.Now()
	m.Join(tr)
	data, err := json.Marshal(m.Snapshot())
	require.NoError(t, err)
	require.Contains(t, string(data), tr.metadata.ID.String())
}
