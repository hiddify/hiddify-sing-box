package xhttp

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/xray/net"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

type XmuxConn interface {
	IsClosed() bool
}

type XmuxClient struct {
	XmuxConn     XmuxConn
	OpenUsage    atomic.Int32
	leftUsage    int32
	LeftRequests atomic.Int32
	UnreusableAt time.Time
	NotUsed      atomic.Bool  // taken out of the manager: closed as soon as nothing runs on it
	manager      *XmuxManager //H
	idleSince    atomic.Int64 //H: when its last connection ended (unix nanoseconds); 0 while it is in use
}

func (c *XmuxClient) AddRunning() {
	c.OpenUsage.Add(1)
	c.idleSince.Store(0) //H
}

func (c *XmuxClient) DoneRunning() {
	if c.OpenUsage.Add(-1) <= 0 {
		c.idleSince.Store(time.Now().UnixNano()) //H
		c.manager.hIdle()                        //H
	}
	c.maybeClose()
}

// close the XmuxConn if it is not used and has no running requests
func (c *XmuxClient) maybeClose() {
	if c.NotUsed.Load() && c.OpenUsage.Load() <= 0 {
		common.Close(c.XmuxConn)
	}
}

type XmuxManager struct {
	options     option.V2RayXHTTPXmuxOptions
	concurrency int32
	connections int32
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	mtx         sync.Mutex
	trimTimer   *time.Timer //H: closes the clients that stay idle, see hTrim
}

func NewXmuxManager(options option.V2RayXHTTPXmuxOptions, newConnFunc func() XmuxConn) *XmuxManager {
	return &XmuxManager{
		options:     options,
		concurrency: options.GetNormalizedMaxConcurrency().Rand(),
		connections: options.GetNormalizedMaxConnections().Rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
	}
}

func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:  m.newConnFunc(),
		leftUsage: -1,
		manager:   m, //H
	}
	if x := m.options.GetNormalizedCMaxReuseTimes().Rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.options.GetNormalizedHMaxRequestTimes().Rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	if x := m.options.GetNormalizedHMaxReusableSecs().Rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	return xmuxClient
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	xmuxClient := m.getXmuxClient()
	xmuxClient.idleSince.Store(0) //H: handed out, so not idle: hTrim leaves it alone
	return xmuxClient
}

func (m *XmuxManager) getXmuxClient() *XmuxClient {
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		if xmuxClient.XmuxConn.IsClosed() ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && time.Now().After(xmuxClient.UnreusableAt)) {
			xmuxClient.NotUsed.Store(true)
			xmuxClient.maybeClose()
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
		} else {
			i++
		}
	}
	if len(m.xmuxClients) == 0 {
		return m.newXmuxClient()
	}
	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		return m.newXmuxClient()
	}
	xmuxClients := make([]*XmuxClient, 0)
	if m.concurrency > 0 {
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.OpenUsage.Load() < m.concurrency {
				xmuxClients = append(xmuxClients, xmuxClient)
			}
		}
	} else {
		xmuxClients = m.xmuxClients
	}
	if len(xmuxClients) == 0 {
		return m.newXmuxClient()
	}
	i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(xmuxClients))))
	xmuxClient := xmuxClients[i.Int64()]
	if xmuxClient.leftUsage > 0 {
		xmuxClient.leftUsage -= 1
	}
	return xmuxClient
}

// The connections to the server are closed when they are no longer needed. //H
//
// With max_concurrency 1, the default, every proxied connection has an HTTP connection of its
// own, and when it ends that connection stays open to be used again: a page that opened thirty
// connections leaves thirty TLS or QUIC connections to the server, each sending its keep-alive
// (QUIC every 10 seconds) until h_max_reusable_secs is over, up to 50 minutes later. So a client
// with nothing on it is closed after hXmuxIdle. The one used last is kept for hXmuxKeep, so that
// the next connection after a pause still starts without a handshake.
var (
	hXmuxIdle = time.Minute
	hXmuxKeep = net.ConnIdleTimeout
)

// hIdle is called when a client's last connection ended: it is looked at again after hXmuxIdle.
func (m *XmuxManager) hIdle() {
	if m == nil {
		return
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.trimTimer == nil {
		m.trimTimer = time.AfterFunc(hXmuxIdle, m.hTrim)
	}
}

// hTrim closes the clients that have been idle for too long.
func (m *XmuxManager) hTrim() {
	m.mtx.Lock()
	m.trimTimer = nil
	now := time.Now().UnixNano()
	var (
		latest   *XmuxClient
		latestAt int64
	)
	for _, xmuxClient := range m.xmuxClients {
		if at := xmuxClient.idleSince.Load(); at > latestAt && xmuxClient.OpenUsage.Load() <= 0 {
			latest, latestAt = xmuxClient, at
		}
	}
	var (
		closing []*XmuxClient
		next    int64 // when the next idle client is due
	)
	kept := make([]*XmuxClient, 0, len(m.xmuxClients))
	for _, xmuxClient := range m.xmuxClients {
		at := xmuxClient.idleSince.Load()
		if at == 0 || xmuxClient.OpenUsage.Load() > 0 {
			kept = append(kept, xmuxClient)
			continue
		}
		limit := hXmuxIdle
		if xmuxClient == latest {
			limit = hXmuxKeep
		}
		due := at + int64(limit)
		if due <= now {
			closing = append(closing, xmuxClient)
			continue
		}
		kept = append(kept, xmuxClient)
		if next == 0 || due < next {
			next = due
		}
	}
	m.xmuxClients = kept
	if next != 0 {
		m.trimTimer = time.AfterFunc(time.Duration(next-now)+time.Millisecond, m.hTrim)
	}
	m.mtx.Unlock()
	for _, xmuxClient := range closing {
		xmuxClient.NotUsed.Store(true)
		xmuxClient.maybeClose()
	}
}

// Close closes every connection to the server. The manager can be used again: the next
// connection makes a new one. //H
func (m *XmuxManager) Close() error {
	m.mtx.Lock()
	xmuxClients := m.xmuxClients
	m.xmuxClients = make([]*XmuxClient, 0)
	if m.trimTimer != nil {
		m.trimTimer.Stop()
		m.trimTimer = nil
	}
	m.mtx.Unlock()
	for _, xmuxClient := range xmuxClients {
		xmuxClient.NotUsed.Store(true)
		common.Close(xmuxClient.XmuxConn)
	}
	return nil
}

// CloseIdleConnections closes the connections to the server that nothing runs on. //H
func (m *XmuxManager) CloseIdleConnections() {
	m.mtx.Lock()
	var idle []*XmuxClient
	kept := make([]*XmuxClient, 0, len(m.xmuxClients))
	for _, xmuxClient := range m.xmuxClients {
		if xmuxClient.OpenUsage.Load() <= 0 && xmuxClient.idleSince.Load() != 0 {
			idle = append(idle, xmuxClient)
		} else {
			kept = append(kept, xmuxClient)
		}
	}
	m.xmuxClients = kept
	m.mtx.Unlock()
	for _, xmuxClient := range idle {
		xmuxClient.NotUsed.Store(true)
		xmuxClient.maybeClose()
	}
}
