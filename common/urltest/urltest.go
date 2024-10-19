package urltest

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/imkira/go-observer/v2"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
)

type History struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}

type HistoryStorage struct {
	access       sync.RWMutex
	delayHistory map[string]*History
	updateHook   observer.Property[int]
	updateHookv2 *observable.Observer[int]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory: make(map[string]*History),
		updateHookv2: observable.NewObserver(observable.NewSubscriber[int](10), 1),
	}
}

func (s *HistoryStorage) SetHook(hook observer.Property[int]) {
	s.updateHook = hook
}
func (s *HistoryStorage) Observer() *observable.Observer[int] {
	return s.updateHookv2
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *History {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.delayHistory[tag]
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.access.Lock()
	delete(s.delayHistory, tag)
	s.access.Unlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *History) {
	s.access.Lock()
	s.delayHistory[tag] = history
	s.access.Unlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) notifyUpdated() {
	updateHook := s.updateHook
	if updateHook != nil {
		updateHook.Update(1)
		// select {
		// case updateHook <- struct{}{}:
		// default:
		// }
	}
	s.updateHookv2.Emit(1)
}

func (s *HistoryStorage) Close() error {
	s.updateHook = nil
	s.updateHookv2.Close()
	return nil
}

func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	start := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if earlyConn, isEarlyConn := common.Cast[N.EarlyConn](instance); isEarlyConn && earlyConn.NeedHandshake() {
		start = time.Now()
	}
	req, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	resp.Body.Close()
	t = uint16(time.Since(start) / time.Millisecond)
	return
}
