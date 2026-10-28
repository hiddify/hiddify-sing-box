package psiphon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing/common/logger"
)

var Countries = []string{
	"AT",
	"AU",
	"BE",
	"BG",
	"CA",
	"CH",
	"CZ",
	"DE",
	"DK",
	"EE",
	"ES",
	"FI",
	"FR",
	"GB",
	"HR",
	"HU",
	"IE",
	"IN",
	"IT",
	"JP",
	"LV",
	"NL",
	"NO",
	"PL",
	"PT",
	"RO",
	"RS",
	"SE",
	"SG",
	"SK",
	"US",
}

// NoticeEvent represents the notices emitted by tunnel core.
type NoticeEvent struct {
	Data      map[string]interface{} `json:"data"`
	Type      string                 `json:"noticeType"`
	Timestamp string                 `json:"timestamp"`
}

type Psiphon struct {
	controller      atomic.Pointer[psiphon.Controller] // set by the async start; read from other goroutines
	logger          logger.ContextLogger
	config          *psiphon.Config
	ctx             context.Context
	cancel          context.CancelFunc
	dataStoreOpened bool
	connected       atomic.Bool // driven by NoticeTunnels; read by IsReady/DisplayType
	tag             string
}

// Dial opens a connection through the tunnel. The controller only dials while a tunnel is up, so
// the outcome also tells whether it is connected: the Tunnels notices alone can be missed (see
// noticeHub).
func (p *Psiphon) Dial(address string, conn net.Conn) (net.Conn, error) {
	ctl := p.controller.Load()
	if ctl == nil {
		return nil, errors.New("controller not initialized")
	}
	tunneled, err := ctl.Dial(address, conn)
	switch {
	case err == nil:
		p.setConnected(true)
	case strings.Contains(err.Error(), noActiveTunnels):
		p.setConnected(false)
	}
	return tunneled, err
}

// noActiveTunnels is the controller's dial error while no tunnel is up.
const noActiveTunnels = "no active tunnels"

// noticeHub is the one notice writer of the process. psiphon-tunnel-core has a single, global
// notice writer: an instance that set its own and one that reset it on close left the others
// deaf, so a Psiphon started while another was closing (a reload) never saw its Tunnels notice
// and showed as connecting with a working tunnel. The hub is installed once, passes every notice
// to every running instance, and is removed when the last one stops.
var noticeHub struct {
	access    sync.Mutex
	installed bool
	listeners map[*Psiphon]func(NoticeEvent)
}

func listenNotices(p *Psiphon, listener func(NoticeEvent)) error {
	noticeHub.access.Lock()
	defer noticeHub.access.Unlock()
	if !noticeHub.installed {
		err := psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(func(notice []byte) {
			var event NoticeEvent
			if json.Unmarshal(notice, &event) != nil {
				return
			}
			noticeHub.access.Lock()
			listeners := make([]func(NoticeEvent), 0, len(noticeHub.listeners))
			for _, listener := range noticeHub.listeners {
				listeners = append(listeners, listener)
			}
			noticeHub.access.Unlock()
			for _, listener := range listeners {
				listener(event)
			}
		}))
		if err != nil {
			return err
		}
		noticeHub.installed = true
		noticeHub.listeners = make(map[*Psiphon]func(NoticeEvent))
	}
	noticeHub.listeners[p] = listener
	return nil
}

func stopListeningNotices(p *Psiphon) {
	noticeHub.access.Lock()
	defer noticeHub.access.Unlock()
	if _, listening := noticeHub.listeners[p]; !listening {
		return
	}
	delete(noticeHub.listeners, p)
	if len(noticeHub.listeners) == 0 && noticeHub.installed {
		psiphon.ResetNoticeWriter()
		noticeHub.installed = false
	}
}

// setConnected updates readiness from NoticeTunnels. On first connect it asks
// monitoring to urltest — same pattern as SSH/AWG/DNSTT after they are ready.
func (p *Psiphon) setConnected(ok bool) {
	was := p.connected.Swap(ok)
	if ok && !was {
		if m := monitoring.Get(p.ctx); m != nil {
			m.TestNow(p.tag)
		}
	}
}

func noticeCount(data map[string]interface{}) (float64, bool) {
	if data == nil {
		return 0, false
	}
	v, ok := data["count"]
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func (p *Psiphon) PreStart() error {
	if err := os.MkdirAll(p.config.DataRootDirectory, 0o755); err != nil {
		return err
	}
	if err := p.config.Commit(true); err != nil {
		return err
	}
	if err := psiphon.OpenDataStore(p.config); err != nil {
		return err
	}
	p.dataStoreOpened = true
	if err := psiphon.ImportEmbeddedServerEntries(p.ctx, p.config, "", ""); err != nil {
		p.closeDataStore()
		return err
	}
	return nil
}
func (p *Psiphon) closeDataStore() {
	if p.dataStoreOpened {
		psiphon.CloseDataStore()
		p.dataStoreOpened = false
	}
}

func (p *Psiphon) State() string {
	if p.IsConnected() {
		return "connected"
	}
	return "connecting..."
}
func (p *Psiphon) IsConnected() bool {
	return p.controller.Load() != nil && p.connected.Load()
}

// NetworkChanged tells the running controller that the network changed.
// It is a no-op before the controller exists (still starting, or start failed).
func (p *Psiphon) NetworkChanged() {
	if ctl := p.controller.Load(); ctl != nil {
		ctl.NetworkChanged()
	}
}

func (p *Psiphon) Close() error {
	p.controller.Store(nil)
	p.connected.Store(false)
	stopListeningNotices(p) // the writer is reset only when no other instance listens
	if p.cancel != nil {    // nil until Start runs
		p.cancel()
	}
	p.closeDataStore()
	return nil
}
func NewPsiphon(ctx context.Context, l logger.ContextLogger, config *psiphon.Config, tag string) (*Psiphon, error) {
	p := Psiphon{
		logger: l,
		config: config,
		ctx:    ctx,
		tag:    tag,
	}
	return &p, nil
}

func (p *Psiphon) Start() error {
	ctx, cancel := context.WithCancel(p.ctx)
	p.cancel = cancel
	// config.Commit must be called before calling config.SetParameters
	// or attempting to connect.
	if err := p.config.Commit(true); err != nil {
		return errors.New("config.Commit failed")
	}

	// Same contract as clientlib.StartTunnel: NoticeTunnels(count>0) means
	// connected. Handle notices synchronously so readiness flips before Dial
	// / urltest can observe a live tunnel while DisplayType still says Connecting.
	connectedSignal := make(chan struct{})
	var connectedOnce sync.Once
	errored := make(chan error, 1)

	if err := listenNotices(p, func(event NoticeEvent) {
		p.logger.Debug(fmt.Sprint("Notice ", event.Type, " data ", event.Data))
		switch event.Type {
		case "EstablishTunnelTimeout":
			select {
			case errored <- errors.New("clientlib: tunnel establishment timeout"):
			default:
			}
		case "Tunnels":
			count, ok := noticeCount(event.Data)
			if !ok {
				return
			}
			if count > 0 {
				p.setConnected(true)
				connectedOnce.Do(func() { close(connectedSignal) })
			} else {
				p.setConnected(false)
			}
		}
	}); err != nil {
		return err
	}

	if err := psiphon.OpenDataStore(p.config); err != nil {
		return errors.New("failed to open data store")
	}

	if err := psiphon.ImportEmbeddedServerEntries(ctx, p.config, "", ""); err != nil {
		return err
	}

	controller, err := psiphon.NewController(p.config)
	if err != nil {
		return errors.New("psiphon.NewController failed")
	}
	p.controller.Store(controller)

	go func() {
		controller.Run(ctx) // Run will block until the controller is stopped

		select {
		case errored <- errors.New("controller.Run exited unexpectedly"):
		default:
		}
	}()
	p.logger.Debug("Waiting for success or failure of tunnel connection...")
	select {
	case <-ctx.Done():
		p.logger.Debug("Context done while waiting for success or failure of tunnel connection")
		p.Close()
		return ctx.Err()
	case <-connectedSignal:
		p.logger.Debug("Tunnel connection established")
		return nil
	case err := <-errored:
		p.logger.Debug("Tunnel connection failed: ", err)
		p.Close()
		return err
	}

}

// func RunPsiphon(ctx context.Context, l logger.ContextLogger, wgBind netip.AddrPort, dir string, localSocksAddr netip.AddrPort, country string) error {
// 	host := ""
// 	if !netip.MustParsePrefix("127.0.0.0/8").Contains(localSocksAddr.Addr()) {
// 		host = "any"
// 	}

// 	timeout := 60
// 	config := psiphon.Config{
// 		EgressRegion:                                 country,
// 		ListenInterface:                              host,
// 		LocalSocksProxyPort:                          int(localSocksAddr.Port()),
// 		UpstreamProxyURL:                             fmt.Sprintf("socks5://%s", wgBind),
// 		DisableLocalHTTPProxy:                        true,
// 		PropagationChannelId:                         "FFFFFFFFFFFFFFFF",
// 		RemoteServerListDownloadFilename:             "remote_server_list",
// 		RemoteServerListSignaturePublicKey:           "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
// 		RemoteServerListUrl:                          "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
// 		SponsorId:                                    "FFFFFFFFFFFFFFFF",
// 		NetworkID:                                    "test",
// 		ClientPlatform:                               "Android_4.0.4_com.example.exampleClientLibraryApp",
// 		AllowDefaultDNSResolverWithBindToDevice:      true,
// 		EstablishTunnelTimeoutSeconds:                &timeout,
// 		DataRootDirectory:                            dir,
// 		MigrateDataStoreDirectory:                    dir,
// 		MigrateObfuscatedServerListDownloadDirectory: dir,
// 		MigrateRemoteServerListDownloadFilename:      filepath.Join(dir, "server_list_compressed"),
// 	}

// 	l.Info("starting handshake")
// 	if _, err := StartTunnel(ctx, l, &config); err != nil {
// 		return fmt.Errorf("Unable to start psiphon: %w", err)
// 	}
// 	l.Info("psiphon started successfully")
// 	return nil
// }
