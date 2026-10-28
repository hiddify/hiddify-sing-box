package warp

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterWARPEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WARPEndpointOptions](registry, C.TypeWARP, NewWARPEndpoint)
}

type WARPEndpoint struct {
	endpoint.Adapter
	endpoint     adapter.Endpoint
	startHandler func()
	scope        *adapter.Scope // H: the inner endpoint is started as a child of it, so it closes with WARP

	mtx sync.Mutex

	// H: failover (h_failover.go)
	ctx       context.Context
	router    adapter.Router
	logger    log.ContextLogger
	tag       string
	uniqueID  string
	options   option.WARPEndpointOptions
	failover  *warpFailover
	done      chan struct{}
	closeOnce sync.Once

	replaceAccess sync.Mutex      // H: one replacement of the inner endpoint at a time
	peerAddr      string          // H: the peer of the inner endpoint, guarded by mtx
	peerPort      uint16          // H
	scanStatus    warpscan.Status // H: the WireGuard scanner, for the display type
	scanStatusOf  func() *warpscan.Status
	failed        atomic.Bool           // H: see Status
	tracker       adapter.StatusTracker // H
	registering   atomic.Bool           // H: a device is being registered

	mode          string        // H: the tunnel, see h_mode.go
	active        atomic.Value  // H: in auto mode, the tunnel chosen
	selecting     atomic.Bool   // H: auto mode races the tunnels
	profiles      *warpProfiles // H: the devices, see h_profiles.go
	profile       *warpProfile  // H: the device in use, guarded by mtx
	recreated     sync.Map      // H: kinds registered anew for profile.recreate
	sessionAccess sync.Mutex    // H
	current       *warpSession  // H: the current start
}

func NewWARPEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WARPEndpointOptions) (adapter.Endpoint, error) {
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	uniqueId := options.UniqueIdentifier
	if uniqueId == "" {
		uniqueId = tag
	}
	mode, err := warpMode(&options) //H: wg, awg, masque or auto
	if err != nil {                 //H
		return nil, err //H
	} //H
	if err := options.Noise.FakePacket.Validate(); err != nil { //H: a bad template fails the config, not the handshake
		return nil, E.Cause(err, "warp") //H
	} //H
	if options.Scanner != nil { //H
		for _, name := range options.Scanner.NoisePresets { //H
			if _, found := warpscan.NoisePresetByName(name); !found { //H
				return nil, E.New("warp: unknown noise preset: ", name) //H
			} //H
		} //H
	} //H
	warpEndpoint := &WARPEndpoint{
		Adapter:  endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:      ctx,                                    //H
		router:   router,                                 //H
		logger:   logger,                                 //H
		tag:      tag,                                    //H
		uniqueID: uniqueId,                               //H
		options:  options,                                //H
		done:     make(chan struct{}),                    //H
		mode:     mode,                                   //H
		profiles: newWARPProfiles(ctx, logger, uniqueId), //H: read at start, once the cache file is open
	}
	// Do not hold mtx across registration/scan/handshake: Final/dns may dial this
	// endpoint while it starts (extra security), and a held lock deadlocks or stalls
	// urltest. IsReady/Dial see nil until connect installs the inner endpoint.
	warpEndpoint.startHandler = warpEndpoint.start //H: see h_mode.go
	return warpEndpoint, nil
}
func GetWarpProfile(ctx context.Context, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	var result *cloudflare.CloudflareProfile
	err := withWARPAPI(ctx, profile, func(dialer N.Dialer) error { //H: the same order for every tunnel
		cf, err := GetWarpProfileDialer(ctx, dialer, profile)
		result = cf
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// withWARPAPI calls register with the dialer to reach the WARP API through: profile.detour (a
// direct connection when unset), then every outbound until one works. //H
func withWARPAPI(ctx context.Context, profile *option.WARPProfile, register func(dialer N.Dialer) error) error {
	var dialer N.Dialer
	outmanager := service.FromContext[adapter.OutboundManager](ctx)
	if profile.Detour != "" && outmanager != nil {
		var ok bool
		dialer, ok = outmanager.Outbound(profile.Detour)
		if !ok {
			return E.New("outbound detour not found: ", profile.Detour)
		}

	}
	err := register(dialer)
	if err == nil {
		return nil
	}
	if outmanager == nil { //H: returning (nil, nil) here made the caller dereference a nil profile
		return err //H
	} //H

	for _, dialer := range outmanager.Outbounds() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if register(dialer) == nil {
			return nil
		}
	}
	return err
}
func GetWarpProfileDialer(ctx context.Context, dialer N.Dialer, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	api := cloudflare.NewCloudflareApiDetour(dialer)
	if profile.AuthToken != "" && profile.ID != "" {
		return api.GetProfileWithKey(ctx, profile.AuthToken, profile.ID, profile.PrivateKey) //H: GetProfile has no private key, so the endpoint could not start

	} else {
		return api.CreateProfileLicense(ctx, profile.PrivateKey, profile.License)
	}
}

// retry runs attempt until it succeeds, with a backoff between failures, and reports false when
// the endpoint closes first. //H
func (w *WARPEndpoint) retry(done <-chan struct{}, what string, attempt func() error) bool {
	backoff := retryMin
	for {
		err := attempt()
		if err == nil {
			return true
		}
		w.logger.ErrorContext(w.ctx, E.Cause(err, what))
		select {
		case <-w.ctx.Done():
			return false
		case <-done:
			return false
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, retryMax)
	}
}

// The registration of a device is retried with a backoff between these. //H
const (
	retryMin = time.Second
	retryMax = 30 * time.Second
)

// Status is registering while a device is registered; ready only while the peer answers, not
// once the endpoint exists; searching while the scanner looks for an endpoint; reconnecting
// after it was ready; failed when the config cannot work. Over MASQUE, once registered, it is the
// tunnel's status. //H
func (w *WARPEndpoint) Status() adapter.Status {
	if w.failed.Load() {
		return adapter.StatusFailed
	}
	if w.registering.Load() {
		return adapter.StatusRegistering
	}
	if w.selecting.Load() {
		return adapter.StatusSearching // auto mode races the tunnels
	}
	inner := w.currentEndpoint()
	if w.activeMode() == modeMASQUE {
		if inner == nil {
			return adapter.StatusConnecting
		}
		return inner.Status()
	}
	if w.scanStatus.IsScanning() {
		return adapter.StatusSearching
	}
	if inner == nil {
		return adapter.StatusConnecting
	}
	return w.tracker.Status(handshakeFresh(inner))
}

// fail logs err, after which the endpoint shows as failed: it cannot work as configured. //H
func (w *WARPEndpoint) fail(err error) {
	w.logger.ErrorContext(w.ctx, err)
	w.failed.Store(true)
}
func (w *WARPEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		w.scope = scope
		go func() { //H: the box closes the scope, not the endpoint; stop the background work with it
			select {
			case <-scope.Context().Done():
				w.closeOnce.Do(func() { close(w.done) })
				w.endSession()
			case <-w.done:
			}
		}()
	}
	if stage != adapter.StartStatePostStart {
		return nil
	}
	go w.startHandler()
	return nil
}

func (w *WARPEndpoint) Close() error {
	w.closeOnce.Do(func() { close(w.done) })              //H: stops the failover checks
	w.endSession()                                        //H
	if w.scope != nil && w.scope.Context().Err() != nil { //H: the closing scope closes the inner endpoint
		return nil //H
	} //H
	w.mtx.Lock()        //H
	inner := w.endpoint //H
	w.mtx.Unlock()      //H
	return adapter.CloseLate(w.scope, inner)
}

func (w *WARPEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	inner := w.currentEndpoint() //H: the failover replaces it
	if inner == nil {
		return nil, E.New("endpoint not initialized")
	}
	return inner.DialContext(ctx, network, destination)
}

func (w *WARPEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	inner := w.currentEndpoint() //H
	if inner == nil {
		return nil, E.New("endpoint not initialized")
	}
	return inner.ListenPacket(ctx, destination)
}

// currentEndpoint returns the inner endpoint, waiting for the first start to finish. //H
func (w *WARPEndpoint) currentEndpoint() adapter.Endpoint {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return w.endpoint
}

// DisplayType names the tunnel WARP uses and the scanner status. //H
func (w *WARPEndpoint) DisplayType() string {
	name := C.DisplayWARPWireGuard
	status := &w.scanStatus
	switch w.activeMode() {
	case "": // auto mode, before it chose
		return C.DisplayWARPAuto
	case modeMASQUE:
		name = C.DisplayWARPMASQUE
		w.mtx.Lock()
		statusOf := w.scanStatusOf
		w.mtx.Unlock()
		status = nil
		if statusOf != nil {
			status = statusOf()
		}
	case modeAWG:
		name = C.DisplayWARPAWG
	}
	return name + status.String()
}

// warpPeerEndpoint picks the address and port of the WARP peer: the configured server and
// server_port when set, otherwise the profile's endpoint host and one of its ports, or the
// port in the host when the profile lists none. //H
func warpPeerEndpoint(config *C.WARPConfig, server option.ServerOptions) (string, uint16, error) {
	if len(config.Peers) == 0 {
		return "", 0, E.New("WARP config has no peers")
	}
	endpoint := config.Peers[0].Endpoint
	address, portString, hasPort := strings.Cut(endpoint.Host, ":")
	var port uint16
	if len(endpoint.Ports) > 0 {
		port = uint16(endpoint.Ports[rand.Intn(len(endpoint.Ports))])
	} else if hasPort {
		parsed, err := strconv.ParseUint(portString, 10, 16)
		if err == nil {
			port = uint16(parsed)
		}
	}
	if server.Server != "" {
		address = server.Server
	} else if !M.ParseAddr(address).IsValid() { //H: the profile's host is a domain
		// use the profile's own address: a domain peer resolves to IPv4 and IPv6, and WireGuard
		// sends to both over one UDP association, which a detour without IPv6 then closes
		if profileAddress := warpProfileAddress(endpoint.V4, endpoint.V6); profileAddress != "" { //H
			address = profileAddress //H
		} //H
	}
	if server.ServerPort != 0 {
		port = server.ServerPort
	}
	if address == "" || port == 0 {
		return "", 0, E.New("WARP config has no peer address or port")
	}
	return address, port, nil
}

// warpInterfaceAddresses returns the tunnel addresses of a WARP config; a missing family is
// skipped, but at least one is required. //H
func warpInterfaceAddresses(config *C.WARPConfig) (badoption.Listable[netip.Prefix], error) {
	var addresses badoption.Listable[netip.Prefix]
	for _, address := range []struct {
		value string
		bits  string
	}{{config.Interface.Addresses.V4, "/32"}, {config.Interface.Addresses.V6, "/128"}} {
		if address.value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(address.value + address.bits)
		if err != nil {
			return nil, E.Cause(err, "parse WARP interface address")
		}
		addresses = append(addresses, prefix)
	}
	if len(addresses) == 0 {
		return nil, E.New("WARP config has no interface address")
	}
	return addresses, nil
}

// warpProfileAddress returns the IP of the profile's IPv4 endpoint, or of its IPv6 one when there
// is no IPv4 one. The endpoints are written as "ip:port" or "[ip]:port". //H
func warpProfileAddress(v4 string, v6 string) string {
	for _, candidate := range []string{v4, v6} {
		if candidate == "" {
			continue
		}
		if addrPort := M.ParseSocksaddr(candidate); addrPort.Addr.IsValid() {
			return addrPort.Addr.String()
		}
	}
	return ""
}
