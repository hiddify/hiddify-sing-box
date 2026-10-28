package warp

import (
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
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
	warpEndpoint := &WARPEndpoint{
		Adapter:  endpoint.NewAdapter(C.TypeWARP, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:      ctx,                 //H
		router:   router,              //H
		logger:   logger,              //H
		tag:      tag,                 //H
		uniqueID: uniqueId,            //H
		options:  options,             //H
		done:     make(chan struct{}), //H
	}
	warpEndpoint.mtx.Lock()
	warpEndpoint.startHandler = func() {
		defer warpEndpoint.mtx.Unlock()
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		var config *C.WARPConfig
		var err error
		if !options.Profile.Recreate && cacheFile != nil && cacheFile.StoreWARPConfig() {
			savedProfile := cacheFile.LoadBinary(uniqueId)
			if savedProfile != nil {
				if err = json.Unmarshal(savedProfile.Content, &config); err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
			}
		}
		if config == nil && options.WARPConfig != nil {
			config = options.WARPConfig
		}
		if config == nil || config.PrivateKey == "" {
			profile, err := GetWarpProfile(ctx, &options.Profile)
			if err != nil {
				logger.ErrorContext(ctx, err)
				return
			}
			config = &profile.Config

			if cacheFile != nil && cacheFile.StoreWARPConfig() {
				content, err := json.Marshal(config)
				if err != nil {
					logger.ErrorContext(ctx, err)
					return
				}
				cacheFile.SaveBinary(uniqueId, &adapter.SavedBinary{
					LastUpdated: time.Now(),
					Content:     content,
					LastEtag:    "",
				})
			}
		}
		warpEndpoint.connect(config) //H: pick the endpoint (scanning when enabled) and start it
	}
	return warpEndpoint, nil
}
func GetWarpProfile(ctx context.Context, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	var dialer N.Dialer
	outmanager := service.FromContext[adapter.OutboundManager](ctx)
	if profile.Detour != "" && outmanager != nil {
		var ok bool
		dialer, ok = outmanager.Outbound(profile.Detour)
		if !ok {
			return nil, E.New("outbound detour not found: ", profile.Detour)
		}

	}
	cf, err := GetWarpProfileDialer(ctx, dialer, profile)
	if err == nil {
		return cf, nil
	}
	if outmanager == nil { //H: returning (nil, nil) here made the caller dereference a nil profile
		return nil, err //H
	} //H

	for _, dialer := range outmanager.Outbounds() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if cf, err := GetWarpProfileDialer(ctx, dialer, profile); err == nil {
			return cf, nil
		}
	}
	return nil, err

}
func GetWarpProfileDialer(ctx context.Context, dialer N.Dialer, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	api := cloudflare.NewCloudflareApiDetour(dialer)
	if profile.AuthToken != "" && profile.ID != "" {
		return api.GetProfileWithKey(ctx, profile.AuthToken, profile.ID, profile.PrivateKey) //H: GetProfile has no private key, so the endpoint could not start

	} else {
		return api.CreateProfileLicense(ctx, profile.PrivateKey, profile.License)
	}
}
func (w *WARPEndpoint) IsReady() bool {
	inner := w.currentEndpoint() //H
	if inner == nil {
		return false
	}
	return handshakeFresh(inner) //H: connected only while the peer answers, not once the endpoint exists
}
func (w *WARPEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		w.scope = scope
	}
	if stage != adapter.StartStatePostStart {
		return nil
	}
	go w.startHandler()
	return nil
}

func (w *WARPEndpoint) Close() error {
	w.closeOnce.Do(func() { close(w.done) }) //H: stops the failover checks
	w.mtx.Lock()                             //H
	inner := w.endpoint                      //H
	w.mtx.Unlock()                           //H
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

func (w *WARPEndpoint) DisplayType() string {
	str := C.ProxyDisplayName(w.Type())
	if !w.IsReady() {
		str += " ⚠️ Connecting..."
	}
	return str
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
