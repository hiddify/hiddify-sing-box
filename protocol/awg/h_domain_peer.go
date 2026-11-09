package awg

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A peer given by a domain was resolved by the system resolver when the endpoint was created
// (hiddify-app#2478). With the VPN up, the system's DNS goes into the tunnel: with fake DNS it got
// a fake address (198.18.0.0/15), which the system kept for its TTL, and every handshake went
// there; a WARP endpoint in AmneziaWG mode, which makes its inner endpoint again on failover,
// looked it up through the tunnel it was replacing. A failed lookup also failed the box's start.
//
// Now the peer starts without an address, and the DNS router resolves it once the box started,
// with the endpoint dialer's query options (its domain_resolver, or route.default_domain_resolver),
// as the WireGuard endpoint does. A failed lookup is tried again, and the address is looked up
// again after each network change.

const (
	peerResolveRetryMin = time.Second
	peerResolveRetryMax = 30 * time.Second
)

type domainPeer struct {
	publicKey string // hex, as in the UAPI configuration
	domain    string
	port      uint16
	current   netip.AddrPort // the address in use; changed under Endpoint.bindAccess
}

type domainPeers struct {
	dial  N.Dialer
	peers []*domainPeer
	only  bool // the endpoint's only peer: the bind connects to it
}

// deferDomainPeers returns options without the domains of the peers given by one, for the first
// configuration of the device, and those peers.
func deferDomainPeers(options option.AwgEndpointOptions) (option.AwgEndpointOptions, []*domainPeer, error) {
	var peers []*domainPeer
	options.Peers = slices.Clone(options.Peers)
	for i, peer := range options.Peers {
		if peer.Address == "" || peer.Port == 0 || M.ParseAddr(peer.Address).IsValid() {
			continue
		}
		publicKey, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil {
			return options, nil, E.Cause(err, "decode public key of peer ", peer.Address)
		}
		peers = append(peers, &domainPeer{publicKey: hex.EncodeToString(publicKey), domain: peer.Address, port: peer.Port})
		options.Peers[i].Address = ""
	}
	return options, peers, nil
}

func newDomainPeers(dial N.Dialer, peers []*domainPeer, peerCount int) *domainPeers {
	if len(peers) == 0 {
		return nil
	}
	return &domainPeers{dial: dial, peers: peers, only: peerCount == 1}
}

// startResolvingPeers resolves the domain peers until each has an address.
func (w *Endpoint) startResolvingPeers() {
	if w.peers == nil {
		return
	}
	go func() {
		delay := peerResolveRetryMin
		for {
			w.bindAccess.Lock()
			resolved := w.ctx.Err() != nil || !w.deviceStarted.Load()
			if !resolved {
				resolved, _ = w.resolvePeersLocked()
			}
			w.bindAccess.Unlock()
			if resolved {
				return
			}
			select {
			case <-w.ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, peerResolveRetryMax)
		}
	}()
}

// resolvePeersLocked looks the domain peers up and sets the addresses that changed. It reports
// whether every peer has an address, and whether the bind connected again (the only peer moved).
// w.bindAccess is held.
func (w *Endpoint) resolvePeersLocked() (all bool, rebound bool) {
	if w.peers == nil {
		return true, false
	}
	var queryOptions adapter.DNSQueryOptions
	if resolveDialer, isResolve := w.peers.dial.(dialer.ResolveDialer); isResolve {
		queryOptions = resolveDialer.QueryOptions()
	}
	all = true
	for _, peer := range w.peers.peers {
		addresses, err := w.dnsRouter.Lookup(w.ctx, peer.domain, queryOptions)
		if err == nil && len(addresses) == 0 {
			err = E.New("no address")
		}
		if err != nil {
			w.logger.Error(E.Cause(err, "resolve peer ", peer.domain))
			all = all && peer.current.IsValid() // keep the address it had
			continue
		}
		address := netip.AddrPortFrom(addresses[0].Unmap(), peer.port)
		if address == peer.current {
			continue
		}
		if err = w.Device.SetPeerEndpoint(peer.publicKey, address, w.peers.only); err != nil {
			w.logger.Error(E.Cause(err, "set the address of peer ", peer.domain))
			all = all && peer.current.IsValid()
			continue
		}
		w.logger.Info("peer ", peer.domain, " is at ", address)
		peer.current = address
		rebound = rebound || w.peers.only
	}
	return all, rebound
}
