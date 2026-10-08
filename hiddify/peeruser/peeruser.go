// Package peeruser finds the user of a WireGuard peer from a connection's tunnel source address.
//
// WireGuard only accepts a packet from a peer when its source address is in that peer's allowed
// IPs (cryptokey routing), so the source address of an inbound connection identifies the peer.
// Setting the user on the connection metadata makes the per-user accounting (V2Ray API stats,
// Clash API) and auth_user route rules work as they do for user-based inbounds.
package peeruser

import (
	"net/netip"
	"sort"
)

type Peer struct {
	User       string
	AllowedIPs []netip.Prefix
}

// Users is a longest-prefix table of the peers that have a user; the zero value matches nothing.
type Users struct {
	entries []entry
}

type entry struct {
	prefix netip.Prefix
	user   string
}

func New(peers []Peer) *Users {
	var entries []entry
	for _, peer := range peers {
		if peer.User == "" {
			continue
		}
		for _, prefix := range peer.AllowedIPs {
			entries = append(entries, entry{prefix: prefix.Masked(), user: peer.User})
		}
	}
	if len(entries) == 0 {
		return nil
	}
	// most specific first, as WireGuard picks the peer for an address
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].prefix.Bits() > entries[j].prefix.Bits()
	})
	return &Users{entries: entries}
}

// Lookup returns the user of the peer the address belongs to, or "".
func (u *Users) Lookup(addr netip.Addr) string {
	if u == nil || !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	for _, entry := range u.entries {
		if entry.prefix.Contains(addr) {
			return entry.user
		}
	}
	return ""
}
