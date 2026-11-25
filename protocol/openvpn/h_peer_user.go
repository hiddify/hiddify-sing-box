package openvpn

import "net/netip"

// The server endpoint routes the connections of all its clients from one device, so the source
// address, which the OpenVPN server assigned to one client and accepts only from that client,
// is what tells the clients apart. Setting it as the connection's user makes per-user
// accounting (V2Ray API stats, Clash API) and auth_user rules work, as for user-based inbounds.

// lookupPeerUser returns the user owning a tunnel address, or "" for a client endpoint.
func (e *endpointBase) lookupPeerUser(address netip.Addr) string {
	if e.peerUser == nil {
		return ""
	}
	return e.peerUser(address)
}

// serverPeerUser names a client by its auth-user-pass user name, or else by its certificate
// common name, as OpenVPN does. A static key server has no authenticated client and names none.
// The device that calls it starts after Start set s.server.
func (s *ServerEndpoint) serverPeerUser(address netip.Addr) string {
	server := s.server
	if server == nil {
		return ""
	}
	identity, found := server.LookupPeer(address)
	if !found {
		return ""
	}
	return identity.Name()
}
