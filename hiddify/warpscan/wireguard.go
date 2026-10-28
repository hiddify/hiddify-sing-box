package warpscan

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/hiddify"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// The ports Cloudflare's WARP WireGuard endpoints answer on, and their ranges.
var (
	WireGuardPorts = []uint16{
		500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
		955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371,
		2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152,
		7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}
	WireGuardCIDRs = []netip.Prefix{
		netip.MustParsePrefix("162.159.192.0/24"),
		netip.MustParsePrefix("162.159.193.0/24"),
		netip.MustParsePrefix("162.159.195.0/24"),
		netip.MustParsePrefix("188.114.96.0/24"),
		netip.MustParsePrefix("188.114.97.0/24"),
		netip.MustParsePrefix("188.114.98.0/24"),
		netip.MustParsePrefix("188.114.99.0/24"),
		netip.MustParsePrefix("2606:4700:d0::/64"),
		netip.MustParsePrefix("2606:4700:d1::/64"),
	}
)

// WireGuardProbe probes with a WireGuard handshake initiation made with the profile's own keys,
// after the endpoint's noise packets when it has any, and times the handshake response.
func WireGuardProbe(dialer N.Dialer, privateKey string, peerPublicKey string, noiseOptions hiddify.NoiseOptions) (Probe, error) {
	private, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(private) != 32 {
		return nil, E.New("WARP scanner: invalid private key")
	}
	peer, err := base64.StdEncoding.DecodeString(peerPublicKey)
	if err != nil || len(peer) != 32 {
		return nil, E.New("WARP scanner: invalid peer public key")
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	static := noise.DHKey{Private: private, Public: public}
	return func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		return wireGuardHandshake(ctx, dialer, addrPort, static, peer, noiseOptions)
	}, nil
}

func wireGuardHandshake(ctx context.Context, dialer N.Dialer, addrPort netip.AddrPort, static noise.DHKey, peer []byte, noiseOptions hiddify.NoiseOptions) (time.Duration, error) {
	ephemeral, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return 0, err
	}
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         static,
		PeerStatic:            peer,
		Prologue:              []byte("WireGuard v1 zx2c4 Jason@zx2c4.com"),
		PresharedKey:          make([]byte, 32),
		PresharedKeyPlacement: 2,
		EphemeralKeypair:      ephemeral,
		Random:                rand.Reader,
	})
	if err != nil {
		return 0, err
	}
	// TAI64N timestamp
	now := time.Now()
	timestamp := binary.BigEndian.AppendUint64(nil, uint64(4611686018427387914+now.Unix()))
	timestamp = binary.BigEndian.AppendUint32(timestamp, uint32(now.Nanosecond()))
	message, _, _, err := state.WriteMessage(nil, timestamp)
	if err != nil {
		return 0, err
	}
	const senderIndex = 28
	initiation := []byte{1, 0, 0, 0}
	initiation = binary.LittleEndian.AppendUint32(initiation, senderIndex)
	initiation = append(initiation, message...)
	macKey := blake2s.Sum256(append([]byte("mac1----"), peer...))
	mac, err := blake2s.New128(macKey[:])
	if err != nil {
		return 0, err
	}
	mac.Write(initiation)
	initiation = append(initiation, mac.Sum(nil)...)
	initiation = append(initiation, make([]byte, 16)...)

	conn, err := dialer.DialContext(ctx, N.NetworkUDP, M.SocksaddrFromNetIP(addrPort))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err = sendNoise(ctx, conn, noiseOptions); err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err = conn.Write(initiation); err != nil {
		return 0, err
	}
	response := make([]byte, 128)
	for {
		n, err := conn.Read(response)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			return 0, err
		}
		// a handshake response (type 2) for our sender index
		if n != 92 || response[0] != 2 || binary.LittleEndian.Uint32(response[8:12]) != senderIndex {
			continue
		}
		if _, _, _, err = state.ReadMessage(nil, response[12:60]); err != nil {
			return 0, E.Cause(err, "invalid handshake response")
		}
		return time.Since(start), nil
	}
}

// sendNoise sends the endpoint's fake packets before the initiation, the same ones its WireGuard
// device sends (FakePacketOptions.Build): on networks that need them, a bare initiation gets no
// answer.
func sendNoise(ctx context.Context, conn interface{ Write([]byte) (int, error) }, options hiddify.NoiseOptions) error {
	packets, err := options.FakePacket.Build()
	if err != nil {
		return err
	}
	for _, packet := range packets {
		if _, err := conn.Write(packet.Data); err != nil {
			return err
		}
		if packet.Delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(packet.Delay):
			}
		}
	}
	return nil
}
