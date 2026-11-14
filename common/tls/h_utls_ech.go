//go:build with_utls

package tls

import (
	"net"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
)

// H: uTLS sends ECH through the fingerprint's ECH extension. Only some fingerprints (Chrome,
// Firefox) have one; with any other (Safari, iOS, Edge, Android, randomized, and "random" when it
// picks one of these) uTLS dropped the error and the handshake failed with
// "tls: malformed outer client hello". A fingerprint without the extension gets one, and one
// that cannot carry ECH at all (no fixed spec, or no TLS 1.3) is replaced by Chrome's.

// hECHClientHelloID returns the fingerprint to use with ECH: id itself when its spec can carry
// ECH, Chrome's otherwise. A randomized one draws a new spec for each connection, so it is made
// to always offer TLS 1.3.
func hECHClientHelloID(logger logger.ContextLogger, name string, id utls.ClientHelloID) utls.ClientHelloID {
	if hIsRandomized(id) {
		weights := utls.DefaultWeights
		if id.Weights != nil {
			weights = *id.Weights
		}
		weights.TLSVersMax_Set_VersionTLS13 = 1
		id.Weights = &weights
		return id
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err == nil && hSpecSupportsTLS13(spec) {
		return id
	}
	logger.Warn("uTLS fingerprint ", name, " cannot carry ECH, using chrome")
	return hChromeFingerprint
}

func hSpecSupportsTLS13(spec utls.ClientHelloSpec) bool {
	for _, extension := range spec.Extensions {
		if versions, isVersions := extension.(*utls.SupportedVersionsExtension); isVersions {
			return slices.Contains(versions.Versions, utls.VersionTLS13)
		}
	}
	return false
}

func hSpecHasECH(spec utls.ClientHelloSpec) bool {
	return slices.ContainsFunc(spec.Extensions, func(extension utls.TLSExtension) bool {
		_, isECH := extension.(utls.EncryptedClientHelloExtension)
		return isECH
	})
}

func hIsRandomized(id utls.ClientHelloID) bool {
	switch id.Client {
	case utls.HelloRandomized.Client, utls.HelloRandomizedALPN.Client, utls.HelloRandomizedNoALPN.Client:
		return true
	}
	return false
}

// hAddHybridKeyShare gives X25519MLKEM768 a key share when the spec offers the group without
// one, as a randomized spec may. A server that prefers it (Go's does) asks for it in a
// HelloRetryRequest, which uTLS cannot answer: "tls: CurvePreferences includes unsupported curve".
func hAddHybridKeyShare(spec *utls.ClientHelloSpec) {
	var offered bool
	var keyShares *utls.KeyShareExtension
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			offered = slices.Contains(extension.Curves, utls.X25519MLKEM768)
		case *utls.KeyShareExtension:
			keyShares = extension
		}
	}
	if !offered || keyShares == nil || slices.ContainsFunc(keyShares.KeyShares, func(keyShare utls.KeyShare) bool {
		return keyShare.Group == utls.X25519MLKEM768
	}) {
		return
	}
	keyShares.KeyShares = slices.Insert(keyShares.KeyShares, 0, utls.KeyShare{Group: utls.X25519MLKEM768})
}

// hAddECH puts BoringSSL's ECH extension before the padding and the pre-shared key, which stay
// last; uTLS fills it with the real ECH when the config has an ECH config list.
func hAddECH(spec *utls.ClientHelloSpec) {
	index := slices.IndexFunc(spec.Extensions, func(extension utls.TLSExtension) bool {
		switch extension.(type) {
		case *utls.UtlsPaddingExtension, utls.PreSharedKeyExtension:
			return true
		}
		return false
	})
	if index < 0 {
		index = len(spec.Extensions)
	}
	spec.Extensions = slices.Insert(spec.Extensions, index, utls.TLSExtension(utls.BoringGREASEECH()))
}

// hUClient makes the uTLS conn: with the fingerprint as is, or with its spec edited for the
// tls_tricks padding, for ECH and for a randomized spec's missing key share.
func (c *UTLSClientConfig) hUClient(conn net.Conn, config *utls.Config) (*utls.UConn, error) {
	padding := c.tricks != nil && c.tricks.padding
	ech := len(config.EncryptedClientHelloConfigList) > 0
	randomized := hIsRandomized(c.id)
	if !padding && !ech && !randomized {
		return utls.UClient(conn, config, c.id), nil
	}
	spec, err := utls.UTLSIdToSpec(c.id)
	if err != nil {
		return nil, E.Cause(err, "uTLS fingerprint spec")
	}
	if !padding && !randomized && hSpecHasECH(spec) {
		return utls.UClient(conn, config, c.id), nil
	}
	if randomized {
		hAddHybridKeyShare(&spec)
	}
	if ech && !hSpecHasECH(spec) {
		hAddECH(&spec)
	}
	if padding {
		applyTLSTricksPadding(&spec, c.tricks)
	}
	uConn := utls.UClient(conn, config, utls.HelloCustom)
	err = uConn.ApplyPreset(&spec)
	if err != nil {
		return nil, err
	}
	return uConn, nil
}
