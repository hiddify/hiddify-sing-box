//go:build with_utls

package tls

import (
	"slices"

	utls "github.com/metacubex/utls"
)

// realityClientHelloSpec returns the ClientHello of fingerprint id, changed as little as needed
// to pass every REALITY server: Xray servers from v26.10 reject a ClientHello without an
// X25519MLKEM768 key share before the X25519 one, and REALITY needs TLS 1.3 with an X25519 key
// share, which some fingerprints (old browsers, Android OkHttp, 360) do not send.
//
// With classical (key_share "classical"), X25519MLKEM768 is removed instead: the ClientHello
// fits in one TCP segment, which some networks need, but v26.9.8+ Xray servers reject it.
func realityClientHelloSpec(id utls.ClientHelloID, config *utls.Config, classical bool) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		// randomized fingerprints have no fixed spec: generate one and take it from the result
		probe := utls.UClient(nil, config.Clone(), id)
		err = probe.BuildHandshakeStateWithoutSession()
		if err != nil {
			return nil, err
		}
		hello := probe.HandshakeState.Hello
		spec = utls.ClientHelloSpec{
			CipherSuites:       hello.CipherSuites,
			CompressionMethods: hello.CompressionMethods,
			Extensions:         probe.Extensions,
		}
	}
	patchRealityClientHelloSpec(&spec)
	if classical {
		removeHybridKeyShare(&spec)
	}
	return &spec, nil
}

// removeHybridKeyShare drops X25519MLKEM768 from the supported groups and the key shares.
func removeHybridKeyShare(spec *utls.ClientHelloSpec) {
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			extension.Curves = slices.DeleteFunc(slices.Clone(extension.Curves), func(curve utls.CurveID) bool {
				return curve == utls.X25519MLKEM768
			})
		case *utls.KeyShareExtension:
			extension.KeyShares = slices.DeleteFunc(slices.Clone(extension.KeyShares), func(share utls.KeyShare) bool {
				return share.Group == utls.X25519MLKEM768
			})
		}
	}
}

func patchRealityClientHelloSpec(spec *utls.ClientHelloSpec) {
	if spec.TLSVersMax != 0 && spec.TLSVersMax < utls.VersionTLS13 {
		spec.TLSVersMax = utls.VersionTLS13
	}
	spec.CipherSuites = withFirst(spec.CipherSuites, utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256)
	var hasVersions, hasCurves, hasKeyShare, hasSignatureAlgorithms bool
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedVersionsExtension:
			hasVersions = true
			extension.Versions = withFirst(extension.Versions, utls.VersionTLS13, utls.VersionTLS12)
		case *utls.SupportedCurvesExtension:
			hasCurves = true
			extension.Curves = withFirst(extension.Curves, utls.X25519MLKEM768, utls.X25519)
		case *utls.KeyShareExtension:
			hasKeyShare = true
			extension.KeyShares = realityKeyShares(extension.KeyShares)
		case *utls.SignatureAlgorithmsExtension:
			hasSignatureAlgorithms = true
		}
	}
	if !hasCurves {
		spec.Extensions = append(spec.Extensions, &utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519}})
	}
	if !hasSignatureAlgorithms {
		spec.Extensions = append(spec.Extensions, &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
			utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
		}})
	}
	if !hasVersions {
		spec.Extensions = append(spec.Extensions, &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}})
	}
	if !hasKeyShare {
		spec.Extensions = append(spec.Extensions, &utls.KeyShareExtension{KeyShares: realityKeyShares(nil)})
	}
	if !hasVersions || !hasKeyShare {
		// TLS 1.3 ClientHellos offer PSK modes; a server may reject one without them
		if !slices.ContainsFunc(spec.Extensions, func(extension utls.TLSExtension) bool {
			_, isPSKModes := extension.(*utls.PSKKeyExchangeModesExtension)
			return isPSKModes
		}) {
			spec.Extensions = append(spec.Extensions, &utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}})
		}
	}
}

// realityKeyShares keeps the GREASE share first, then X25519MLKEM768 and X25519 (the REALITY
// auth key share), then the fingerprint's other shares. Key data is left empty for utls to
// generate.
func realityKeyShares(keyShares []utls.KeyShare) []utls.KeyShare {
	var grease, others []utls.KeyShare
	for _, share := range keyShares {
		switch {
		case isGREASE(uint16(share.Group)):
			grease = append(grease, share)
		case share.Group == utls.X25519MLKEM768 || share.Group == utls.X25519:
		default:
			others = append(others, utls.KeyShare{Group: share.Group})
		}
	}
	result := append(grease, utls.KeyShare{Group: utls.X25519MLKEM768}, utls.KeyShare{Group: utls.X25519})
	return append(result, others...)
}

// withFirst returns values with first placed right after any leading GREASE values, in order,
// and not repeated later.
func withFirst[T ~uint16](values []T, first ...T) []T {
	result := make([]T, 0, len(values)+len(first))
	index := 0
	for index < len(values) && isGREASE(uint16(values[index])) {
		result = append(result, values[index])
		index++
	}
	result = append(result, first...)
	for _, value := range values[index:] {
		if !slices.Contains(first, value) {
			result = append(result, value)
		}
	}
	return result
}

func isGREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && value>>8 == value&0xff
}
