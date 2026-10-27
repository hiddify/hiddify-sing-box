//go:build with_utls

package tls

import (
	utls "github.com/metacubex/utls"
)

// applyTLSTricksPadding replaces the fingerprint's padding extension with one of the configured
// size, placed right before the SNI.
func applyTLSTricksPadding(conn *utls.UConn, id utls.ClientHelloID, tricks *tlsTricks) error {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return err
	}
	padding := &utls.UtlsPaddingExtension{PaddingLen: tricks.paddingLength(), WillPad: true}
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	inserted := false
	for _, extension := range spec.Extensions {
		switch extension.(type) {
		case *utls.UtlsPaddingExtension:
			continue
		case *utls.SNIExtension:
			extensions = append(extensions, padding)
			inserted = true
		}
		extensions = append(extensions, extension)
	}
	if !inserted {
		extensions = append([]utls.TLSExtension{padding}, extensions...)
	}
	spec.Extensions = extensions
	return conn.ApplyPreset(&spec)
}
