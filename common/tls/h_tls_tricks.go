package tls

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"strings"
	"unicode"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// tlsTricks are Hiddify's ClientHello changes (tls_tricks). They are made by the TLS stack, not
// by a finalmask byte mask: the ClientHello is part of the handshake transcript, so editing it on
// the wire breaks the handshake.
type tlsTricks struct {
	// mixedCaseSNI sends the server name with a random case on each connection; certificate
	// names are compared without case, so verification is unchanged.
	mixedCaseSNI bool
	// paddingMin..paddingMax is the size of a padding extension added before the SNI (uTLS only).
	padding    bool
	paddingMin int
	paddingMax int
}

const maxTLSTricksPadding = 16000

func parseTLSTricks(logger logger.ContextLogger, options *option.TLSTricksOptions, uTLS bool) (*tlsTricks, error) {
	if options == nil {
		return nil, nil
	}
	tricks := &tlsTricks{mixedCaseSNI: options.MixedCaseSNI}
	switch options.PaddingMode {
	case "random", "":
		if options.PaddingSize == "" {
			if options.PaddingMode == "random" {
				return nil, E.New("tls_tricks: padding_mode random needs a padding_size, such as \"100-200\"")
			}
			break
		}
		from, to, err := parseTLSTricksRange(options.PaddingSize)
		if err != nil {
			return nil, E.Cause(err, "tls_tricks: invalid padding_size")
		}
		if !uTLS {
			logger.Warn("tls_tricks: padding needs uTLS, ignored")
			break
		}
		tricks.padding, tricks.paddingMin, tricks.paddingMax = true, from, to
	default:
		// "sni" and "hello_client" were never implemented
		logger.Warn("tls_tricks: unsupported padding_mode ", options.PaddingMode, ", ignored")
	}
	if options.PaddingSNI != "" {
		logger.Warn("tls_tricks: padding_sni is not supported, ignored")
	}
	if !tricks.mixedCaseSNI && !tricks.padding {
		return nil, nil
	}
	return tricks, nil
}

func parseTLSTricksRange(value string) (int, int, error) {
	fromString, toString, isRange := strings.Cut(value, "-")
	if !isRange {
		toString = fromString
	}
	from, err := strconv.Atoi(strings.TrimSpace(fromString))
	if err != nil {
		return 0, 0, err
	}
	to, err := strconv.Atoi(strings.TrimSpace(toString))
	if err != nil {
		return 0, 0, err
	}
	if from > to {
		from, to = to, from
	}
	if from < 1 || to > maxTLSTricksPadding {
		return 0, 0, E.New("out of range [1, ", maxTLSTricksPadding, "]: ", value)
	}
	return from, to, nil
}

func (t *tlsTricks) serverName(name string) string {
	if t == nil || !t.mixedCaseSNI {
		return name
	}
	return randomizeCase(name)
}

func (t *tlsTricks) paddingLength() int {
	return t.paddingMin + randomInt(t.paddingMax-t.paddingMin+1)
}

func randomizeCase(name string) string {
	runes := []rune(name)
	for i, r := range runes {
		if randomInt(2) == 0 {
			runes[i] = unicode.ToUpper(r)
		} else {
			runes[i] = unicode.ToLower(r)
		}
	}
	return string(runes)
}

func randomInt(n int) int {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(value.Int64())
}
