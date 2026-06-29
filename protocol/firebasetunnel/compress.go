package firebasetunnel

// Adapted from github.com/Hiddify2/Firebase-Tunnel (no LICENSE upstream;
// logic rewritten into this package rather than vendored).

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

const compressionLevel = 3

var (
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
)

func init() {
	var err error
	zstdEncoder, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevel(compressionLevel)))
	if err != nil {
		panic(fmt.Sprintf("firebasetunnel: zstd encoder init: %v", err))
	}
	zstdDecoder, err = zstd.NewReader(nil)
	if err != nil {
		panic(fmt.Sprintf("firebasetunnel: zstd decoder init: %v", err))
	}
}

func compressBytes(data []byte) []byte {
	return zstdEncoder.EncodeAll(data, make([]byte, 0, len(data)))
}

func decompressBytes(data []byte) ([]byte, error) {
	out, err := zstdDecoder.DecodeAll(data, make([]byte, 0, len(data)*3))
	if err != nil {
		return nil, fmt.Errorf("firebasetunnel: zstd decompress: %w", err)
	}
	return out, nil
}
