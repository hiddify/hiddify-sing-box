package firebasetunnel

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const compressionLevel = 3

var (
	zstdOnce    sync.Once
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
	zstdInitErr error
)

func initZstd() error {
	zstdOnce.Do(func() {
		var err error
		zstdEncoder, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevel(compressionLevel)))
		if err != nil {
			zstdInitErr = fmt.Errorf("firebasetunnel: zstd encoder init: %w", err)
			return
		}
		zstdDecoder, err = zstd.NewReader(nil)
		if err != nil {
			zstdInitErr = fmt.Errorf("firebasetunnel: zstd decoder init: %w", err)
		}
	})
	return zstdInitErr
}

func compressBytes(data []byte) []byte {
	if err := initZstd(); err != nil {
		return data
	}
	return zstdEncoder.EncodeAll(data, make([]byte, 0, len(data)))
}

func decompressBytes(data []byte) ([]byte, error) {
	if err := initZstd(); err != nil {
		return nil, err
	}
	out, err := zstdDecoder.DecodeAll(data, make([]byte, 0, len(data)*3))
	if err != nil {
		return nil, fmt.Errorf("firebasetunnel: zstd decompress: %w", err)
	}
	return out, nil
}
