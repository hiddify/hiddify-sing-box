//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// hRealityHelloRecords returns the number of TLS records the REALITY ClientHello is sent in.
func hRealityHelloRecords(t *testing.T, fragment bool, recordFragment bool) int {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	config, err := NewRealityClient(context.Background(), log.NewNOPFactory().Logger(), "www.example.com", option.OutboundTLSOptions{
		Enabled:        true,
		ServerName:     "www.example.com",
		Fragment:       fragment,
		RecordFragment: recordFragment,
		UTLS:           &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:        &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())},
	})
	require.NoError(t, err)
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		config.(*RealityClientConfig).ClientHandshake(ctx, client)
		client.Close()
	}()
	server.SetDeadline(time.Now().Add(3 * time.Second))
	readRecord := func() []byte {
		header := make([]byte, 5)
		_, err := io.ReadFull(server, header)
		require.NoError(t, err)
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		_, err = io.ReadFull(server, body)
		require.NoError(t, err)
		return body
	}
	body := readRecord()
	total := 4 + (int(body[1])<<16 | int(body[2])<<8 | int(body[3]))
	records, received := 1, len(body)
	for received < total {
		received += len(readRecord())
		records++
	}
	return records
}

// fragment and record_fragment apply to REALITY as to the other TLS clients.
func TestH_RealityFragment(t *testing.T) {
	require.Equal(t, 1, hRealityHelloRecords(t, false, false))
	require.Greater(t, hRealityHelloRecords(t, false, true), 1, "record_fragment splits the ClientHello into records")
}
