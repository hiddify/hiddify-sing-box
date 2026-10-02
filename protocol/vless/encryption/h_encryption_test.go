package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testTimeout = 5 * time.Second

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(testTimeout):
		t.Fatal("accept timeout")
	}
	require.NotNil(t, server)
	deadline := time.Now().Add(testTimeout)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

type keyKind int

const (
	keyX25519 keyKind = iota
	keyMLKEM
)

func generateKeys(t *testing.T, kinds ...keyKind) (serverKeys, clientKeys [][]byte) {
	t.Helper()
	for _, kind := range kinds {
		switch kind {
		case keyX25519:
			sk, err := ecdh.X25519().GenerateKey(rand.Reader)
			require.NoError(t, err)
			serverKeys = append(serverKeys, sk.Bytes())
			clientKeys = append(clientKeys, sk.PublicKey().Bytes())
		case keyMLKEM:
			dk, err := mlkem.GenerateKey768()
			require.NoError(t, err)
			serverKeys = append(serverKeys, dk.Bytes())
			clientKeys = append(clientKeys, dk.EncapsulationKey().Bytes())
		}
	}
	return
}

type handshakeResult struct {
	conn *CommonConn
	err  error
}

func runHandshake(t *testing.T, client *ClientInstance, server *ServerInstance) (*CommonConn, *CommonConn) {
	t.Helper()
	clientRaw, serverRaw := tcpPair(t)
	serverDone := make(chan handshakeResult, 1)
	go func() {
		conn, err := server.Handshake(serverRaw, nil)
		serverDone <- handshakeResult{conn, err}
	}()
	clientConn, err := client.Handshake(clientRaw)
	require.NoError(t, err)
	var result handshakeResult
	select {
	case result = <-serverDone:
	case <-time.After(testTimeout):
		t.Fatal("server handshake timeout")
	}
	require.NoError(t, result.err)
	return clientConn, result.conn
}

func exchange(t *testing.T, writer, reader net.Conn, payload []byte, readSize int) {
	t.Helper()
	writeErr := make(chan error, 1)
	go func() {
		n, err := writer.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		writeErr <- err
	}()
	received := make([]byte, 0, len(payload))
	buffer := make([]byte, readSize)
	for len(received) < len(payload) {
		n, err := reader.Read(buffer)
		require.NoError(t, err)
		received = append(received, buffer[:n]...)
	}
	require.NoError(t, <-writeErr)
	require.Equal(t, payload, received)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func newPair(t *testing.T, xorMode uint32, clientSeconds uint32, secondsFrom, secondsTo int64, padding string, kinds ...keyKind) (*ClientInstance, *ServerInstance) {
	t.Helper()
	serverKeys, clientKeys := generateKeys(t, kinds...)
	server := &ServerInstance{}
	require.NoError(t, server.Init(serverKeys, xorMode, secondsFrom, secondsTo, padding))
	t.Cleanup(func() { server.Close() })
	client := &ClientInstance{}
	require.NoError(t, client.Init(clientKeys, xorMode, clientSeconds, padding))
	return client, server
}

func TestH_HandshakeRoundTrip1RTT(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		kinds []keyKind
	}{
		{"x25519", []keyKind{keyX25519}},
		{"mlkem768", []keyKind{keyMLKEM}},
		{"chain", []keyKind{keyX25519, keyMLKEM, keyX25519}},
	}
	for _, xorMode := range []uint32{0, 1, 2} {
		for _, c := range cases {
			name := c.name + "/xor" + string(rune('0'+xorMode))
			kinds := c.kinds
			mode := xorMode
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				client, server := newPair(t, mode, 0, 0, 0, "100-40-80", kinds...)
				require.Equal(t, mode > 0, server.IsXorMode())
				require.Equal(t, mode == 2, server.IsFullRandomXorMode())
				require.Equal(t, mode == 2, client.IsFullRandomXorMode())
				clientConn, serverConn := runHandshake(t, client, server)
				require.True(t, clientConn.IsEncryptionLayer())
				require.NotNil(t, clientConn.Upstream())
				_, isXor := clientConn.Conn.(*XorConn)
				require.Equal(t, mode == 2, isXor)

				exchange(t, clientConn, serverConn, []byte("hello server"), 64)
				exchange(t, serverConn, clientConn, []byte("hello client"), 64)
				exchange(t, clientConn, serverConn, randomBytes(70000), 1000)
				exchange(t, serverConn, clientConn, randomBytes(70000), 20000)
			})
		}
	}
}

func TestH_HandshakeDefaultPadding(t *testing.T) {
	t.Parallel()
	client, server := newPair(t, 0, 0, 0, 0, "", keyX25519)
	clientConn, serverConn := runHandshake(t, client, server)
	exchange(t, clientConn, serverConn, []byte("ping"), 16)
	exchange(t, serverConn, clientConn, []byte("pong"), 16)
}

func TestH_Handshake0RTT(t *testing.T) {
	t.Parallel()
	for _, xorMode := range []uint32{0, 2} {
		mode := xorMode
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			t.Parallel()
			client, server := newPair(t, mode, 1, 600, 0, "100-40-40", keyX25519, keyMLKEM)

			clientConn, serverConn := runHandshake(t, client, server)
			exchange(t, clientConn, serverConn, []byte("first"), 64)
			exchange(t, serverConn, clientConn, []byte("first-reply"), 64)

			client.RWLock.RLock()
			require.True(t, time.Now().Before(client.Expire))
			require.Len(t, client.Ticket, 16)
			require.Len(t, client.PfsKey, 64)
			client.RWLock.RUnlock()

			clientRaw, serverRaw := tcpPair(t)
			clientConn, err := client.Handshake(clientRaw)
			require.NoError(t, err)
			require.NotNil(t, clientConn.PreWrite)
			require.Nil(t, clientConn.PeerAEAD)

			serverDone := make(chan handshakeResult, 1)
			go func() {
				conn, err := server.Handshake(serverRaw, nil)
				serverDone <- handshakeResult{conn, err}
			}()
			writeErr := make(chan error, 1)
			go func() {
				_, err := clientConn.Write([]byte("early data"))
				writeErr <- err
			}()
			result := <-serverDone
			require.NoError(t, result.err)
			require.NoError(t, <-writeErr)
			buffer := make([]byte, 64)
			n, err := result.conn.Read(buffer)
			require.NoError(t, err)
			require.Equal(t, "early data", string(buffer[:n]))
			exchange(t, result.conn, clientConn, []byte("0rtt reply"), 64)
			exchange(t, clientConn, result.conn, randomBytes(20000), 4096)
		})
	}
}

type recordConn struct {
	net.Conn
	reader  io.Reader
	written bytes.Buffer
}

func (c *recordConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *recordConn) Write(b []byte) (int, error) { return c.written.Write(b) }

func obtainTicket(t *testing.T, client *ClientInstance, server *ServerInstance) {
	t.Helper()
	clientConn, serverConn := runHandshake(t, client, server)
	exchange(t, clientConn, serverConn, []byte("x"), 8)
}

func captureZeroRTT(t *testing.T, client *ClientInstance) []byte {
	t.Helper()
	capture := &recordConn{reader: bytes.NewReader(nil)}
	conn, err := client.Handshake(capture)
	require.NoError(t, err)
	require.NotNil(t, conn.PreWrite)
	_, err = conn.Write([]byte("payload"))
	require.NoError(t, err)
	return capture.written.Bytes()
}

func TestH_Handshake0RTTReplayRejected(t *testing.T) {
	t.Parallel()
	client, server := newPair(t, 0, 1, 600, 0, "", keyX25519)
	obtainTicket(t, client, server)
	sent := captureZeroRTT(t, client)

	_, err := server.Handshake(&recordConn{reader: bytes.NewReader(sent)}, nil)
	require.NoError(t, err)
	_, err = server.Handshake(&recordConn{reader: bytes.NewReader(sent)}, nil)
	require.ErrorContains(t, err, "replay detected")
}

func TestH_Handshake0RTTRejectedWhenDisabled(t *testing.T) {
	t.Parallel()
	client, server := newPair(t, 0, 1, 600, 0, "", keyX25519)
	obtainTicket(t, client, server)
	sent := captureZeroRTT(t, client)

	noTicketServer := &ServerInstance{}
	require.NoError(t, noTicketServer.Init([][]byte{server.NfsSKeys[0].(*ecdh.PrivateKey).Bytes()}, 0, 0, 0, ""))
	_, err := noTicketServer.Handshake(&recordConn{reader: bytes.NewReader(sent)}, nil)
	require.ErrorContains(t, err, "0-RTT is not allowed")
}

func TestH_Handshake0RTTExpiredTicketForcesNewHandshake(t *testing.T) {
	t.Parallel()
	client, server := newPair(t, 0, 1, 600, 0, "", keyX25519)
	obtainTicket(t, client, server)

	otherServer := &ServerInstance{}
	require.NoError(t, otherServer.Init([][]byte{server.NfsSKeys[0].(*ecdh.PrivateKey).Bytes()}, 0, 600, 0, ""))
	t.Cleanup(func() { otherServer.Close() })

	clientRaw, serverRaw := tcpPair(t)
	clientConn, err := client.Handshake(clientRaw)
	require.NoError(t, err)
	serverErr := make(chan error, 1)
	go func() {
		_, err := otherServer.Handshake(serverRaw, nil)
		serverErr <- err
	}()
	_, err = clientConn.Write([]byte("early"))
	require.NoError(t, err)
	require.ErrorContains(t, <-serverErr, "expired ticket")

	_, err = clientConn.Read(make([]byte, 64))
	require.ErrorContains(t, err, "new handshake needed")
	client.RWLock.RLock()
	require.False(t, time.Now().Before(client.Expire))
	client.RWLock.RUnlock()

	clientConn, serverConn := runHandshake(t, client, otherServer)
	require.Nil(t, clientConn.PreWrite)
	exchange(t, clientConn, serverConn, []byte("fresh"), 16)
}

func TestH_HandshakeWrongKeyFails(t *testing.T) {
	t.Parallel()
	_, clientKeys := generateKeys(t, keyX25519)
	serverKeys, _ := generateKeys(t, keyX25519)
	client := &ClientInstance{}
	require.NoError(t, client.Init(clientKeys, 0, 0, ""))
	server := &ServerInstance{}
	require.NoError(t, server.Init(serverKeys, 0, 0, 0, ""))

	clientRaw, serverRaw := tcpPair(t)
	serverErr := make(chan error, 1)
	var fallback []byte
	go func() {
		_, err := server.Handshake(serverRaw, &fallback)
		serverRaw.Close()
		serverErr <- err
	}()
	_, clientErr := client.Handshake(clientRaw)
	require.Error(t, <-serverErr)
	require.Error(t, clientErr)
	require.Len(t, fallback, 16+server.RelaysLength+18)
}

func TestH_HandshakeFallbackClearedOnSuccess(t *testing.T) {
	t.Parallel()
	client, server := newPair(t, 1, 0, 0, 0, "", keyMLKEM)
	clientRaw, serverRaw := tcpPair(t)
	fallback := []byte{}
	serverDone := make(chan error, 1)
	go func() {
		_, err := server.Handshake(serverRaw, &fallback)
		serverDone <- err
	}()
	_, err := client.Handshake(clientRaw)
	require.NoError(t, err)
	require.NoError(t, <-serverDone)
	require.Nil(t, fallback)
}

func TestH_HandshakeChainHashMismatch(t *testing.T) {
	t.Parallel()
	serverKeys, clientKeys := generateKeys(t, keyX25519, keyX25519)
	_, otherClientKeys := generateKeys(t, keyX25519)
	client := &ClientInstance{}
	require.NoError(t, client.Init([][]byte{clientKeys[0], otherClientKeys[0]}, 0, 0, ""))
	server := &ServerInstance{}
	require.NoError(t, server.Init(serverKeys, 0, 0, 0, ""))

	clientRaw, serverRaw := tcpPair(t)
	serverErr := make(chan error, 1)
	go func() {
		_, err := server.Handshake(serverRaw, nil)
		serverRaw.Close()
		serverErr <- err
	}()
	client.Handshake(clientRaw)
	require.ErrorContains(t, <-serverErr, "unexpected hash32")
}

func TestH_InitErrors(t *testing.T) {
	t.Parallel()
	_, clientKeys := generateKeys(t, keyX25519)
	serverKeys, _ := generateKeys(t, keyX25519)

	client := &ClientInstance{}
	_, err := client.Handshake(nil)
	require.ErrorContains(t, err, "uninitialized")
	require.ErrorContains(t, client.Init(nil, 0, 0, ""), "empty")
	require.Error(t, (&ClientInstance{}).Init([][]byte{make([]byte, 10)}, 0, 0, ""))
	require.Error(t, (&ClientInstance{}).Init(clientKeys, 0, 0, "1-2"))
	require.NoError(t, client.Init(clientKeys, 0, 0, ""))
	require.Equal(t, 32, client.RelaysLength)
	require.ErrorContains(t, client.Init(clientKeys, 0, 0, ""), "already initialized")

	server := &ServerInstance{}
	_, err = server.Handshake(nil, nil)
	require.ErrorContains(t, err, "uninitialized")
	require.ErrorContains(t, server.Init(nil, 0, 0, 0, ""), "empty")
	require.Error(t, (&ServerInstance{}).Init([][]byte{make([]byte, 10)}, 0, 0, 0, ""))
	require.NoError(t, server.Init(serverKeys, 0, 0, 0, ""))
	require.ErrorContains(t, server.Init(serverKeys, 0, 0, 0, ""), "already initialized")

	mlkemServerKeys, mlkemClientKeys := generateKeys(t, keyMLKEM, keyX25519)
	chainClient := &ClientInstance{}
	require.NoError(t, chainClient.Init(mlkemClientKeys, 0, 0, ""))
	chainServer := &ServerInstance{}
	require.NoError(t, chainServer.Init(mlkemServerKeys, 0, 0, 0, ""))
	require.Equal(t, 1088+32+32, chainClient.RelaysLength)
	require.Equal(t, chainClient.RelaysLength, chainServer.RelaysLength)
	require.Equal(t, mlkemClientKeys, chainServer.NfsPKeysBytes)
	require.Equal(t, chainClient.Hash32s, chainServer.Hash32s)
}

func TestH_ParsePadding(t *testing.T) {
	t.Parallel()
	var lens, gaps [][3]int
	require.NoError(t, ParsePadding("100-111-1111.75-0-111.50-0-3333", &lens, &gaps))
	require.Equal(t, [][3]int{{100, 111, 1111}, {50, 0, 3333}}, lens)
	require.Equal(t, [][3]int{{75, 0, 111}}, gaps)

	lens, gaps = nil, nil
	require.NoError(t, ParsePadding("", &lens, &gaps))
	require.Nil(t, lens)
	require.Nil(t, gaps)

	for _, invalid := range []string{
		"100-111",
		"100--111",
		"-1-2",
		"a-111-1111",
		"100-b-1111",
		"100-111-c",
		"99-111-1111",
		"100-34-1111",
		"100-111-34",
		"100-111-1111.75-0",
		"100-35-65554",
		"100-35-35.0-0-0.100-0-65535",
	} {
		lens, gaps = nil, nil
		require.Error(t, ParsePadding(invalid, &lens, &gaps), invalid)
	}
	lens, gaps = nil, nil
	require.NoError(t, ParsePadding("100-35-65553", &lens, &gaps))
}

func TestH_CreatePadding(t *testing.T) {
	t.Parallel()
	length, lens, gaps := CreatePadding([][3]int{{100, 200, 200}, {0, 5, 5}}, [][3]int{{100, 7, 7}})
	require.Len(t, lens, 2)
	require.Equal(t, 200, lens[0])
	require.LessOrEqual(t, lens[1], 5)
	require.Equal(t, lens[0]+lens[1], length)
	require.Equal(t, []time.Duration{7 * time.Millisecond}, gaps)

	for range 50 {
		length, lens, gaps = CreatePadding(nil, nil)
		require.Len(t, lens, 2)
		require.Len(t, gaps, 1)
		require.GreaterOrEqual(t, lens[0], 111)
		require.Less(t, lens[0], 1111)
		require.Less(t, lens[1], 3333)
		require.Equal(t, lens[0]+lens[1], length)
		require.Less(t, gaps[0], 111*time.Millisecond)
	}
}

func TestH_HeaderAndLength(t *testing.T) {
	t.Parallel()
	h := make([]byte, 5)
	EncodeHeader(h, 1234)
	require.Equal(t, []byte{23, 3, 3, 0x04, 0xd2}, h)
	l, err := DecodeHeader(h)
	require.NoError(t, err)
	require.Equal(t, 1234, l)

	for _, valid := range []int{17, 17000} {
		EncodeHeader(h, valid)
		l, err = DecodeHeader(h)
		require.NoError(t, err)
		require.Equal(t, valid, l)
	}
	for _, invalid := range []int{0, 16, 17001} {
		EncodeHeader(h, invalid)
		_, err = DecodeHeader(h)
		require.ErrorIs(t, err, ErrInvalidHeader)
	}
	l, err = DecodeHeader([]byte{22, 3, 3, 0, 100})
	require.ErrorIs(t, err, ErrInvalidHeader)
	require.Equal(t, 0, l)

	require.Equal(t, []byte{0x12, 0x34}, EncodeLength(0x1234))
	require.Equal(t, 0xfedc, DecodeLength(EncodeLength(0xfedc)))
}

func TestH_IncreaseNonce(t *testing.T) {
	t.Parallel()
	nonce := make([]byte, 12)
	require.Equal(t, append(make([]byte, 11), 1), IncreaseNonce(nonce))
	nonce = append(make([]byte, 10), 0, 0xff)
	require.Equal(t, append(make([]byte, 10), 1, 0), IncreaseNonce(nonce))
	nonce = bytes.Clone(MaxNonce)
	require.Equal(t, make([]byte, 12), IncreaseNonce(nonce))
}

func TestH_AEADBothCiphers(t *testing.T) {
	t.Parallel()
	key := randomBytes(32)
	for _, useAES := range []bool{true, false} {
		sealer := NewAEAD([]byte("ctx"), key, useAES)
		opener := NewAEAD([]byte("ctx"), key, useAES)
		other := NewAEAD([]byte("other"), key, useAES)
		for i := range 3 {
			msg := []byte{byte(i), 1, 2, 3}
			sealed := sealer.Seal(nil, nil, msg, []byte("ad"))
			opened, err := opener.Open(nil, nil, sealed, []byte("ad"))
			require.NoError(t, err)
			require.Equal(t, msg, opened)
			_, err = other.Open(nil, bytes.Clone(opener.Nonce[:]), sealed, []byte("ad"))
			require.Error(t, err)
		}
		require.Equal(t, append(make([]byte, 11), 3), sealer.Nonce[:])
	}
}

func TestH_CommonConnRekeyAtMaxNonce(t *testing.T) {
	t.Parallel()
	for _, useAES := range []bool{true, false} {
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(testTimeout))
		b.SetDeadline(time.Now().Add(testTimeout))
		key := randomBytes(96)
		writer := NewCommonConn(a, useAES)
		writer.UnitedKey = key
		writer.AEAD = NewAEAD([]byte("ctx"), key, useAES)
		reader := NewCommonConn(b, useAES)
		reader.UnitedKey = key
		reader.PeerAEAD = NewAEAD([]byte("ctx"), key, useAES)
		start := bytes.Clone(MaxNonce)
		start[11] = 0xfe
		copy(writer.AEAD.Nonce[:], start)
		copy(reader.PeerAEAD.Nonce[:], start)

		for i := range 4 {
			exchange(t, writer, reader, []byte{byte(i), 'r', 'e', 'k', 'e', 'y'}, 64)
		}
		require.Equal(t, writer.AEAD.Nonce, reader.PeerAEAD.Nonce)
		a.Close()
		b.Close()
	}
}

func TestH_CommonConnRejectsTamperedRecord(t *testing.T) {
	t.Parallel()
	key := randomBytes(64)
	writer := NewCommonConn(&recordConn{reader: bytes.NewReader(nil)}, false)
	writer.UnitedKey = key
	writer.AEAD = NewAEAD([]byte("ctx"), key, false)
	_, err := writer.Write([]byte("secret"))
	require.NoError(t, err)
	sent := bytes.Clone(writer.Conn.(*recordConn).written.Bytes())
	require.Len(t, sent, 5+6+16)

	sent[len(sent)-1] ^= 1
	reader := NewCommonConn(&recordConn{reader: bytes.NewReader(sent)}, false)
	reader.UnitedKey = key
	reader.PeerAEAD = NewAEAD([]byte("ctx"), key, false)
	_, err = reader.Read(make([]byte, 64))
	require.Error(t, err)

	reader = NewCommonConn(&recordConn{reader: bytes.NewReader([]byte{1, 2, 3, 4, 5})}, false)
	reader.UnitedKey = key
	reader.PeerAEAD = NewAEAD([]byte("ctx"), key, false)
	_, err = reader.Read(make([]byte, 64))
	require.ErrorIs(t, err, ErrInvalidHeader)

	n, err := reader.Write(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = reader.Read(nil)
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestH_XorConnRoundTrip(t *testing.T) {
	t.Parallel()
	key := randomBytes(32)
	iv := randomBytes(16)
	var records []byte
	records = append(records, []byte("PREFIX")...)
	var plainHeaders [][]byte
	for _, size := range []int{17, 300, 17000} {
		h := make([]byte, 5)
		EncodeHeader(h, size)
		plainHeaders = append(plainHeaders, h)
		records = append(records, h...)
		records = append(records, randomBytes(size)...)
	}
	original := bytes.Clone(records)

	writer := NewXorConn(&recordConn{reader: bytes.NewReader(nil)}, NewCTR(key, iv), nil, len("PREFIX"), 0)
	for offset := 0; offset < len(records); {
		n := 3
		if offset > 400 {
			n = 997
		}
		n = min(n, len(records)-offset)
		chunk := bytes.Clone(records[offset : offset+n])
		written, err := writer.Write(chunk)
		require.NoError(t, err)
		require.Equal(t, n, written)
		offset += n
	}
	onWire := writer.Conn.(*recordConn).written.Bytes()
	require.Len(t, onWire, len(original))
	require.Equal(t, original[:6], onWire[:6])
	offset := 6
	for i, size := range []int{17, 300, 17000} {
		require.NotEqual(t, plainHeaders[i], onWire[offset:offset+5])
		require.Equal(t, original[offset+5:offset+5+size], onWire[offset+5:offset+5+size])
		offset += 5 + size
	}

	reader := NewXorConn(&recordConn{reader: bytes.NewReader(onWire)}, nil, NewCTR(key, iv), 0, len("PREFIX"))
	var decoded []byte
	buffer := make([]byte, 7)
	for {
		n, err := reader.Read(buffer)
		decoded = append(decoded, buffer[:n]...)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	require.Equal(t, original, decoded)
	require.True(t, reader.IsEncryptionLayer())
	require.NotNil(t, reader.Upstream())

	n, err := reader.Write(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = reader.Read(nil)
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestH_NewCTRDeterministic(t *testing.T) {
	t.Parallel()
	key := randomBytes(32)
	iv := randomBytes(16)
	a := make([]byte, 64)
	b := make([]byte, 64)
	NewCTR(key, iv).XORKeyStream(a, a)
	NewCTR(key, iv).XORKeyStream(b, b)
	require.Equal(t, a, b)
	require.NotEqual(t, make([]byte, 64), a)
	c := make([]byte, 64)
	NewCTR(randomBytes(32), iv).XORKeyStream(c, c)
	require.NotEqual(t, a, c)
}
