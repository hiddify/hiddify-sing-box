package libbox

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestH_ErrorMessageRoundTrip(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"", "boom", strings.Repeat("x", 300), "unicode: مثال"} {
		encoded := (&ErrorMessage{Message: text}).Encode()
		require.Equal(t, byte(MessageTypeError), encoded[0])
		decoded, err := DecodeErrorMessage(encoded)
		require.NoError(t, err)
		require.Equal(t, text, decoded.Message)

		legacy, err := readString(bytes.NewReader(encoded[1:]))
		require.NoError(t, err)
		require.Equal(t, text, legacy)
		var legacyBuffer bytes.Buffer
		legacyBuffer.WriteByte(MessageTypeError)
		writeString(&legacyBuffer, text)
		require.Equal(t, legacyBuffer.Bytes(), encoded)
	}
	_, err := DecodeErrorMessage(nil)
	require.Error(t, err)
	_, err = DecodeErrorMessage([]byte{MessageTypeProfileList, 0})
	require.ErrorContains(t, err, "invalid message")
	_, err = DecodeErrorMessage([]byte{MessageTypeError, 10, 'a'})
	require.Error(t, err)
}

func TestH_ProfileListRoundTrip(t *testing.T) {
	t.Parallel()
	encoder := &ProfileEncoder{}
	profiles := []ProfilePreview{
		{ProfileID: 1, Name: "local", Type: ProfileTypeLocal},
		{ProfileID: -7, Name: "", Type: ProfileTypeiCloud},
		{ProfileID: 1 << 40, Name: strings.Repeat("r", 200), Type: ProfileTypeRemote},
	}
	for i := range profiles {
		encoder.Append(&profiles[i])
	}
	encoded := encoder.Encode()
	var decoder ProfileDecoder
	require.NoError(t, decoder.Decode(encoded))
	iterator := decoder.Iterator()
	var decoded []ProfilePreview
	for iterator.HasNext() {
		decoded = append(decoded, *iterator.Next())
	}
	require.Equal(t, profiles, decoded)

	require.Error(t, (&ProfileDecoder{}).Decode([]byte{MessageTypeError}))
	require.Error(t, (&ProfileDecoder{}).Decode(encoded[:len(encoded)-2]))
	require.NoError(t, (&ProfileDecoder{}).Decode((&ProfileEncoder{}).Encode()))
}

func TestH_ProfileContentRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []ProfileContent{
		{Name: "local", Type: ProfileTypeLocal, Config: `{"log":{}}`},
		{Name: "cloud", Type: ProfileTypeiCloud, Config: "{}", RemotePath: "/icloud/p.json"},
		{Name: "remote", Type: ProfileTypeRemote, Config: "{}", RemotePath: "https://example.com/sub", AutoUpdate: true, AutoUpdateInterval: 60, LastUpdated: 1700000000},
	}
	for _, content := range cases {
		decoded, err := DecodeProfileContent(content.Encode())
		require.NoError(t, err)
		require.Equal(t, content, *decoded)
	}
	_, err := DecodeProfileContent([]byte{MessageTypeError})
	require.ErrorContains(t, err, "invalid message")
	_, err = DecodeProfileContent([]byte{MessageTypeProfileContent, 1, 'n', 'o', 't', 'g', 'z'})
	require.Error(t, err)
}

func TestH_ProfileContentLegacyVersion0(t *testing.T) {
	t.Parallel()
	buffer := new(bytes.Buffer)
	buffer.WriteByte(MessageTypeProfileContent)
	buffer.WriteByte(0)
	gWriter := gzip.NewWriter(buffer)
	writer := bufio.NewWriter(gWriter)
	writeStringBuffered(writer, "old")
	_ = binary.Write(writer, binary.BigEndian, ProfileTypeiCloud)
	writeStringBuffered(writer, "{}")
	writeStringBuffered(writer, "/path")
	_ = binary.Write(writer, binary.BigEndian, true)
	_ = binary.Write(writer, binary.BigEndian, int64(42))
	require.NoError(t, writer.Flush())
	require.NoError(t, gWriter.Close())
	decoded, err := DecodeProfileContent(buffer.Bytes())
	require.NoError(t, err)
	require.Equal(t, ProfileContent{Name: "old", Type: ProfileTypeiCloud, Config: "{}", RemotePath: "/path", AutoUpdate: true, LastUpdated: 42}, *decoded)
}

func TestH_ProfileContentRequestAndChunk(t *testing.T) {
	t.Parallel()
	request, err := DecodeProfileContentRequest((&ProfileContentRequest{ProfileID: 99}).Encode())
	require.NoError(t, err)
	require.Equal(t, int64(99), request.ProfileID)
	_, err = DecodeProfileContentRequest([]byte{MessageTypeError})
	require.Error(t, err)

	chunk := EncodeChunkedMessage([]byte("hello"))
	require.Equal(t, int32(5), DecodeLengthChunk(chunk[:2]))
	require.Equal(t, "hello", string(chunk[2:]))
}

func hWriteTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
}

func TestH_CreateZipArchive(t *testing.T) {
	t.Parallel()
	temp := t.TempDir()
	source := filepath.Join(temp, "report")
	hWriteTree(t, source, map[string]string{"a.txt": "alpha", "sub/b.log": "beta"})
	require.NoError(t, os.MkdirAll(filepath.Join(source, "empty"), 0o755))
	destination := filepath.Join(temp, "report.zip")
	require.NoError(t, CreateZipArchive(source, destination, false))

	reader, err := zip.OpenReader(destination)
	require.NoError(t, err)
	defer reader.Close()
	var names []string
	contents := make(map[string]string)
	for _, file := range reader.File {
		names = append(names, file.Name)
		if strings.HasSuffix(file.Name, "/") {
			continue
		}
		rc, err := file.Open()
		require.NoError(t, err)
		var buffer bytes.Buffer
		_, err = buffer.ReadFrom(rc)
		require.NoError(t, err)
		rc.Close()
		contents[file.Name] = buffer.String()
	}
	sort.Strings(names)
	require.Equal(t, []string{"report/a.txt", "report/empty/", "report/sub/", "report/sub/b.log"}, names)
	require.Equal(t, "alpha", contents["report/a.txt"])
	require.Equal(t, "beta", contents["report/sub/b.log"])

	require.ErrorIs(t, CreateZipArchive(filepath.Join(source, "a.txt"), filepath.Join(temp, "x.zip"), false), os.ErrInvalid)
	require.Error(t, CreateZipArchive(filepath.Join(temp, "missing"), filepath.Join(temp, "y.zip"), false))
}

// a report archive leaves out the configuration and connections, and scrubs its text
func TestH_CreateZipArchiveRemovesSensitiveData(t *testing.T) {
	t.Parallel()
	temp := t.TempDir()
	source := filepath.Join(temp, "report")
	hWriteTree(t, source, map[string]string{
		"configuration.json": `{"password": "hunter2"}`,
		"1.connections.json": `[{"destination": "secret.example:443"}]`,
		"go.log":             "dial 203.0.113.7:443 via vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?sni=x failed; token=abc123 user me@example.com at https://api.example.com/v1/reg?key=zz [2001:db8::1]:53",
		"metadata.json":      `{"coreVersion": "1.15"}`,
	})
	destination := filepath.Join(temp, "report.zip")
	require.NoError(t, CreateZipArchive(source, destination, true))
	reader, err := zip.OpenReader(destination)
	require.NoError(t, err)
	defer reader.Close()
	files := map[string]string{}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		content, err := file.Open()
		require.NoError(t, err)
		data, err := io.ReadAll(content)
		content.Close()
		require.NoError(t, err)
		files[filepath.Base(file.Name)] = string(data)
	}
	require.NotContains(t, files, "configuration.json")
	require.NotContains(t, files, "1.connections.json")
	require.Equal(t, `{"coreVersion": "1.15"}`, files["metadata.json"])
	log := files["go.log"]
	for _, secret := range []string{"203.0.113.7", "1.2.3.4", "b831381d", "abc123", "me@example.com", "api.example.com", "zz", "2001:db8"} {
		require.NotContains(t, log, secret)
	}
	require.Contains(t, log, "failed")
}

func TestH_ContextHelpers(t *testing.T) {
	t.Parallel()
	require.Nil(t, WrapPlatformInterface(nil))
	//nolint:staticcheck
	ctx := FromContext(nil, nil)
	require.NotNil(t, ctx)
	require.NotNil(t, service.FromContext[adapter.InboundRegistry](ctx))
	require.NotNil(t, service.FromContext[adapter.OutboundRegistry](ctx))
	require.NotNil(t, service.FromContext[adapter.EndpointRegistry](ctx))

	type hKey struct{}
	parent := context.WithValue(context.Background(), hKey{}, "v")
	derived := FromContext(parent, nil)
	require.Equal(t, "v", derived.Value(hKey{}))
	require.NotNil(t, BaseContext(nil))
}

func TestH_CheckConfigOptionsNil(t *testing.T) {
	t.Parallel()
	require.ErrorIs(t, CheckConfigOptions(nil), os.ErrInvalid)
}

func TestH_PlatformInterfaceStub(t *testing.T) {
	t.Parallel()
	stub := (*platformInterfaceStub)(nil)
	require.Nil(t, stub.SystemCertificates())
	require.False(t, stub.UsePlatformShell())
	require.ErrorIs(t, stub.CheckPlatformShell(), os.ErrInvalid)
	_, err := stub.LookupUser("root")
	require.ErrorIs(t, err, os.ErrInvalid)
	require.False(t, stub.UsePlatformLocalDNSTransport())
	require.Nil(t, stub.LocalDNSTransport())
	monitor := &interfaceMonitorStub{}
	require.Nil(t, monitor.MyInterfaces())
	require.Empty(t, monitor.MyInterface())
}

func TestH_PlatformWrapperSystemCertificates(t *testing.T) {
	t.Parallel()
	wrapper := &platformInterfaceWrapper{iif: &hCertPlatform{certificates: []string{"a", "b"}}}
	require.Equal(t, []string{"a", "b"}, wrapper.SystemCertificates())
	require.Nil(t, (&platformInterfaceWrapper{iif: &hCertPlatform{}}).SystemCertificates())
}

type hCertPlatform struct {
	PlatformInterface
	certificates []string
}

func (p *hCertPlatform) SystemCertificates() StringIterator {
	if p.certificates == nil {
		return nil
	}
	return newIterator(p.certificates)
}
