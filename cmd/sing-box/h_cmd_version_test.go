package main

import (
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func hCaptureVersion(t *testing.T, name bool) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	originalStdout := os.Stdout
	originalNameOnly := nameOnly
	os.Stdout = writer
	nameOnly = name
	defer func() {
		os.Stdout = originalStdout
		nameOnly = originalNameOnly
	}()
	printVersion(commandVersion, nil)
	require.NoError(t, writer.Close())
	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	return string(output)
}

func TestH_PrintVersion(t *testing.T) {
	output := hCaptureVersion(t, false)
	require.True(t, strings.HasPrefix(output, "hiddify-sing-box version "+C.Version+"\n\n"), output)
	require.Contains(t, output, "Environment: "+runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH+"\n")
	require.Regexp(t, `CGO: (enabled|disabled)\n$`, output)

	require.Equal(t, C.Version+"\n", hCaptureVersion(t, true))
}

func TestH_VersionCommandFlags(t *testing.T) {
	flag := commandVersion.Flags().Lookup("name")
	require.NotNil(t, flag)
	require.Equal(t, "n", flag.Shorthand)
	require.Equal(t, "false", flag.DefValue)
	found := false
	for _, command := range mainCommand.Commands() {
		if command == commandVersion {
			found = true
		}
	}
	require.True(t, found)
}
