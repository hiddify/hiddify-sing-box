package libbox

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func hReportPaths(t *testing.T) {
	t.Helper()
	basePath, workingPath := sBasePath, sWorkingPath
	sBasePath, sWorkingPath = t.TempDir(), t.TempDir()
	t.Cleanup(func() { sBasePath, sWorkingPath = basePath, workingPath })
}

// A crash report is made to be shared, so it must not carry the configuration, which holds the
// servers' addresses, keys and passwords; nor is the configuration kept on disk for it.
func TestH_CrashReportWithoutConfiguration(t *testing.T) {
	hReportPaths(t)
	saveConfigSnapshot(`{"outbounds":[{"type":"vless","uuid":"secret"}]}`)
	_, err := os.Stat(configSnapshotPath())
	require.True(t, os.IsNotExist(err), "the configuration was saved for reports")
	crashLog := filepath.Join(sWorkingPath, "CrashReport-test.log")
	require.NoError(t, os.WriteFile(crashLog, []byte("panic: test"), 0o600))
	reportsDir := filepath.Join(sWorkingPath, "crash_reports")
	archiveCrashReport(crashLog, reportsDir)
	reports, err := os.ReadDir(reportsDir)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	_, err = os.Stat(filepath.Join(reportsDir, reports[0].Name(), "configuration.json"))
	require.True(t, os.IsNotExist(err), "the report carries the configuration")
}

// Reports pile up with every crash; only the newest are kept.
func TestH_CrashReportsArePruned(t *testing.T) {
	hReportPaths(t)
	reportsDir := filepath.Join(sWorkingPath, "crash_reports")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range maxReports + 8 {
		path, err := nextAvailableReportPath(reportsDir, start.Add(time.Duration(i)*time.Hour))
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(path, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(path, "go.log"), []byte("panic: "+strconv.Itoa(i)), 0o600))
	}
	crashLog := filepath.Join(sWorkingPath, "CrashReport-test.log")
	require.NoError(t, os.WriteFile(crashLog, []byte("panic: newest"), 0o600))
	archiveCrashReport(crashLog, reportsDir)
	reports, err := os.ReadDir(reportsDir)
	require.NoError(t, err)
	require.Len(t, reports, maxReports)
	// the oldest went first
	require.Equal(t, start.Add(9*time.Hour).Format("2006-01-02T15-04-05"), reports[0].Name())
}
