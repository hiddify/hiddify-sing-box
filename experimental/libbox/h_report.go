package libbox

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/service/powerreport"
)

// Reports pile up with every crash, OOM kill and power report; keep the newest maxReports of
// each kind, and drop the oldest past maxReportsSize.
const (
	maxReports     = 32
	maxReportsSize = 64 << 20
)

const crashReportsDirectoryName = "crash_reports"

func pruneAllReports() {
	for _, name := range []string{crashReportsDirectoryName, oomkiller.ReportsDirectoryName, powerreport.ReportsDirectoryName} {
		pruneReports(filepath.Join(sWorkingPath, name))
	}
}

// pruneReports removes the oldest reports in reportsDir past the limits. Report directories are
// named by time, so the name order is the age order; the newest report is always kept.
func pruneReports(reportsDir string) {
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return
	}
	var reports []string
	for _, entry := range entries {
		if entry.IsDir() {
			reports = append(reports, entry.Name())
		}
	}
	slices.Sort(reports)
	sizes := make([]int64, len(reports))
	var totalSize int64
	for i, report := range reports {
		sizes[i] = directorySize(filepath.Join(reportsDir, report))
		totalSize += sizes[i]
	}
	for i := 0; i < len(reports)-1; i++ {
		if len(reports)-i <= maxReports && totalSize <= maxReportsSize {
			break
		}
		os.RemoveAll(filepath.Join(reportsDir, reports[i]))
		totalSize -= sizes[i]
	}
}

func directorySize(path string) int64 {
	var size int64
	filepath.WalkDir(path, func(_ string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			info, infoErr := entry.Info()
			if infoErr == nil {
				size += info.Size()
			}
		}
		return nil
	})
	return size
}
