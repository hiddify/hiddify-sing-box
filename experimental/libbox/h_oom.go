//go:build darwin || linux || windows

package libbox

import (
	"path/filepath"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox/internal/runtimeinfo"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing/common/byteformats"
)

// Hiddify runs its own service rather than the command server, and starts a new
// daemon.StartedService at every start of the core. The OOM recorder lives for the whole process,
// as the command server's does, so it reads the service that runs when it writes a report.

// OOMKillerOptions are the OOM killer settings of Setup, for a service built without the command
// server: daemon.ServiceOptions takes them as they are.
func OOMKillerOptions() (enabled bool, killerDisabled bool, memoryLimit uint64) {
	return sOOMKillerEnabled, sOOMKillerDisabled, uint64(sOOMMemoryLimit)
}

// OOMRecorderOptionsFor is OOMRecorderOptions for a service that changes: current gives the
// running one, or nil between two starts.
func OOMRecorderOptionsFor(current func() *daemon.StartedService) oomkiller.RecorderOptions {
	return oomkiller.RecorderOptions{
		BasePath:    sWorkingPath,
		Logger:      log.StdLogger(),
		AcceptDraft: acceptOOMDraft,
		MetadataCallback: func(status oomkiller.ReportStatus) any {
			metadata := oomReportMetadata{
				reportMetadata: baseReportMetadata(),
				RecordedAt:     status.RecordedAt.UTC().Format(time.RFC3339),
				MemoryUsage:    byteformats.FormatMemoryBytes(status.PeakMemory),
				Snapshots:      status.Snapshots,
			}
			metadata.StartedAt = status.StartedAt.UTC().Format(time.RFC3339)
			if status.MemoryLimit > 0 {
				metadata.MemoryLimit = byteformats.FormatMemoryBytes(status.MemoryLimit)
			}
			if status.AvailableKnown {
				metadata.AvailableMemory = byteformats.FormatMemoryBytes(status.MinAvailable)
			}
			return metadata
		},
		OwnerCallback: chownReport,
		LogCallback: func() []byte {
			startedService := current()
			if startedService == nil {
				return nil
			}
			return formatLogEntries(startedService.SavedLog())
		},
		SnapshotCallback: func(directory string, prefix string) {
			for _, name := range oomReportProfiles {
				writeOOMProfile(filepath.Join(directory, prefix+"."+name+".pb"), name)
			}
			runtimeInfoPath := filepath.Join(directory, prefix+".runtime.json")
			if runtimeinfo.WriteFile(runtimeInfoPath) == nil {
				chownReport(runtimeInfoPath)
			}
			copyConfigSnapshot(directory)
			if startedService := current(); startedService != nil {
				if content := oomConnectionsContent(startedService); content != nil {
					writeReportFile(directory, prefix+".connections.json", content)
				}
			}
		},
	}
}
