package box

import (
	"os"

	"github.com/sagernet/sing-box/hiddify/procs"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func hCheckProcsOptions(options *option.HProcsOptions) error {
	if options == nil {
		return nil
	}
	if options.Min < 0 || options.Max < 0 {
		return E.New("debug.procs: min and max cannot be negative")
	}
	if options.Max != 0 && options.Max < max(options.Min, 1) {
		return E.New("debug.procs: max (", options.Max, ") is less than min (", max(options.Min, 1), ")")
	}
	return nil
}

// hStartProcs starts the governor of the number of Go processors (experimental.debug.procs),
// once everything is started: what sizes itself by the processors at start sees them all. It
// stops, and the runtime gets its own number back, when the box closes.
//
// GOMAXPROCS in the environment is a number somebody chose, and is left alone. HIDDIFY_PROCS=off
// turns the governor off and HIDDIFY_PROCS=auto on, whatever the config says: to compare.
func (s *Box) hStartProcs() {
	options := s.debugOptions.Procs
	enabled := options != nil && options.Enabled
	switch os.Getenv("HIDDIFY_PROCS") {
	case "off":
		enabled = false
	case "auto":
		enabled = true
	}
	if !enabled {
		return
	}
	if os.Getenv("GOMAXPROCS") != "" {
		s.logger.Info("procs: GOMAXPROCS is set, the number of processors is left alone")
		return
	}
	governorOptions := procs.Options{Logger: s.logger}
	if options != nil {
		governorOptions.Min, governorOptions.Max = options.Min, options.Max
	}
	governor := procs.Start(governorOptions)
	if governor != nil {
		s.scope.Add(governor.Close)
		least, most := governor.Range()
		s.logger.Info("procs: ", least, " Go processor(s) while there is little to do, up to ", most, " under load")
	}
}
