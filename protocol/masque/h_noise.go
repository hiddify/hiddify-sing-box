package masque

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/hiddify/rating"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// The noise of a MASQUE tunnel is its TLS server name: with search_noise, the scanner tries the
// configured one and those of warpscan.MASQUENoisePresets (www.speedtest.net), keeps the one an
// endpoint answers, and the tunnel connects with it. "" is the configured server name.

type masqueScannerOptions = option.WARPScannerOptions

// lastWayNoise is the method of a last way (see edgescan.LastWay) that names its noise.
const lastWayNoise = "noise"

// configuredNoisePrior is the score the configured server name counts as on a network where it
// was never tried: the user chose it, so it comes first more often than an untried preset.
const configuredNoisePrior rating.Score = 2

// noiseSearchCount is the most endpoints a scan probes with a noise that did not get through on
// the network before: the endpoints known to answer come first, so a few are enough to tell.
const noiseSearchCount = 16

// masqueNoises keeps the TLS configurations and probes of each noise, and the noise in use per
// HTTP version.
type masqueNoises struct {
	probeDialer N.Dialer
	base        tls.Config // the configured server name

	access  sync.Mutex
	configs map[string]tls.Config
	probes  map[noiseProbeKey]warpscan.Probe
	current map[bool]string // per HTTP/2
}

type noiseProbeKey struct {
	noise string
	http2 bool
}

func newMASQUENoises(probeDialer N.Dialer, base tls.Config) *masqueNoises {
	return &masqueNoises{
		probeDialer: probeDialer,
		base:        base,
		configs:     map[string]tls.Config{"": base},
		probes:      make(map[noiseProbeKey]warpscan.Probe),
		current:     make(map[bool]string),
	}
}

// config is the TLS of noise: the configured one with the preset's server name.
func (n *masqueNoises) config(noise string) tls.Config {
	n.access.Lock()
	defer n.access.Unlock()
	if config, loaded := n.configs[noise]; loaded {
		return config
	}
	preset, found := warpscan.MASQUENoisePresetByName(noise)
	if !found {
		return n.base
	}
	config := n.base.Clone()
	config.SetServerName(preset.ServerName)
	n.configs[noise] = config
	return config
}

// probe is the probe of the HTTP version with noise.
func (n *masqueNoises) probe(http2 bool, noise string) warpscan.Probe {
	config := n.config(noise)
	n.access.Lock()
	defer n.access.Unlock()
	key := noiseProbeKey{noise, http2}
	if probe, loaded := n.probes[key]; loaded {
		return probe
	}
	probe := warpscan.MASQUEProbe(n.probeDialer, config, http2)
	n.probes[key] = probe
	return probe
}

// TLSConfig is the TLS of the next connect of the HTTP version (see masque.TunnelOptions).
func (n *masqueNoises) TLSConfig(http2 bool) tls.Config {
	return n.config(n.noise(http2))
}

func (n *masqueNoises) noise(http2 bool) string {
	if n == nil {
		return ""
	}
	n.access.Lock()
	defer n.access.Unlock()
	return n.current[http2]
}

// use puts noise in use for the HTTP version, and reports whether it changed.
func (n *masqueNoises) use(http2 bool, noise string) bool {
	if n == nil {
		return false
	}
	n.access.Lock()
	defer n.access.Unlock()
	changed := n.current[http2] != noise
	n.current[http2] = noise
	return changed
}

// noiseName names a noise for the log.
func noiseName(noise string) string {
	if noise == "" {
		return "the configured server name"
	}
	if preset, found := warpscan.MASQUENoisePresetByName(noise); found {
		return "server name " + preset.ServerName
	}
	return noise
}

// noisePresets are the MASQUE presets of options' scanner: those of noise_presets that are
// MASQUE's, or all of them when it names none.
func noisePresets(options *masqueScannerOptions) []string {
	var presets []string
	if len(options.NoisePresets) == 0 {
		for _, preset := range warpscan.MASQUENoisePresets {
			presets = append(presets, preset.Name)
		}
		return presets
	}
	for _, name := range options.NoisePresets {
		if preset, found := warpscan.MASQUENoisePresetByName(name); found {
			presets = append(presets, preset.Name)
		}
	}
	return presets
}

// validateNoisePresets fails a noise_presets name that is no preset of WireGuard or MASQUE.
func validateNoisePresets(options *masqueScannerOptions) error {
	if options == nil {
		return nil
	}
	for _, name := range options.NoisePresets {
		if !warpscan.IsNoisePreset(name) {
			return E.New("masque: unknown noise preset: ", name)
		}
	}
	return nil
}

// noiseCandidates are the noises a scan tries on network (the configured server name, then the
// presets), in a weighted random order by their score there (see warpscan.Book.OrderMethods):
// the one that gets through most is tried first most of the time, the others now and then.
// Without search_noise, the configured one alone.
func (s *masqueScanner) noiseCandidates(networkName string) []string {
	scanner := s.options.Scanner
	if scanner == nil || !scanner.SearchNoise {
		return []string{""}
	}
	byMethod := map[string]string{warpscan.NoiseMethod(""): ""}
	methods := []string{warpscan.NoiseMethod("")}
	for _, preset := range noisePresets(scanner) {
		method := warpscan.NoiseMethod(preset)
		if _, seen := byMethod[method]; !seen {
			byMethod[method] = preset
			methods = append(methods, method)
		}
	}
	if len(methods) == 1 {
		return []string{""}
	}
	ordered := s.book.OrderMethods(networkName, methods, func(method string) rating.Score {
		if method == warpscan.NoiseMethod("") {
			return configuredNoisePrior
		}
		return 0
	})
	candidates := make([]string, len(ordered))
	for i, method := range ordered {
		candidates[i] = byMethod[method]
	}
	return candidates
}

// noiseCount is the most endpoints the scan with the i-th of candidates probes: the full count
// for the first, unless it never got through on the network while another did; noiseSearchCount
// for the others.
func (s *masqueScanner) noiseCount(networkName string, candidates []string, i int, count int) int {
	if count > 0 && count <= noiseSearchCount {
		return count
	}
	if i == 0 {
		if score, _ := s.book.MethodScore(networkName, warpscan.NoiseMethod(candidates[0])); score > 0 {
			return count
		}
		for _, candidate := range candidates {
			if score, _ := s.book.MethodScore(networkName, warpscan.NoiseMethod(candidate)); score > 0 {
				return noiseSearchCount
			}
		}
		return count
	}
	return noiseSearchCount
}

// scanNoises scans with each noise of noiseCandidates until an endpoint answers, and returns the
// endpoints and the noise. That noise gains a point on the network, and those tried before it
// lose one; when none gets through, none is marked down.
func (s *masqueScanner) scanNoises(ctx context.Context, network string, scan func(options *masqueScannerOptions, probe warpscan.Probe) ([]warpscan.Result, error), http2 bool) ([]warpscan.Result, string, error) {
	candidates := s.noiseCandidates(network)
	var (
		lastErr error
		failed  []string
	)
	for i, noise := range candidates {
		options := *s.options.Scanner
		if len(candidates) > 1 {
			options.Count = s.noiseCount(network, candidates, i, options.Count)
		}
		results, err := scan(&options, s.probe(http2, noise))
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			failed = append(failed, warpscan.NoiseMethod(noise))
			continue
		}
		if len(candidates) > 1 {
			s.book.SettleMethods(network, warpscan.NoiseMethod(noise), failed, time.Now())
		}
		return results, noise, nil
	}
	return nil, "", lastErr
}

// probe is the probe of the HTTP version with noise.
func (s *masqueScanner) probe(http2 bool, noise string) warpscan.Probe {
	if noise == "" || s.noises == nil {
		return s.probes[http2]
	}
	return s.noises.probe(http2, noise)
}

// useNoise puts noise in use for the next connect of the HTTP version.
func (s *masqueScanner) useNoise(http2 bool, noise string) {
	if s.noises.use(http2, noise) {
		s.logger.InfoContext(s.ctx, "WARP scanner: ", noiseName(noise), " gets through", versionSuffix(http2))
	}
}

// probeLastWay checks addrPort with the noise of the last way, and puts that noise in use when it
// answers.
func (s *masqueScanner) probeLastWay(ctx context.Context, http2 bool, noise string, addrPort netip.AddrPort, try func(probe warpscan.Probe) (time.Duration, error)) (time.Duration, error) {
	if noise != "" {
		if _, found := warpscan.MASQUENoisePresetByName(noise); !found || s.options.Scanner == nil || !s.options.Scanner.SearchNoise {
			noise = "" // a preset that is no longer offered
		}
	}
	rtt, err := try(s.probe(http2, noise))
	if err == nil {
		s.useNoise(http2, noise)
	}
	return rtt, err
}
