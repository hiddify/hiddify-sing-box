package scanner

import (
	"context"
	"time"
)

func probeEndpoint(ctx context.Context, cfg Config, ep Endpoint) []Result {
	base := Result{
		IP:        ep.IP.String(),
		Port:      ep.Port,
		CheckedAt: time.Now().UTC(),
	}

	if err := ctx.Err(); err != nil {
		base.Error = err.Error()
		return []Result{base}
	}

	lanes, needFP := lanesForPort(cfg, ep.Port)
	if needFP {
		fp, err := fingerprintEndpoint(ctx, cfg, ep)
		if err != nil {
			base.Error = "fingerprint: " + err.Error()
			return []Result{base}
		}
		switch fp {
		case fpSOCKS5:
			lanes = []Protocol{ProtoSOCKS5, ProtoHTTP}
		case fpHTTP:
			lanes = []Protocol{ProtoHTTP, ProtoSOCKS5}
		case fpAmbiguous:
			lanes = []Protocol{ProtoHTTP, ProtoSOCKS5}
		default:
			base.Error = "fingerprint: drop (tls server)"
			return []Result{base}
		}
	}

	var results []Result
	var lastErr string
	for _, lane := range lanes {
		if ctx.Err() != nil {
			base.Error = ctx.Err().Error()
			return []Result{base}
		}
		var (
			lat int64
			err error
		)
		switch lane {
		case ProtoSOCKS5:
			lat, err = probeSOCKS5(ctx, cfg, ep)
		case ProtoHTTP:
			lat, err = probeHTTP(ctx, cfg, ep)
		default:
			continue
		}
		if err == nil {
			r := base
			r.Protocol = lane
			r.LatencyMS = lat
			results = append(results, r)
		} else {
			lastErr = string(lane) + ": " + err.Error()
		}
	}

	if len(results) > 0 {
		return results
	}
	if lastErr == "" {
		lastErr = "no lane validated"
	}
	base.Error = lastErr
	return []Result{base}
}

func fingerprintEndpoint(ctx context.Context, cfg Config, ep Endpoint) (fingerprintVerdict, error) {
	conn, err := dialFast(ctx, ep, cfg.DialTimeout)
	if err != nil {
		return fpTLS, err
	}
	defer conn.Close()
	release := armCancel(ctx, conn)
	defer release()
	return fingerprint(ctx, conn, cfg.FingerprintTimeout), nil
}
