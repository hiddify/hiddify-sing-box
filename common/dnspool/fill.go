package dnspool

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

const (
	// DefaultFillWant is how many working resolvers a pool is filled up to.
	DefaultFillWant = 10
	// DefaultFillConcurrency is how many resolvers are probed at once.
	DefaultFillConcurrency = 100
	// DefaultFillRecheck is how often a filled pool checks that it still has enough working
	// resolvers.
	DefaultFillRecheck = 15 * time.Second
)

// FillOptions say how a pool is filled from an outbound's candidates.
type FillOptions struct {
	// Candidates are probed in this order (sort them with History.Sort first).
	Candidates []Candidate
	// Probe checks one candidate; nil when it may join the pool.
	Probe func(ctx context.Context, address string) error
	// Want is how many working resolvers the pool keeps (DefaultFillWant). A resolver that is
	// down does not count, so once resolvers that worked stop answering, probing resumes from
	// the next candidate, like Soar's discovery.
	Want int
	// Concurrency bounds the probes at once (DefaultFillConcurrency).
	Concurrency int
	// Pace is the least gap between starting two probes (none by default).
	Pace time.Duration
	// Recheck is how often a filled pool is checked again (DefaultFillRecheck).
	Recheck time.Duration
	// History records each probe's result; saved under HistoryKey in Cache after the first
	// resolver joined and at the end of each round.
	History    *History
	Cache      adapter.CacheFile
	HistoryKey string
	// OnFirst runs once, when the first resolver joined.
	OnFirst func()
}

// Working is the number of resolvers in the pool that are not down: healthy or rate-limited.
func (p *Pool) Working() int {
	working := 0
	for _, stat := range p.manager.Stats() {
		if stat.State != "down" {
			working++
		}
	}
	return working
}

// Fill probes the candidates and puts the ones that answer into the pool, until Want of them
// work, then checks every Recheck and probes the next candidates whenever fewer work. It returns
// when the candidates are used up or ctx ends, with the number of resolvers added.
func (p *Pool) Fill(ctx context.Context, logger log.ContextLogger, options FillOptions) int {
	if options.Want <= 0 {
		options.Want = DefaultFillWant
	}
	if options.Concurrency <= 0 {
		options.Concurrency = DefaultFillConcurrency
	}
	if options.Recheck <= 0 {
		options.Recheck = DefaultFillRecheck
	}
	if options.History == nil {
		options.History = NewHistory()
	}
	history := options.History
	defer history.Save(options.Cache, options.HistoryKey, logger)

	var firstOnce sync.Once
	total := 0
	pending := options.Candidates
	for ctx.Err() == nil && len(pending) > 0 {
		need := options.Want - p.Working()
		if need > 0 {
			var added int
			added, pending = p.fillRound(ctx, logger, options, pending, need, &firstOnce)
			total += added
			history.Save(options.Cache, options.HistoryKey, logger)
			if len(pending) == 0 {
				break
			}
			if total > 0 && need-added > 0 {
				logger.InfoContext(ctx, "resolver pool: ", p.Working(), " of ", options.Want, " resolvers working")
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(options.Recheck):
		}
	}
	return total
}

// fillRound probes candidates until need of them joined or they are used up, and returns how
// many joined and the candidates left for the next round: those not reached, after those that
// were handed out but skipped because the round was already full. Probes run Concurrency at a
// time, in order.
func (p *Pool) fillRound(ctx context.Context, logger log.ContextLogger, options FillOptions, candidates []Candidate, need int, firstOnce *sync.Once) (int, []Candidate) {
	var (
		mu      sync.Mutex
		added   int
		skipped []Candidate
	)
	isFull := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return added >= need
	}
	slots := make(chan struct{}, options.Concurrency)
	var wg sync.WaitGroup
	used := 0
	for _, candidate := range candidates {
		select { // wait for a free slot, so candidates go out in order
		case slots <- struct{}{}:
		case <-ctx.Done():
		}
		if isFull() || ctx.Err() != nil {
			if ctx.Err() == nil {
				<-slots
			}
			break
		}
		used++
		if options.Pace > 0 && used > 1 {
			select {
			case <-time.After(options.Pace):
			case <-ctx.Done():
			}
		}
		wg.Go(func() {
			defer func() { <-slots }()
			if isFull() || ctx.Err() != nil {
				mu.Lock()
				skipped = append(skipped, candidate)
				mu.Unlock()
				return
			}
			if err := options.Probe(ctx, candidate.Address); err != nil {
				options.History.Record(candidate.Address, -3)
				logger.DebugContext(ctx, "resolver ", candidate.Address, " failed: ", err)
				return
			}
			if err := p.Add(candidate.Address); err != nil {
				logger.WarnContext(ctx, "resolver ", candidate.Address, " not added: ", err)
				return
			}
			options.History.Record(candidate.Address, 1)
			mu.Lock()
			added++
			mu.Unlock()
			logger.InfoContext(ctx, "resolver ", candidate.Address, " is working and added to the pool")
			firstOnce.Do(func() {
				options.History.Save(options.Cache, options.HistoryKey, logger)
				if options.OnFirst != nil {
					options.OnFirst()
				}
			})
		})
	}
	wg.Wait()
	return added, append(skipped, candidates[used:]...)
}
