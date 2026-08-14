package converge

import (
	"context"
	"slices"
	"time"
)

// Config controls engine behavior. See README.md for detailed descriptions.
type Config struct {
	// Stability: how the engine decides a value is ready to push.
	Threshold int // consecutive identical observations to stabilize (min: 1)

	// Polling: how the runner drives the engine.
	PollInterval time.Duration // tick interval for the live lane
	Lookback     time.Duration // live lane query range and window TTL

	// Backfill: how startup gaps are filled.
	MaxBackfill          time.Duration // max historical backfill on startup
	BackfillChunk        time.Duration // time range per backfill Fetch call
	BackfillCallsPerTick int           // max Fetch calls for backfill per tick

	// Callbacks (optional).
	OnTick func(TickStats) // called after each runner tick with per-tick stats
}

// DefaultConfig returns a config tuned for convergence with reasonable defaults.
func DefaultConfig() Config {
	return Config{
		Threshold:            3,
		PollInterval:         30 * time.Second,
		Lookback:             10 * time.Minute,
		MaxBackfill:          2 * time.Hour,
		BackfillChunk:        10 * time.Minute,
		BackfillCallsPerTick: 3,
	}
}

// Engine is a pure state machine that tracks observations across time-bucketed
// windows and emits Samples when values stabilize. It performs no I/O, spawns
// no goroutines, and holds no timers. A Runner drives it.
//
// Stabilized gauge values are routed through per-series counterChains that
// produce cumulative prefix sums. When an earlier bucket re-converges, the
// delta cascades forward and the engine re-emits corrected counter values for
// all affected later buckets.
//
//	caller                          engine
//	  │                               │
//	  │── Ingest(observations) ──────►│
//	  │◄── []Sample (push-ready) ─────│
//	  │                               │
//	  │── Expire(now) ───────────────►│
//	  │◄── []Sample (forced push) ────│
//	  │                               │
//	  │── Flush() ───────────────────►│
//	  │◄── []Sample (all values) ─────│
type Engine struct {
	cfg                 Config
	windows             map[time.Time]*window
	chains              map[string]*chainWithKey // per-key counter accumulation
	expireCount         uint64
	postStabilizeUpdate uint64
	oldestBucket        time.Time // low water mark: earliest bucket ever ingested
	newestBucket        time.Time // high water mark: latest bucket ever ingested
}

// chainWithKey pairs a counterChain with the structured Key it belongs to,
// so Snapshot can emit Samples without parsing the string map key.
type chainWithKey struct {
	key Key
	*counterChain
}

// NewEngine creates an engine with the given configuration.
func NewEngine(cfg Config) *Engine {
	if cfg.Threshold < 1 {
		cfg.Threshold = 1
	}
	return &Engine{
		cfg:     cfg,
		windows: make(map[time.Time]*window),
		chains:  make(map[string]*chainWithKey),
	}
}

// SeedChainBase sets the starting base for a counter chain so that emitted
// counter values continue from where a previous process left off. Call
// before Ingest to avoid counter resets on restart.
func (e *Engine) SeedChainBase(key Key, base uint64) {
	sk := key.String()
	ch := e.chains[sk]
	if ch == nil {
		ch = &chainWithKey{key: key, counterChain: newCounterChain()}
		e.chains[sk] = ch
	}
	ch.base = base
}

// Ingest feeds observations into the engine and returns any samples that
// became push-ready as a result (trackers that crossed the stability
// threshold). Returned sample values are cumulative counters.
func (e *Engine) Ingest(obs []Observation) []Sample {
	var ready []Sample
	for _, o := range obs {
		if e.oldestBucket.IsZero() || o.Bucket.Before(e.oldestBucket) {
			e.oldestBucket = o.Bucket
		}
		if o.Bucket.After(e.newestBucket) {
			e.newestBucket = o.Bucket
		}
		w := e.windows[o.Bucket]
		if w == nil {
			w = newWindow(o.Bucket)
			e.windows[o.Bucket] = w
		}

		sk := o.Key.String()
		te := w.trackers[sk]
		if te == nil {
			te = &trackerEntry{key: o.Key, tracker: newTracker(e.cfg.Threshold)}
			w.trackers[sk] = te
		}

		if te.tracker.observe(o.Value, o.Bucket) == obsRewrite {
			e.postStabilizeUpdate++
		}
		if te.tracker.needsSyncAndConsume() {
			ready = append(ready, e.emit(o.Key, o.Value, o.Bucket)...)
			te.pushed = true
		}
	}
	return ready
}

// Expire checks all open windows against Lookback. Windows past their TTL
// have ALL trackers' latest values fed to the counter chains before eviction,
// capturing any post-stabilization drift.
//
// When evictChains is true, the bucket is also evicted from each counter
// chain, folding its gauge into the chain's base. Pass false during backfill
// to free tracker memory while preserving chain entries for Snapshot.
func (e *Engine) Expire(now time.Time, evictChains bool) []Sample {
	// Collect expired buckets and process them in ascending time order.
	// counterChain.Evict only succeeds on the oldest entry, so
	// nondeterministic map iteration would cause evictions to silently
	// fail when a newer bucket is visited before an older one.
	var expired []time.Time
	for bucket := range e.windows {
		if now.Sub(bucket) > e.cfg.Lookback {
			expired = append(expired, bucket)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	slices.SortFunc(expired, func(a, b time.Time) int { return a.Compare(b) })

	var samples []Sample
	for _, bucket := range expired {
		w := e.windows[bucket]
		hadUnpushed := false
		for _, te := range w.trackers {
			if v, ok := te.tracker.currentValue(); ok {
				samples = append(samples, e.emit(te.key, v, w.bucket)...)
			}

			if !te.pushed {
				hadUnpushed = true
			}
		}
		if hadUnpushed {
			e.expireCount++
		}
		if evictChains {
			e.evictBucket(w)
		}
		delete(e.windows, bucket)
	}
	return samples
}

// Flush feeds the best known value for every tracker into the counter chains
// and removes all windows. Used for graceful shutdown.
func (e *Engine) Flush() []Sample {
	var samples []Sample
	for bucket, w := range e.windows {
		for _, te := range w.trackers {
			if v, ok := te.tracker.currentValue(); ok {
				samples = append(samples, e.emit(te.key, v, w.bucket)...)
			}
		}
		delete(e.windows, bucket)
	}
	return samples
}

// Stats returns a snapshot of the engine's internal state.
func (e *Engine) Stats() Stats {
	trackers := 0
	for _, w := range e.windows {
		trackers += len(w.trackers)
	}
	var gaugeDown, counterReg uint64
	for _, ch := range e.chains {
		gaugeDown += ch.gaugeDownRevisions
		counterReg += ch.counterRegressions
	}
	return Stats{
		OpenWindows:          len(e.windows),
		TrackerCount:         trackers,
		ExpireCount:          e.expireCount,
		PostStabilizeUpdates: e.postStabilizeUpdate,
		GaugeDownRevisions:   gaugeDown,
		CounterRegressions:   counterReg,
		OldestBucket:         e.oldestBucket,
		NewestBucket:         e.newestBucket,
	}
}

func (e *Engine) seed(ctx context.Context, s Sink, maxBackfill time.Duration) {
	log := LoggerFromContext(ctx)
	// Seed chain bases from the sink's last known values so counters
	// continue monotonically across restarts.
	seeder, ok := s.(ChainSeeder)
	if !ok {
		return
	}
	selector := `{__name__=~"cloudflare_zone_.*"}`
	seeds, err := seeder.LastValues(ctx, selector, maxBackfill)
	if err != nil {
		log.WithError(err).Warn("chain seed: failed to query last values, starting from zero")
		return
	}
	for _, sample := range seeds {
		e.SeedChainBase(sample.Key, sample.Value)
	}
	log.WithField("chains_seeded", len(seeds)).Info(
		"chain seed: loaded last values from sink")
}

// emit feeds a stabilized gauge value through the per-key counter chain and
// returns samples for every bucket whose cumulative counter changed (the
// target bucket plus any cascaded later buckets).
func (e *Engine) emit(key Key, gauge uint64, bucket time.Time) []Sample {
	sk := key.String()
	ch := e.chains[sk]
	if ch == nil {
		ch = &chainWithKey{key: key, counterChain: newCounterChain()}
		e.chains[sk] = ch
	}
	emissions := ch.Set(bucket, gauge)
	if len(emissions) == 0 {
		return nil
	}
	samples := make([]Sample, len(emissions))
	for i, em := range emissions {
		samples[i] = Sample{Key: key, Value: em.Counter, Timestamp: em.Bucket}
	}
	return samples
}

// Snapshot returns one Sample per active counter chain entry, reflecting
// the current prefix-sum state without mutating the engine. Used after
// backfill completes to push the final settled counter values in one shot.
func (e *Engine) Snapshot() []Sample {
	var samples []Sample
	for _, ch := range e.chains {
		for _, entry := range ch.entries {
			samples = append(samples, Sample{
				Key:       ch.key,
				Value:     entry.counter,
				Timestamp: entry.bucket,
			})
		}
	}
	return samples
}

// KeepAlive returns a Sample re-affirming the current counter value, at
// timestamp now, for every known key not present in touched. Cloudflare's
// Adaptive Groups API only returns a group for a (zone, status) pair that
// had at least one request in the bucket, so a rare status code can go
// several minutes without appearing at all - Ingest never sees an
// Observation for it during that gap and never re-emits its counter.
// Without a fresh sample, that series ages past VictoriaMetrics' staleness
// window and silently drops out of any sum()/rate()/delta() over the zone's
// total, producing a phantom drop that reverses the moment the status code
// reappears. KeepAlive closes that gap by re-pushing the unchanged value at
// a fresh timestamp every tick that the key has no real observation.
func (e *Engine) KeepAlive(now time.Time, touched map[string]bool) []Sample {
	var samples []Sample
	for sk, ch := range e.chains {
		if touched[sk] {
			continue
		}
		samples = append(samples, Sample{
			Key:       ch.key,
			Value:     ch.Current(),
			Timestamp: now,
		})
	}
	return samples
}

// EvictStaleChains evicts all counter chain entries whose bucket is older
// than Lookback. Used after Snapshot to clean up chain entries that were
// preserved during backfill (when Expire ran with evictChains=false).
func (e *Engine) EvictStaleChains(now time.Time) {
	cutoff := now.Add(-e.cfg.Lookback)
	for _, ch := range e.chains {
		for len(ch.entries) > 0 && ch.entries[0].bucket.Before(cutoff) {
			ch.base += ch.entries[0].gauge
			ch.entries = ch.entries[1:]
		}
	}
}

// evictBucket removes the expired bucket from every counter chain that
// references it, folding the gauge into each chain's base.
func (e *Engine) evictBucket(w *window) {
	for _, te := range w.trackers {
		if ch := e.chains[te.key.String()]; ch != nil {
			ch.Evict(w.bucket)
		}
	}
}
