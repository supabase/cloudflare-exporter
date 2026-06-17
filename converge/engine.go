package converge

import (
	"slices"
	"time"
)

// Config controls engine behavior. See README.md for detailed descriptions.
type Config struct {
	// Stability: how the engine decides a value is ready to push.
	Threshold int           // consecutive identical observations to stabilize (min: 1)
	WindowTTL time.Duration // close window when bucket age exceeds this duration

	// Polling: how the runner drives the engine.
	PollInterval time.Duration // tick interval for the live lane
	Lookback     time.Duration // live lane query range: [now-Lookback, now]

	// Backfill: how startup gaps are filled.
	MaxBackfill          time.Duration // max historical backfill on startup
	BackfillChunk        time.Duration // time range per backfill Fetch call
	BackfillCallsPerTick int           // max Fetch calls for backfill per tick
}

// DefaultConfig returns a config tuned for convergence with reasonable defaults.
func DefaultConfig() Config {
	return Config{
		Threshold:            3,
		WindowTTL:            15 * time.Minute,
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

// Ingest feeds observations into the engine and returns any samples that
// became push-ready as a result (trackers that crossed the stability
// threshold). Returned sample values are cumulative counters.
func (e *Engine) Ingest(obs []Observation) []Sample {
	var ready []Sample
	for _, o := range obs {
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

// Expire checks all open windows against WindowTTL. Windows past their TTL
// have ALL trackers' latest values fed to the counter chains before eviction,
// capturing any post-stabilization drift. The bucket is then evicted from
// each chain, folding its gauge into the chain's base.
func (e *Engine) Expire(now time.Time) []Sample {
	// Collect expired buckets and process them in ascending time order.
	// counterChain.Evict only succeeds on the oldest entry, so
	// nondeterministic map iteration would cause evictions to silently
	// fail when a newer bucket is visited before an older one.
	var expired []time.Time
	for bucket := range e.windows {
		if now.Sub(bucket) >= e.cfg.WindowTTL {
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
		e.evictBucket(w)
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
	return Stats{
		OpenWindows:          len(e.windows),
		TrackerCount:         trackers,
		ExpireCount:          e.expireCount,
		PostStabilizeUpdates: e.postStabilizeUpdate,
	}
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

// evictBucket removes the expired bucket from every counter chain that
// references it, folding the gauge into each chain's base.
func (e *Engine) evictBucket(w *window) {
	for _, te := range w.trackers {
		if ch := e.chains[te.key.String()]; ch != nil {
			ch.Evict(w.bucket)
		}
	}
}
