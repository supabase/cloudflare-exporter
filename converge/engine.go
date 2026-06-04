package converge

import "time"

// Config controls engine behavior. See README.md for detailed descriptions.
type Config struct {
	// Stability: how the engine decides a value is ready to push.
	Threshold int           // consecutive identical observations to stabilize (min: 1)
	WindowTTL time.Duration // close window after this duration since creation

	// Polling: how the runner drives the engine.
	PollInterval time.Duration // tick interval for the live lane
	Lookback     time.Duration // live lane query range: [now-Lookback, now]

	// Backfill: how startup gaps are filled.
	MaxBackfill          time.Duration // max historical backfill on startup
	BackfillChunk        time.Duration // time range per backfill Fetch call
	BackfillCallsPerTick int           // max Fetch calls for backfill per tick
}

// DefaultConfig returns a config tuned for eager push with reasonable defaults.
func DefaultConfig() Config {
	return Config{
		Threshold:            3,
		WindowTTL:            15 * time.Minute,
		PollInterval:         30 * time.Second,
		Lookback:             10 * time.Minute,
		MaxBackfill:          2 * time.Hour,
		BackfillChunk:        10 * time.Minute,
		BackfillCallsPerTick: 1,
	}
}

// Engine is a pure state machine that tracks observations across time-bucketed
// windows and emits Samples when values stabilize. It performs no I/O, spawns
// no goroutines, and holds no timers. A Runner drives it.
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
	cfg     Config
	windows map[time.Time]*window
}

// NewEngine creates an engine with the given configuration.
func NewEngine(cfg Config) *Engine {
	if cfg.Threshold < 1 {
		cfg.Threshold = 1
	}
	return &Engine{
		cfg:     cfg,
		windows: make(map[time.Time]*window),
	}
}

// Ingest feeds observations into the engine and returns any samples that
// became push-ready as a result (trackers that crossed the stability
// threshold).
func (e *Engine) Ingest(obs []Observation) []Sample {
	var ready []Sample
	for _, o := range obs {
		w := e.windows[o.Bucket]
		if w == nil {
			w = newWindow(o.Bucket, time.Now())
			e.windows[o.Bucket] = w
		}

		t := w.trackers[o.Key]
		if t == nil {
			t = newTracker(e.cfg.Threshold)
			w.trackers[o.Key] = t
		}

		t.observe(o.Value, o.Bucket)
		if t.needsSyncAndConsume() {
			ready = append(ready, Sample{
				Key:       o.Key,
				Value:     o.Value,
				Timestamp: o.Bucket,
			})
			w.pushed = true
		}
	}
	return ready
}

// Expire checks all open windows against WindowTTL. Windows past their TTL
// are force-flushed (best known values pushed if not already pushed) and
// removed.
func (e *Engine) Expire(now time.Time) []Sample {
	var samples []Sample
	for bucket, w := range e.windows {
		if now.Sub(w.created) >= e.cfg.WindowTTL {
			if !w.pushed {
				samples = append(samples, w.flush()...)
			}
			delete(e.windows, bucket)
		}
	}
	return samples
}

// Flush returns the best known value for every tracker in every open window
// and removes all windows. Used for graceful shutdown.
func (e *Engine) Flush() []Sample {
	var samples []Sample
	for bucket, w := range e.windows {
		samples = append(samples, w.flush()...)
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
		OpenWindows:  len(e.windows),
		TrackerCount: trackers,
	}
}
