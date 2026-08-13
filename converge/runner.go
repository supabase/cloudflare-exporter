package converge

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

// Run drives an Engine in a loop, fetching observations from f and pushing
// stable samples to s. It handles live polling, backfill, and graceful
// shutdown. Run blocks until ctx is cancelled.
//
//	┌──────────────────────────────────────────────────────┐
//	│                    each tick                         │
//	│                                                     │
//	│  1. Live:  Fetch [now-lookback, now]                 │
//	│           ──► Engine.Ingest                          │
//	│           (push suppressed until backfill completes) │
//	│                                                     │
//	│  2. Backfill (up to N calls):                        │
//	│           Fetch [cursor, cursor+chunk]               │
//	│           ──► Engine.Ingest (no push)                │
//	│           advance cursor                             │
//	│                                                     │
//	│  3. Backfill complete:                               │
//	│           Engine.Snapshot ──► Sink.Push (one shot)   │
//	│                                                     │
//	│  4. Steady state (backfill done):                    │
//	│           Ingest ──► Sink.Push, Expire ──► Sink.Push │
//	│                                                     │
//	│  5. On shutdown:                                     │
//	│           Engine.Flush ──► Sink.Push                 │
//	└──────────────────────────────────────────────────────┘
//

type runner struct {
	backfillCursor time.Time
	backfillDone   bool
	snapshotPushed bool
	// cfg                  Config
	backfillCallsPerTick int
	backfillChunk        time.Duration
	lookback             time.Duration
}

func newRunner(cfg Config) *runner {
	return &runner{
		backfillCursor:       time.Now().Add(-cfg.MaxBackfill).Truncate(time.Minute),
		snapshotPushed:       false,
		backfillCallsPerTick: cfg.BackfillCallsPerTick,
		backfillDone:         cfg.BackfillCallsPerTick <= 0,
		backfillChunk:        cfg.BackfillChunk,
		lookback:             cfg.Lookback,
	}
}

// runBackfill drives the runner's backfill phase for one tick. Two
// independent steps run in sequence:
//
//  1. advanceBackfill: only while backfill is still in progress, fetch
//     historical chunks until the cursor catches up, then mark
//     backfillDone.
//  2. pushSnapshot: once backfillDone (whether that just happened above,
//     was already true from an earlier tick, or was true from
//     construction because backfill is disabled), push the engine's
//     settled state exactly once.
func (r *runner) runBackfill(ctx context.Context, eng *Engine, f Fetcher, s Sink, now time.Time, ts *TickStats, backfillDoneCB func()) {
	log := LoggerFromContext(ctx)

	if !r.backfillDone {
		r.advanceBackfill(ctx, log, eng, f, now, ts)
	}
	if r.backfillDone {
		r.pushSnapshot(ctx, log, eng, s, now, ts, backfillDoneCB)
	}
}

// advanceBackfill fetches up to backfillCallsPerTick historical chunks,
// ingesting each into eng and advancing the cursor. Sets r.backfillDone
// once the cursor catches up to the live lookback window. Returns early
// (without setting backfillDone) on fetch error, so the next tick retries
// from the same cursor.
func (r *runner) advanceBackfill(ctx context.Context, log *logrus.Entry, eng *Engine, f Fetcher, now time.Time, ts *TickStats) {
	limit := now.Add(-r.lookback)
	for i := 0; i < r.backfillCallsPerTick; i++ {
		if !r.backfillCursor.Before(limit) {
			r.backfillDone = true
			log.Info("backfill complete")
			return
		}
		end := r.backfillCursor.Add(r.backfillChunk)
		if end.After(limit) {
			end = limit
		}
		obs, err := f.Fetch(ctx, r.backfillCursor, end)
		if err != nil {
			log.WithError(err).WithField("start", r.backfillCursor).WithField(
				"end", end).Error("backfill fetch failed")
			return
		}
		log.WithField("start", r.backfillCursor).WithField("end", end).
			WithField("observations", len(obs)).Info("backfill fetch")
		ts.BackfillObservations += len(obs)
		eng.Ingest(obs)
		r.backfillCursor = end
	}
}

// pushSnapshot pushes the engine's settled state as a one-shot snapshot the
// first time it's called after backfill completes. If the push fails, it
// leaves snapshotPushed false so the next tick retries instead of silently
// reporting stabilized; backfillDoneCB only fires once the push succeeds.
func (r *runner) pushSnapshot(ctx context.Context, log *logrus.Entry, eng *Engine, s Sink, now time.Time, ts *TickStats, backfillDoneCB func()) {
	if r.snapshotPushed {
		return
	}

	st := eng.Stats()
	log.WithField("oldest_bucket", st.OldestBucket.Format(time.RFC3339)).
		WithField("newest_bucket", st.NewestBucket.Format(time.RFC3339)).
		Info("backfill done, pushing snapshot")
	snapshot := eng.Snapshot()
	ts.SnapshotSamples = len(snapshot)
	if err := pushSamples(ctx, s, snapshot); err != nil {
		ts.PushErrors++
		return
	}
	r.snapshotPushed = true
	eng.EvictStaleChains(now)
	if backfillDoneCB != nil {
		backfillDoneCB()
	}
}

func (r *runner) runLive(ctx context.Context, eng *Engine, f Fetcher, s Sink, now time.Time, ts *TickStats) {
	log := LoggerFromContext(ctx)

	prevStats := eng.Stats()

	liveStart := now.Add(-r.lookback)
	obs, err := f.Fetch(ctx, liveStart, now)
	if err != nil {
		log.WithError(err).Error("live fetch failed")
	} else {
		logObservationStats(log, obs, now)
		ts.LiveObservations = len(obs)
		samples := eng.Ingest(obs)
		ts.IngestSamples = len(samples)
		if r.backfillDone {
			if err := pushSamples(ctx, s, samples); err != nil {
				ts.PushErrors++
			}
		}
	}

	expireSamples := eng.Expire(now, r.backfillDone)
	ts.ExpireSamples = len(expireSamples)
	if r.backfillDone {
		if err := pushSamples(ctx, s, expireSamples); err != nil {
			ts.PushErrors++
		}
	}

	st := eng.Stats()
	ts.OpenWindows = st.OpenWindows
	ts.TrackerCount = st.TrackerCount
	ts.PostStabilizeUpdates = st.PostStabilizeUpdates - prevStats.PostStabilizeUpdates
	ts.ExpireFlushes = st.ExpireCount - prevStats.ExpireCount
	ts.GaugeDownRevisions = st.GaugeDownRevisions - prevStats.GaugeDownRevisions
	ts.CounterRegressions = st.CounterRegressions - prevStats.CounterRegressions

	log.WithField("post_stabilize_update_count", st.PostStabilizeUpdates).
		WithField("tracker_expire_count", st.ExpireCount).
		WithField("tracker_count", st.TrackerCount).
		WithField("open_windows", st.OpenWindows).Info("engine stats")
}

func Run(ctx context.Context, cfg Config, f Fetcher, s Sink, backfillDoneCB func()) error {
	log := LoggerFromContext(ctx)
	eng := NewEngine(cfg)
	eng.seed(ctx, s, cfg.MaxBackfill)

	ticker := time.NewTicker(cfg.PollInterval)
	r := newRunner(cfg)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			samples := eng.Flush()
			if len(samples) > 0 {
				// Use a short-lived context for the final push.
				pushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := s.Push(pushCtx, samples); err != nil {
					log.WithError(err).Error("flush push failed")
				}
				cancel()
			}
			return ctx.Err()

		case now := <-ticker.C:
			var ts TickStats
			r.runLive(ctx, eng, f, s, now, &ts)
			r.runBackfill(ctx, eng, f, s, now, &ts, backfillDoneCB)
			if cfg.OnTick != nil {
				cfg.OnTick(ts)
			}
		}
	}
}

func logObservationStats(log *logrus.Entry, obs []Observation, now time.Time) {
	if len(obs) == 0 {
		log.WithField("observations", 0).Info("live fetch: empty")
		return
	}
	buckets := make(map[time.Time]struct{})
	oldest := obs[0].Bucket
	newest := obs[0].Bucket
	for _, o := range obs {
		buckets[o.Bucket] = struct{}{}
		if o.Bucket.Before(oldest) {
			oldest = o.Bucket
		}
		if o.Bucket.After(newest) {
			newest = o.Bucket
		}
	}
	log.WithField("observations", len(obs)).
		WithField("buckets", len(buckets)).
		WithField("oldest", oldest.Format(time.RFC3339)).
		WithField("newest", newest.Format(time.RFC3339)).
		WithField("newest_age", now.Sub(newest).Truncate(time.Second).String()).
		Info("live fetch")
}

func pushSamples(ctx context.Context, s Sink, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	log := LoggerFromContext(ctx)
	if err := s.Push(ctx, samples); err != nil {
		log.WithError(err).WithField("count", len(samples)).Error("push failed")
		return err
	}
	return nil
}
