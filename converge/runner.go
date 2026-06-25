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
func Run(ctx context.Context, cfg Config, f Fetcher, s Sink) error {
	log := LoggerFromContext(ctx)
	eng := NewEngine(cfg)
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	backfillCursor := time.Now().Add(-cfg.MaxBackfill).Truncate(time.Minute)
	backfillDone := false
	snapshotPushed := false

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
			// Live lane: always runs, no call limit.
			liveStart := now.Add(-cfg.Lookback)
			obs, err := f.Fetch(ctx, liveStart, now)
			if err != nil {
				log.WithError(err).Error("live fetch failed")
			} else {
				logObservationStats(log, obs, now)
				samples := eng.Ingest(obs)
				if backfillDone {
					pushSamples(ctx, s, samples)
				}
			}
			// During backfill, expire windows to free tracker memory
			// but preserve counter chain entries for the snapshot.
			expireSamples := eng.Expire(now, backfillDone)
			if backfillDone {
				pushSamples(ctx, s, expireSamples)
			}

			st := eng.Stats()
			log.WithField("post_stabilize_update_count", st.PostStabilizeUpdates).
				WithField("tracker_expire_count", st.ExpireCount).
				WithField("tracker_count", st.TrackerCount).
				WithField("open_windows", st.OpenWindows).Info("engine stats")

			// Backfill lane: capped at BackfillCallsPerTick.
			if backfillDone {
				continue
			}
			if cfg.BackfillCallsPerTick <= 0 {
				backfillDone = true
			} else {
				limit := now.Add(-cfg.Lookback)
				for i := 0; i < cfg.BackfillCallsPerTick; i++ {
					if !backfillCursor.Before(limit) {
						backfillDone = true
						log.Info("backfill complete")
						break
					}
					end := backfillCursor.Add(cfg.BackfillChunk)
					if end.After(limit) {
						end = limit
					}
					obs, err := f.Fetch(ctx, backfillCursor, end)
					if err != nil {
						log.WithError(err).WithField("start", backfillCursor).WithField(
							"end", end).Error("backfill fetch failed")
						break // retry next tick
					}
					log.WithField("start", backfillCursor).WithField("end", end).
						WithField("observations", len(obs)).Info("backfill fetch")
					eng.Ingest(obs)
					backfillCursor = end
				}
			}

			// Backfill just finished this tick: push the final
			// state of every counter chain entry in one shot.
			// During backfill, Ingest built up correct prefix sums
			// but we suppressed pushes to avoid intermediate
			// cascade artifacts in downstream rate() queries.
			if backfillDone && !snapshotPushed {
				snapshotPushed = true
				st := eng.Stats()
				log.WithField("oldest_bucket", st.OldestBucket.Format(time.RFC3339)).
					WithField("newest_bucket", st.NewestBucket.Format(time.RFC3339)).
					Info("backfill done, pushing snapshot")
				pushSamples(ctx, s, eng.Snapshot())
				// Chain eviction was deferred during backfill.
				// Now that the snapshot captured all entries,
				// evict stale buckets to free chain memory.
				eng.EvictStaleChains(now)
				if cfg.BackfillDone != nil {
					close(cfg.BackfillDone)
				}
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

func pushSamples(ctx context.Context, s Sink, samples []Sample) {
	if len(samples) == 0 {
		return
	}
	log := LoggerFromContext(ctx)
	if err := s.Push(ctx, samples); err != nil {
		log.WithError(err).WithField("count", len(samples)).Error("push failed")
	}
}
