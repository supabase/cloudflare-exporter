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
//	│           ──► Engine.Ingest ──► Sink.Push            │
//	│           ──► Engine.Expire ──► Sink.Push            │
//	│                                                     │
//	│  2. Backfill (up to N calls):                        │
//	│           Fetch [cursor, cursor+chunk]               │
//	│           ──► Engine.Ingest ──► Sink.Push            │
//	│           advance cursor                             │
//	│                                                     │
//	│  3. On shutdown:                                     │
//	│           Engine.Flush ──► Sink.Push                 │
//	└──────────────────────────────────────────────────────┘
func Run(ctx context.Context, cfg Config, f Fetcher, s Sink) error {
	log := LoggerFromContext(ctx)
	eng := NewEngine(cfg)
	ticker := time.NewTicker(cfg.PollInterval)
	logInterval := time.NewTicker(time.Second * 60)
	defer ticker.Stop()

	backfillCursor := time.Now().Add(-cfg.MaxBackfill).Truncate(time.Minute)
	backfillDone := false

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

		case <-logInterval.C:
			s := eng.Stats()

			log.WithField("post_stabilize_update_count", s.PostStabilizeUpdates).
				WithField("tracker_expire_count", s.ExpireCount).
				WithField("tracker_count", s.TrackerCount).
				WithField("open_windows", s.OpenWindows).Info("engine stats")

		case now := <-ticker.C:
			// Live lane: always runs, no call limit.
			liveStart := now.Add(-cfg.Lookback)
			obs, err := f.Fetch(ctx, liveStart, now)
			if err != nil {
				log.WithError(err).Error("live fetch failed")
			} else {
				logObservationStats(log, obs, now)
				pushSamples(ctx, s, eng.Ingest(obs))
			}
			pushSamples(ctx, s, eng.Expire(now))

			// Backfill lane: capped at BackfillCallsPerTick.
			if backfillDone {
				continue
			}
			if cfg.BackfillCallsPerTick <= 0 {
				backfillDone = true
				continue
			}
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
				pushSamples(ctx, s, eng.Ingest(obs))
				backfillCursor = end
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
