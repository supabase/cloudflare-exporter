package converge

import (
	"context"
	"time"
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

		case now := <-ticker.C:
			// Live lane: always runs, no call limit.
			liveStart := now.Add(-cfg.Lookback)
			obs, err := f.Fetch(ctx, liveStart, now)
			if err != nil {
				log.WithError(err).Error("live fetch failed")
			} else {
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

func pushSamples(ctx context.Context, s Sink, samples []Sample) {
	if len(samples) == 0 {
		return
	}
	log := LoggerFromContext(ctx)
	if err := s.Push(ctx, samples); err != nil {
		log.WithError(err).WithField("count", len(samples)).Error("push failed")
	}
}
